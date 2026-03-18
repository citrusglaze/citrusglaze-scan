"""
Core secret scanning engine.

Scans text content against all compiled patterns and returns findings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from .chat_parsers import ChatMessage, ChatSource
from .patterns import SecretCategory, SecretPattern, Severity, get_patterns, shannon_entropy


@dataclass
class SecretFinding:
    """A single detected secret."""
    pattern_id: str
    pattern_name: str
    category: SecretCategory
    severity: Severity
    matched_text: str          # The raw matched text
    redacted_text: str         # First 4 chars + "****..."
    source_file: str
    source_tool: str           # Which AI tool (e.g., "Claude Code")
    line_number: Optional[int] = None
    context: Optional[str] = None  # Surrounding text (redacted)


@dataclass
class ScanResult:
    """Results from scanning a single ChatSource."""
    source_name: str
    source_path: str
    found: bool
    conversation_count: int
    message_count: int
    findings: list[SecretFinding] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def secret_count(self) -> int:
        return len(self.findings)

    @property
    def affected_conversations(self) -> int:
        return len(set(f.source_file for f in self.findings))


@dataclass
class FullScanResult:
    """Aggregate results across all sources."""
    results: list[ScanResult] = field(default_factory=list)
    total_secrets: int = 0
    by_severity: dict = field(default_factory=dict)
    by_category: dict = field(default_factory=dict)
    by_pattern: dict = field(default_factory=dict)

    def compute_aggregates(self):
        """Compute aggregate statistics from individual results."""
        self.total_secrets = sum(r.secret_count for r in self.results)

        # By severity
        self.by_severity = {}
        for sev in Severity:
            count = sum(1 for r in self.results for f in r.findings if f.severity == sev)
            if count > 0:
                self.by_severity[sev] = count

        # By category
        self.by_category = {}
        for r in self.results:
            for f in r.findings:
                cat_name = f.category.value
                self.by_category[cat_name] = self.by_category.get(cat_name, 0) + 1

        # By pattern name
        self.by_pattern = {}
        for r in self.results:
            for f in r.findings:
                self.by_pattern[f.pattern_name] = self.by_pattern.get(f.pattern_name, 0) + 1


def redact(text: str) -> str:
    """Redact a secret value, showing only first 4 chars."""
    if len(text) <= 4:
        return "****"
    return text[:4] + "****" + ("..." if len(text) > 12 else "")


def _luhn_check(number: str) -> bool:
    """Validate a credit card number using the Luhn algorithm.

    Returns True if the number passes (likely a real card number).
    """
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# Well-known example/placeholder database credentials
_EXAMPLE_DB_USERS = {
    "user", "username", "admin", "root", "postgres", "mysql",
    "dbuser", "db_user", "myuser", "your_user", "your-user",
    "example", "test", "demo", "sample",
}

_EXAMPLE_DB_PASSWORDS = {
    "password", "passwd", "pass", "secret", "mysecret",
    "your_password", "your-password", "yourpassword",
    "changeme", "example", "test", "demo", "123456",
    "mypassword", "my_password", "dbpassword", "db_password",
}

_EXAMPLE_DB_HOSTS = {
    "host", "hostname", "localhost", "127.0.0.1", "0.0.0.0",
    "your-host", "your_host", "yourhost", "example.com",
    "db.example.com", "myhost", "host.example.com",
    "db", "database", "my-database", "mydb",
}


def _is_false_positive_db_uri(uri: str) -> bool:
    """Check if a database URI uses example/placeholder credentials."""
    import re as _re
    # Extract user:password@host from URI
    m = _re.search(r'://([^:]+):([^@]+)@([^/:?\s]+)', uri)
    if not m:
        return False
    user, password, host = m.group(1).lower(), m.group(2).lower(), m.group(3).lower()

    # Localhost/loopback is local dev, not a real leak
    if host in ("localhost", "127.0.0.1", "0.0.0.0", "[::1]"):
        return True

    # Example/placeholder credentials
    if user in _EXAMPLE_DB_USERS and password in _EXAMPLE_DB_PASSWORDS:
        return True
    if host in _EXAMPLE_DB_HOSTS:
        return True

    return False


# SSN ranges that are invalid per SSA rules
def _is_false_positive_ssn(ssn: str) -> bool:
    """Check if an SSN is in an impossible or well-known test range."""
    digits = ssn.replace("-", "")
    if len(digits) != 9:
        return True

    area = int(digits[:3])
    group = int(digits[3:5])
    serial = int(digits[5:])

    # SSA invalid ranges
    if area == 0 or group == 0 or serial == 0:
        return True
    if area == 666:
        return True
    if area >= 900:
        return True
    # Well-known test/example SSNs
    if digits in ("123456789", "111111111", "222222222", "333333333",
                   "999999999", "078051120", "219099999"):
        return True
    # Repeating digits
    if len(set(digits)) == 1:
        return True

    return False


# Values commonly assigned to secret/password fields in examples, docs, and configs
_GENERIC_SECRET_PLACEHOLDER_VALUES = {
    "password", "secret", "changeme", "test", "testing", "development",
    "your_secret_here", "your-secret-here", "your_token_here",
    "your_api_key", "your_api_key_here", "my_secret_key",
    "supersecret", "mysecret", "passw0rd", "admin123",
    "none", "null", "undefined", "empty", "default",
    "replace_me", "fixme", "todo", "placeholder",
}


def _is_false_positive_generic_secret(matched_text: str) -> bool:
    """Check if a generic secret match is a placeholder or code pattern."""
    # Extract the value part (after = or :)
    parts = re.split(r'[=:]\s*[\'"]?', matched_text)
    if len(parts) < 2:
        return False
    value = parts[-1].strip().strip("'\"").lower()

    # Known placeholder values
    if value in _GENERIC_SECRET_PLACEHOLDER_VALUES:
        return True

    # Values that are just repeated simple chars
    if len(set(value.lower())) <= 3 and len(value) >= 20:
        return True

    # Values that look like file paths
    if value.startswith("/") or value.startswith("./") or value.startswith("~"):
        return True

    # Values that look like Python/JS variable references (no special chars, low entropy)
    # But NOT high-entropy strings that just happen to be all-lowercase alphanumeric
    if re.match(r'^[a-z_][a-z0-9_]*$', value) and len(value) < 30:
        # Extract original value (before lowering) for entropy check
        orig_parts = re.split(r'[=:]\s*[\'"]?', matched_text)
        orig_value = orig_parts[-1].strip().strip("'\"") if len(orig_parts) > 1 else matched_text
        if shannon_entropy(orig_value) < 4.0:
            return True

    # Values that are environment variable references
    if value.startswith("$") or value.startswith("${") or value.startswith("process.env"):
        return True

    return False


def _has_sequential_chars(text: str, min_run: int = 8) -> bool:
    """Detect sequential alphabetical runs (ABCDEFGHij...) that indicate test fixtures."""
    # Extract just the value part after = or : if present
    parts = re.split(r'[=:]\s*[\'"]?', text)
    value = parts[-1].strip().strip("'\"") if len(parts) > 1 else text
    # Strip common prefixes (ghp_, sk_live_, etc.) to check the body
    body = re.sub(r'^[a-z]{2,6}[_-]', '', value, flags=re.IGNORECASE)
    body = re.sub(r'^(v1|api\d*|live|test|proj|ant|or)[_-]', '', body, flags=re.IGNORECASE)

    upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    lower_seq = "abcdefghijklmnopqrstuvwxyz"
    digits = "0123456789"

    for seq in (upper, lower_seq, digits):
        for i in range(len(body) - min_run + 1):
            chunk = body[i:i + min_run]
            if chunk in seq:
                return True
    return False


# Sequential hex byte pairs used in synthetic test data (1a2b3c4d, 5e6f7a8b, etc.)
_SEQUENTIAL_HEX_PAIRS = re.compile(
    r'(?:0[0-9a-f]){4,}|'        # 00-0f sequential
    r'(?:[0-9a-f][0-9a-f]){4,}',  # any 4+ hex byte pairs
    re.IGNORECASE,
)

# Common synthetic test UUID/hex sequences
_SYNTHETIC_HEX_PATTERNS = {
    "1a2b3c4d", "5e6f7a8b", "9c0d1e2f", "3a4b5c6d",
    "1a2b3c4d5e6f", "7a8b9c0d1e2f", "3a4b5c6d7e8f",
    "0a1b2c3d", "4e5f6a7b", "8c9d0e1f",
    "aabb", "aabbccdd", "deadbeef", "cafebabe",
}

# Synthetic character sequences commonly reused across AI-generated test fixtures.
# These appear in fake API keys, tokens, and secrets generated by LLMs when writing
# test data.  If >=2 of these fragments appear in a single matched value, it's almost
# certainly fabricated test data rather than a real leaked credential.
_SYNTHETIC_FIXTURE_FRAGMENTS = [
    "Kx4mBqWz",  "7nJp2rVt",  "9sYdFg5h",  "Jk8qNr3b",
    "Rm7Kp3Wz",  "9Qv2Nx8J",  "t4Bf6Hs5",  "Yd1Cg0Lk",
    "3Mw7Pr2T",  "v9Xq4Zn8",
    "f3a8e2d7",  "c9b04f56",  "c9b0-4f56", "e2a8d1c9",
    "b70452f3",  "a2d8-b704",
    "Xw6eAi0c",  "DlG1fH7q",
    "s3cretP4ss", "s3cretPa55",  # common synthetic DB passwords
]


def _has_synthetic_fixture_fragments(text: str) -> bool:
    """Detect reused synthetic fixture fragments generated by LLMs.

    Returns True when two or more known synthetic fragments appear in the
    same matched value, strongly indicating fabricated test data.
    """
    count = 0
    lower = text.lower()
    for frag in _SYNTHETIC_FIXTURE_FRAGMENTS:
        if frag.lower() in lower:
            count += 1
            if count >= 2:
                return True
    return False


def _has_sequential_hex_pairs(text: str) -> bool:
    """Detect sequential hex byte pair patterns (1a2b3c4d-5e6f-...) common in test fixtures."""
    lower = text.lower()
    # Check for known synthetic hex sequences
    for pattern in _SYNTHETIC_HEX_PATTERNS:
        if pattern in lower:
            return True
    # Check for incrementing hex byte pairs: e.g. "0a0b0c0d" or "1a1b1c1d"
    # Extract hex-looking segments (after stripping prefixes/separators)
    hex_segments = re.findall(r'[0-9a-f]{8,}', lower)
    for seg in hex_segments:
        # Split into byte pairs and check if they form a simple pattern
        pairs = [seg[i:i+2] for i in range(0, len(seg) - 1, 2)]
        if len(pairs) >= 4:
            # Check if pairs follow a repeating incrementing pattern
            diffs = []
            for i in range(1, len(pairs)):
                try:
                    diffs.append(int(pairs[i], 16) - int(pairs[i-1], 16))
                except ValueError:
                    break
            if diffs and all(d == diffs[0] for d in diffs):
                return True
    return False


def _is_likely_example(text: str) -> bool:
    """Check if a matched string is likely a documentation example, not a real secret."""
    example_indicators = [
        "example", "EXAMPLE", "sample", "SAMPLE", "test", "TEST",
        "dummy", "DUMMY", "fake", "FAKE", "placeholder", "PLACEHOLDER",
        "xxx", "XXX", "your-", "YOUR_", "replace", "REPLACE",
        "<your", "<YOUR", "insert", "INSERT", "todo", "TODO",
        "changeme", "CHANGEME",
    ]
    lower = text.lower()
    if any(indicator.lower() in lower for indicator in example_indicators):
        return True
    # Detect sequential alphabetical patterns common in test fixtures
    if _has_sequential_chars(text):
        return True
    # Detect sequential hex byte pairs (1a2b3c4d-5e6f-...) common in test data
    if _has_sequential_hex_pairs(text):
        return True
    # Detect reused synthetic fixture fragments from LLM-generated test data
    if _has_synthetic_fixture_fragments(text):
        return True
    return False


# Well-known test credit card numbers (Stripe, Braintree, PayPal sandbox, etc.)
_TEST_CARD_NUMBERS = {
    "4111111111111111",   # Visa test
    "4242424242424242",   # Stripe Visa test
    "5555555555554444",   # Mastercard test
    "5105105105105100",   # Mastercard test
    "378282246310005",    # Amex test
    "371449635398431",    # Amex test
    "6011111111111117",   # Discover test
    "6011000990139424",   # Discover test
    "3530111333300000",   # JCB test
    "3566002020360505",   # JCB test
    "4000056655665556",   # Stripe intl test
    "5200828282828210",   # Stripe MC test
    "4000000000000077",   # Stripe charge succeeds
    "4000000000000093",   # Stripe charge succeeds
    "4000000000000127",   # Stripe CVC check fails
    "4000000000000002",   # Stripe charge declined
    "4000000000009995",   # Stripe insufficient funds
    "4000000000000069",   # Stripe expired card
    "4000000000000341",   # Stripe attach succeeds, pay fails
    "4012888888881881",   # Visa test (common in docs)
    "5425233430109903",   # Mastercard sandbox
    "2223000048410010",   # Mastercard 2-series test
    "6759649826438453",   # Maestro test
    "3056930009020004",   # Diners Club test
    "3852000002323676",   # Diners Club test
    "6271136264806203568", # UnionPay test
    "36227206271667",     # Diners Club 14-digit test
}

# Email domains that are not sensitive PII
_NOREPLY_EMAIL_PATTERNS = [
    "noreply@", "no-reply@", "donotreply@", "do-not-reply@",
    "mailer-daemon@", "postmaster@", "notifications@",
    "github-noreply@", "bot@", "auto@", "automated@",
]

# Role-based / functional email prefixes — not personal PII
_ROLE_EMAIL_PREFIXES = {
    "hello", "hi", "hey", "info", "contact", "support", "help",
    "sales", "marketing", "press", "media", "legal", "privacy",
    "security", "abuse", "admin", "webmaster", "hostmaster",
    "billing", "invoices", "accounts", "feedback", "team",
    "dmarc-reports", "dmarc", "dmarcreports", "bounces",
    "unsubscribe", "subscribe", "newsletter", "alerts",
}

_NONSENSITIVE_EMAIL_DOMAINS = {
    "example.com", "example.org", "example.net",
    "test.com", "test.org", "localhost",
    "users.noreply.github.com", "anthropic.com",
    "github.com", "email.com", "placeholder.com",
    # Common public/corporate domains that appear in code discussions
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com",
    "yahoo.com", "icloud.com", "protonmail.com", "proton.me",
    # Tech company domains commonly in docs/configs
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "stripe.com", "sendgrid.net", "mailgun.com", "postmarkapp.com",
    # Package ecosystem / CI domains
    "pypi.org", "npmjs.com", "rubygems.org", "crates.io",
    "travis-ci.org", "circleci.com", "github.io",
    # Placeholder / documentation domains commonly used in examples
    "company.com", "acme.com", "acme-corp.com", "corp.com",
    "mycompany.com", "yourcompany.com", "domain.com",
    "foo.com", "bar.com", "baz.com", "foobar.com",
    "contoso.com", "fabrikam.com", "northwind.com",  # Microsoft docs
    "sentry.io",  # Sentry DSN domains (not PII)
}


def _is_false_positive_email(email: str) -> bool:
    """Check if an email is clearly not sensitive PII."""
    lower = email.lower()
    # noreply / bot addresses
    for pat in _NOREPLY_EMAIL_PATTERNS:
        if pat in lower:
            return True
    at_idx = lower.rfind("@")
    if at_idx >= 0:
        domain = lower[at_idx + 1:]
        local_part = lower[:at_idx]
        # Non-sensitive domains
        if domain in _NONSENSITIVE_EMAIL_DOMAINS:
            return True
        # Role-based / functional prefixes are not personal PII
        if local_part in _ROLE_EMAIL_PREFIXES:
            return True
    return False


def _is_false_positive_phone(phone: str) -> bool:
    """Check if a US phone number uses the fictional 555 area code or exchange."""
    digits = re.sub(r'\D', '', phone)
    # 555 is the well-known fictional/reserved phone exchange
    # Numbers like (555) 123-4567 or 555-234-5678 are always fake
    if len(digits) >= 10:
        # Check area code position (first 3 digits of 10-digit number)
        start = len(digits) - 10
        area = digits[start:start + 3]
        exchange = digits[start + 3:start + 6]
        if area == "555" or exchange == "555":
            return True
    elif len(digits) >= 7:
        # 7-digit local: exchange is first 3
        if digits[:3] == "555":
            return True
    return False


# Well-known test/example IBAN numbers from documentation
_TEST_IBANS = {
    "DE89370400440532013000",  # Deutsche Bank test IBAN (ubiquitous in docs)
    "GB29NWBK60161331926819",  # UK test IBAN
    "FR7630006000011234567890189",  # French test IBAN
    "ES9121000418450200051332",  # Spanish test IBAN
    "IT60X0542811101000000123456",  # Italian test IBAN
    "NL91ABNA0417164300",  # Dutch test IBAN
    "BE68539007547034",  # Belgian test IBAN
    "CH9300762011623852957",  # Swiss test IBAN
    "AT611904300234573201",  # Austrian test IBAN
}


def _is_false_positive_url(url: str) -> bool:
    """Check if a URL with basic auth is a local dev or git-clone pattern."""
    lower = url.lower()
    # Localhost / loopback dev URLs are not real credential leaks
    for host in ("://localhost", "://127.0.0.1", "://0.0.0.0", "://[::1]"):
        if host in lower:
            return True
    # Git clone with token — these are caught by dedicated git token patterns
    if "x-access-token:" in lower or "oauth2:" in lower:
        return True
    return False


def _has_context_keyword(text: str, keywords: list[str], window: int = 200) -> bool:
    """Check if any context keyword appears near the match."""
    if not keywords:
        return True  # No keywords required = always match
    lower = text.lower()
    return any(kw.lower() in lower for kw in keywords)


def _check_entropy(match_text: str, threshold: float) -> bool:
    """Check if matched text meets entropy threshold."""
    # Extract just the secret value part (after = or : usually)
    parts = re.split(r'[=:]\s*[\'"]?', match_text)
    value = parts[-1].strip().strip("'\"") if len(parts) > 1 else match_text
    return shannon_entropy(value) >= threshold


# Patterns whose official token format contains words like "test", "sample" etc.
# These should NOT be filtered by _is_likely_example().
_SKIP_EXAMPLE_CHECK = frozenset({
    "easypost_test_api_token",
    "flutterwave_secret_key",
    "flutterwave_public_key",
    "flutterwave_encryption_key",
    "duffel_api_token",
    "stripe_test_key",
    "shippo_api_token",
    "plaid_access_token",
    "lob_api_key",
    "twitter_bearer_token",  # Official prefix is AAAAAAAAAAAAAAAAAAA (19 A's)
})


def scan_text(text: str, patterns: list[SecretPattern], source_file: str = "",
              source_tool: str = "") -> list[SecretFinding]:
    """Scan a single text string for secrets."""
    findings = []
    seen_matches = set()  # Deduplicate identical matches

    for pattern in patterns:
        for match in pattern.regex.finditer(text):
            matched_text = match.group(0)

            # Skip very short matches (likely false positives)
            if len(matched_text) < 8:
                continue

            # Skip documentation examples — but not tokens whose official format
            # contains words like "test" (e.g. FLWSECK_TEST-, EZTK, duffel_test_)
            if pattern.id not in _SKIP_EXAMPLE_CHECK and _is_likely_example(matched_text):
                continue

            # Per-pattern false positive filters
            if pattern.id == "credit_card":
                digits = re.sub(r'\D', '', matched_text)
                if digits in _TEST_CARD_NUMBERS:
                    continue
                if not _luhn_check(digits):
                    continue
            if pattern.id == "email_address" and _is_false_positive_email(matched_text):
                continue
            if pattern.id == "basic_auth_url" and _is_false_positive_url(matched_text):
                continue
            if pattern.id == "ssn" and _is_false_positive_ssn(matched_text):
                continue
            # Database URIs with example/localhost credentials
            if pattern.id in ("postgres_uri", "mongodb_uri", "mysql_uri",
                              "redis_uri", "cassandra_uri", "cockroachdb_uri",
                              "connection_string_generic", "neon_db_uri"):
                if _is_false_positive_db_uri(matched_text):
                    continue
                # Regex literals (e.g. "mysql://[^:]+:[^@]+@[^\s]+")
                if re.search(r'\[[\^\\]', matched_text):
                    continue
            # Phone numbers: filter 555 (fictional) numbers
            if pattern.id in ("phone_number_us", "phone_number_intl"):
                if _is_false_positive_phone(matched_text):
                    continue
            # IBAN: filter well-known test/documentation IBANs
            if pattern.id == "iban":
                iban_digits = re.sub(r'\s', '', matched_text)
                if iban_digits in _TEST_IBANS:
                    continue
            # AWS Cognito pool: filter well-known example pool IDs
            if pattern.id == "aws_cognito_pool":
                pool_id = matched_text.split("_", 1)[-1] if "_" in matched_text else ""
                if pool_id.lower() in ("abcdef123", "abc123def", "example12"):
                    continue
            # Flutterwave encryption key: skip if it's actually a secret key match
            if pattern.id == "flutterwave_encryption_key":
                # Check if the text continues with more hex chars + "-X" (= secret key)
                end_pos = match.end()
                if end_pos < len(text):
                    remaining = text[end_pos:end_pos + 25]
                    if re.match(r'[a-hA-H0-9]{20}-X', remaining):
                        continue
            # Generic secrets: extra filtering for common FP values
            if pattern.id == "generic_secret":
                if _is_false_positive_generic_secret(matched_text):
                    continue

            # Check context keywords if required
            if pattern.context_keywords:
                # Get surrounding context (200 chars before and after)
                start = max(0, match.start() - 200)
                end = min(len(text), match.end() + 200)
                context = text[start:end]
                if not _has_context_keyword(context, pattern.context_keywords):
                    continue

            # Check entropy threshold if required
            if pattern.entropy_threshold is not None:
                if not _check_entropy(matched_text, pattern.entropy_threshold):
                    continue

            # Deduplicate
            dedup_key = (pattern.id, matched_text)
            if dedup_key in seen_matches:
                continue
            seen_matches.add(dedup_key)

            # Calculate line number
            line_number = text[:match.start()].count('\n') + 1

            # Get context (line containing the match, redacted)
            line_start = text.rfind('\n', 0, match.start()) + 1
            line_end = text.find('\n', match.end())
            if line_end == -1:
                line_end = min(len(text), match.end() + 100)
            context_line = text[line_start:line_end].strip()
            # Redact the actual secret in the context
            context_line = context_line.replace(matched_text, redact(matched_text))

            findings.append(SecretFinding(
                pattern_id=pattern.id,
                pattern_name=pattern.name,
                category=pattern.category,
                severity=pattern.severity,
                matched_text=matched_text,
                redacted_text=redact(matched_text),
                source_file=source_file,
                source_tool=source_tool,
                line_number=line_number,
                context=context_line[:200],  # Truncate long contexts
            ))

    return findings


def scan_source(source: ChatSource) -> ScanResult:
    """Scan a single ChatSource for secrets."""
    result = ScanResult(
        source_name=source.name,
        source_path=str(source.path),
        found=source.found,
        conversation_count=source.conversation_count,
        message_count=source.message_count,
        error=source.error,
    )

    if not source.found or not source.messages:
        return result

    patterns = get_patterns()

    for message in source.messages:
        findings = scan_text(
            text=message.text,
            patterns=patterns,
            source_file=message.source_file,
            source_tool=source.name,
        )
        result.findings.extend(findings)

    return result


def scan_all(sources: list[ChatSource]) -> FullScanResult:
    """Scan all ChatSources and return aggregate results."""
    full_result = FullScanResult()

    for source in sources:
        result = scan_source(source)
        full_result.results.append(result)

    full_result.compute_aggregates()
    return full_result
