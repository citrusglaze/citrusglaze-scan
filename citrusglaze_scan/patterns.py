"""
Secret detection patterns — 322 types.

Ported from CitrusGlaze Rust crate + Gitleaks (MIT) + custom research.
Sources: TruffleHog, Gitleaks, STAKPAK, and original patterns.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SecretCategory(Enum):
    CLOUD_PROVIDER = "Cloud Provider"
    AI_SERVICE = "AI Service"
    VERSION_CONTROL = "Version Control"
    PAYMENT = "Payment"
    COMMUNICATION = "Communication"
    DATABASE = "Database"
    INFRASTRUCTURE = "Infrastructure"
    CRYPTOGRAPHIC = "Cryptographic"
    PII = "PII"
    CI_CD = "CI/CD"
    MONITORING = "Monitoring"
    GENERIC = "Generic"



@dataclass
class SecretPattern:
    id: str
    name: str
    description: str
    category: SecretCategory
    severity: Severity
    regex: re.Pattern
    context_keywords: List[str] = field(default_factory=list)
    entropy_threshold: Optional[float] = None


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def build_patterns() -> List[SecretPattern]:
    """Build all secret detection patterns (ported from Rust crate)."""
    patterns = []

    # =========================================================================
    # Cloud Providers: AWS, GCP, Azure, Alibaba, Tencent, Huawei, Baidu
    # =========================================================================

    # AWS
    patterns.append(SecretPattern(
        id="aws_access_key_id",
        name="AWS Access Key ID",
        description="AWS Access Key ID starting with AKIA",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.CRITICAL,
        regex=re.compile(r"AKIA[0-9A-Z]{16}"),
    ))

    patterns.append(SecretPattern(
        id="aws_secret_access_key",
        name="AWS Secret Access Key",
        description="AWS Secret Access Key (40 character base64)",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.CRITICAL,
        regex=re.compile(r"""(?i)(aws_secret_access_key|aws_secret|secret_access_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"""),
        context_keywords=["aws", "secret"],
        entropy_threshold=4.0,
    ))

    patterns.append(SecretPattern(
        id="aws_session_token",
        name="AWS Session Token",
        description="AWS temporary session token",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(aws_session_token|AWS_SESSION_TOKEN)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{100,})['"]?"""),
    ))

    patterns.append(SecretPattern(
        id="aws_mws_key",
        name="AWS MWS Key",
        description="Amazon Marketplace Web Service key",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.HIGH,
        regex=re.compile(r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    ))

    # Google Cloud Platform
    patterns.append(SecretPattern(
        id="gcp_api_key",
        name="Google API Key",
        description="Google Cloud Platform API key",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.CRITICAL,
        regex=re.compile(r"AIzaSy[A-Za-z0-9_-]{33}"),
    ))

    patterns.append(SecretPattern(
        id="gcp_oauth_token",
        name="Google OAuth Token",
        description="Google OAuth 2.0 access token",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.HIGH,
        regex=re.compile(r"ya29\.[A-Za-z0-9_-]+"),
    ))

    patterns.append(SecretPattern(
        id="gcp_service_account",
        name="GCP Service Account",
        description="Google Cloud service account JSON key",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.CRITICAL,
        regex=re.compile(r'''"type"\s*:\s*"service_account"'''),
        context_keywords=["private_key"],
    ))

    patterns.append(SecretPattern(
        id="firebase_key",
        name="Firebase Cloud Messaging Key",
        description="Firebase FCM server key",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.HIGH,
        regex=re.compile(r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"),
    ))

    # Microsoft Azure
    patterns.append(SecretPattern(
        id="azure_storage_key",
        name="Azure Storage Account Key",
        description="Azure Storage account access key",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.CRITICAL,
        regex=re.compile(r"""(?i)(AccountKey|azure_storage_key)\s*[=:]\s*['"]?([A-Za-z0-9+/]{86}==)['"]?"""),
        context_keywords=["azure", "storage"],
    ))

    patterns.append(SecretPattern(
        id="azure_client_secret",
        name="Azure Client Secret",
        description="Azure AD application client secret",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.CRITICAL,
        regex=re.compile(r"""(?i)(client_secret|AZURE_CLIENT_SECRET)\s*[=:]\s*['"]?([A-Za-z0-9_~.\-]{34,})['"]?"""),
        context_keywords=["azure", "client"],
        entropy_threshold=4.0,
    ))

    # Alibaba Cloud
    patterns.append(SecretPattern(
        id="alibaba_access_key",
        name="Alibaba Cloud Access Key",
        description="Alibaba Cloud AccessKey ID",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.CRITICAL,
        regex=re.compile(r"LTAI[A-Za-z0-9]{12,20}"),
    ))

    # Tencent Cloud
    patterns.append(SecretPattern(
        id="tencent_secret_id",
        name="Tencent Cloud Secret ID",
        description="Tencent Cloud API SecretId",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.CRITICAL,
        regex=re.compile(r"AKID[A-Za-z0-9]{13,20}"),
    ))

    # =========================================================================
    # AI Services: OpenAI, Anthropic, DeepSeek, Cohere, HuggingFace, Replicate
    # =========================================================================

    patterns.append(SecretPattern(
        id="openai_api_key",
        name="OpenAI API Key",
        description="OpenAI API key starting with sk-",
        category=SecretCategory.AI_SERVICE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}"),
    ))

    patterns.append(SecretPattern(
        id="openai_project_key",
        name="OpenAI Project Key",
        description="OpenAI project-scoped API key",
        category=SecretCategory.AI_SERVICE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"sk-proj-[A-Za-z0-9_-]{48,}"),
    ))

    patterns.append(SecretPattern(
        id="openai_org_id",
        name="OpenAI Organization ID",
        description="OpenAI organization identifier",
        category=SecretCategory.AI_SERVICE,
        severity=Severity.MEDIUM,
        regex=re.compile(r"org-[A-Za-z0-9]{24}"),
    ))

    patterns.append(SecretPattern(
        id="anthropic_api_key",
        name="Anthropic API Key",
        description="Anthropic Claude API key",
        category=SecretCategory.AI_SERVICE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"sk-ant-[A-Za-z0-9-]{20,}"),
    ))

    patterns.append(SecretPattern(
        id="deepseek_api_key",
        name="DeepSeek API Key",
        description="DeepSeek API key",
        category=SecretCategory.AI_SERVICE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"""(?i)(DEEPSEEK_API_KEY|deepseek_key)\s*[=:]\s*['"]?(sk-[a-f0-9]{32})['"]?"""),
        context_keywords=["deepseek"],
    ))

    patterns.append(SecretPattern(
        id="cohere_api_key",
        name="Cohere API Key",
        description="Cohere NLP API key",
        category=SecretCategory.AI_SERVICE,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(COHERE_API_KEY|cohere_key)\s*[=:]\s*['"]?([A-Za-z0-9]{40})['"]?"""),
        context_keywords=["cohere"],
        entropy_threshold=4.0,
    ))

    patterns.append(SecretPattern(
        id="huggingface_token",
        name="Hugging Face Token",
        description="Hugging Face access token",
        category=SecretCategory.AI_SERVICE,
        severity=Severity.HIGH,
        regex=re.compile(r"hf_[A-Za-z0-9]{30,40}"),
    ))

    patterns.append(SecretPattern(
        id="replicate_api_token",
        name="Replicate API Token",
        description="Replicate ML platform token",
        category=SecretCategory.AI_SERVICE,
        severity=Severity.HIGH,
        regex=re.compile(r"r8_[A-Za-z0-9]{37}"),
    ))

    # =========================================================================
    # Version Control: GitHub, GitLab, Bitbucket
    # =========================================================================

    patterns.append(SecretPattern(
        id="github_pat",
        name="GitHub Personal Access Token",
        description="GitHub classic personal access token",
        category=SecretCategory.VERSION_CONTROL,
        severity=Severity.CRITICAL,
        regex=re.compile(r"ghp_[A-Za-z0-9]{36}"),
    ))

    patterns.append(SecretPattern(
        id="github_oauth",
        name="GitHub OAuth Token",
        description="GitHub OAuth access token",
        category=SecretCategory.VERSION_CONTROL,
        severity=Severity.CRITICAL,
        regex=re.compile(r"gho_[A-Za-z0-9]{36}"),
    ))

    patterns.append(SecretPattern(
        id="github_app_token",
        name="GitHub App User Token",
        description="GitHub App user-to-server token",
        category=SecretCategory.VERSION_CONTROL,
        severity=Severity.HIGH,
        regex=re.compile(r"ghu_[A-Za-z0-9]{36}"),
    ))

    patterns.append(SecretPattern(
        id="github_refresh_token",
        name="GitHub Refresh Token",
        description="GitHub OAuth refresh token",
        category=SecretCategory.VERSION_CONTROL,
        severity=Severity.HIGH,
        regex=re.compile(r"ghr_[A-Za-z0-9]{36}"),
    ))

    patterns.append(SecretPattern(
        id="github_fine_grained",
        name="GitHub Fine-Grained PAT",
        description="GitHub fine-grained personal access token",
        category=SecretCategory.VERSION_CONTROL,
        severity=Severity.CRITICAL,
        regex=re.compile(r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}"),
    ))

    patterns.append(SecretPattern(
        id="gitlab_pat",
        name="GitLab Personal Access Token",
        description="GitLab personal access token",
        category=SecretCategory.VERSION_CONTROL,
        severity=Severity.CRITICAL,
        regex=re.compile(r"glpat-[A-Za-z0-9_-]{20}"),
    ))

    patterns.append(SecretPattern(
        id="gitlab_pipeline_token",
        name="GitLab Pipeline Token",
        description="GitLab pipeline trigger token",
        category=SecretCategory.VERSION_CONTROL,
        severity=Severity.HIGH,
        regex=re.compile(r"glptt-[A-Za-z0-9]{40}"),
    ))

    patterns.append(SecretPattern(
        id="gitlab_runner_token",
        name="GitLab Runner Token",
        description="GitLab CI runner registration token",
        category=SecretCategory.VERSION_CONTROL,
        severity=Severity.HIGH,
        regex=re.compile(r"GR1348941[A-Za-z0-9_-]{20}"),
    ))

    patterns.append(SecretPattern(
        id="bitbucket_app_password",
        name="Bitbucket App Password",
        description="Bitbucket application password",
        category=SecretCategory.VERSION_CONTROL,
        severity=Severity.CRITICAL,
        regex=re.compile(r"ATBB[A-Za-z0-9]{32}"),
    ))

    # =========================================================================
    # Payment: Stripe, PayPal, Square
    # =========================================================================

    patterns.append(SecretPattern(
        id="stripe_secret_key",
        name="Stripe Live Secret Key",
        description="Stripe live mode secret key",
        category=SecretCategory.PAYMENT,
        severity=Severity.CRITICAL,
        regex=re.compile(r"sk_live_[A-Za-z0-9]{24,}"),
    ))

    patterns.append(SecretPattern(
        id="stripe_test_key",
        name="Stripe Test Secret Key",
        description="Stripe test mode secret key",
        category=SecretCategory.PAYMENT,
        severity=Severity.MEDIUM,
        regex=re.compile(r"sk_test_[A-Za-z0-9]{24,}"),
    ))

    patterns.append(SecretPattern(
        id="stripe_publishable",
        name="Stripe Publishable Key",
        description="Stripe publishable key (lower risk)",
        category=SecretCategory.PAYMENT,
        severity=Severity.LOW,
        regex=re.compile(r"pk_(live|test)_[A-Za-z0-9]{24,}"),
    ))

    patterns.append(SecretPattern(
        id="stripe_webhook",
        name="Stripe Webhook Secret",
        description="Stripe webhook signing secret",
        category=SecretCategory.PAYMENT,
        severity=Severity.HIGH,
        regex=re.compile(r"whsec_[A-Za-z0-9]{32,}"),
    ))

    patterns.append(SecretPattern(
        id="paypal_braintree",
        name="PayPal Braintree Token",
        description="PayPal Braintree access token",
        category=SecretCategory.PAYMENT,
        severity=Severity.CRITICAL,
        regex=re.compile(r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"),
    ))

    patterns.append(SecretPattern(
        id="square_access_token",
        name="Square Access Token",
        description="Square OAuth access token",
        category=SecretCategory.PAYMENT,
        severity=Severity.CRITICAL,
        regex=re.compile(r"sq0atp-[A-Za-z0-9_-]{22}"),
    ))

    patterns.append(SecretPattern(
        id="square_oauth_secret",
        name="Square OAuth Secret",
        description="Square application secret",
        category=SecretCategory.PAYMENT,
        severity=Severity.CRITICAL,
        regex=re.compile(r"sq0csp-[A-Za-z0-9_-]{43}"),
    ))

    # =========================================================================
    # Communication: Slack, Discord, Twilio, SendGrid, Mailchimp
    # =========================================================================

    patterns.append(SecretPattern(
        id="slack_bot_token",
        name="Slack Bot Token",
        description="Slack bot user OAuth token",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.CRITICAL,
        regex=re.compile(r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}"),
    ))

    patterns.append(SecretPattern(
        id="slack_user_token",
        name="Slack User Token",
        description="Slack user OAuth token",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.CRITICAL,
        regex=re.compile(r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}"),
    ))

    patterns.append(SecretPattern(
        id="slack_webhook",
        name="Slack Webhook URL",
        description="Slack incoming webhook URL",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.HIGH,
        regex=re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}"),
    ))

    patterns.append(SecretPattern(
        id="slack_app_token",
        name="Slack App Token",
        description="Slack app-level token",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.HIGH,
        regex=re.compile(r"xapp-[0-9]-[A-Z0-9]{11}-[0-9]{13}-[a-f0-9]{64}"),
    ))

    patterns.append(SecretPattern(
        id="discord_bot_token",
        name="Discord Bot Token",
        description="Discord bot authentication token",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.CRITICAL,
        regex=re.compile(r"[MN][A-Za-z\d]{23,}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27}"),
    ))

    patterns.append(SecretPattern(
        id="discord_webhook",
        name="Discord Webhook URL",
        description="Discord webhook URL",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.HIGH,
        regex=re.compile(r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+"),
    ))

    patterns.append(SecretPattern(
        id="twilio_account_sid",
        name="Twilio Account SID",
        description="Twilio account identifier",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.MEDIUM,
        regex=re.compile(r"AC[a-f0-9]{32}"),
    ))

    patterns.append(SecretPattern(
        id="twilio_api_key",
        name="Twilio API Key",
        description="Twilio API key",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.HIGH,
        regex=re.compile(r"SK[a-f0-9]{32}"),
    ))

    patterns.append(SecretPattern(
        id="sendgrid_api_key",
        name="SendGrid API Key",
        description="SendGrid email API key",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.CRITICAL,
        regex=re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
    ))

    patterns.append(SecretPattern(
        id="mailchimp_api_key",
        name="Mailchimp API Key",
        description="Mailchimp API key",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.HIGH,
        regex=re.compile(r"[a-f0-9]{32}-us[0-9]{1,2}"),
    ))

    # =========================================================================
    # Database: MongoDB, PostgreSQL, MySQL, Redis
    # =========================================================================

    patterns.append(SecretPattern(
        id="mongodb_uri",
        name="MongoDB Connection String",
        description="MongoDB URI with credentials",
        category=SecretCategory.DATABASE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"mongodb(\+srv)?://[^:]+:[^@]+@[^\s]+"),
    ))

    patterns.append(SecretPattern(
        id="postgres_uri",
        name="PostgreSQL Connection String",
        description="PostgreSQL URI with credentials",
        category=SecretCategory.DATABASE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"postgres(ql)?://[^:]+:[^@]+@[^\s]+"),
    ))

    patterns.append(SecretPattern(
        id="mysql_uri",
        name="MySQL Connection String",
        description="MySQL URI with credentials",
        category=SecretCategory.DATABASE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"mysql://[^:]+:[^@]+@[^\s]+"),
    ))

    patterns.append(SecretPattern(
        id="redis_uri",
        name="Redis Connection String",
        description="Redis URI with password",
        category=SecretCategory.DATABASE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"redis://:[^@]+@[^\s]+"),
    ))

    # =========================================================================
    # Infrastructure: Docker, npm, PyPI, Terraform, Vault
    # =========================================================================

    patterns.append(SecretPattern(
        id="docker_hub_token",
        name="Docker Hub Token",
        description="Docker Hub personal access token",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"dckr_pat_[A-Za-z0-9_-]{56}"),
    ))

    patterns.append(SecretPattern(
        id="npm_token",
        name="npm Access Token",
        description="npm registry access token",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"npm_[A-Za-z0-9]{36}"),
    ))

    patterns.append(SecretPattern(
        id="pypi_token",
        name="PyPI API Token",
        description="Python Package Index token",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"pypi-[A-Za-z0-9_-]{150,}"),
    ))

    patterns.append(SecretPattern(
        id="terraform_cloud_token",
        name="Terraform Cloud Token",
        description="Terraform Cloud/Enterprise API token",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9]{60,70}"),
    ))

    patterns.append(SecretPattern(
        id="vault_token",
        name="HashiCorp Vault Token",
        description="Vault service token",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"hvs\.[A-Za-z0-9_-]{24}"),
    ))

    patterns.append(SecretPattern(
        id="vault_batch_token",
        name="Vault Batch Token",
        description="Vault batch token",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"hvb\.[A-Za-z0-9_-]{24,}"),
    ))

    # =========================================================================
    # Cryptographic: Private Keys
    # =========================================================================

    patterns.append(SecretPattern(
        id="rsa_private_key",
        name="RSA Private Key",
        description="RSA private key in PEM format",
        category=SecretCategory.CRYPTOGRAPHIC,
        severity=Severity.CRITICAL,
        regex=re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
    ))

    patterns.append(SecretPattern(
        id="ec_private_key",
        name="EC Private Key",
        description="Elliptic curve private key",
        category=SecretCategory.CRYPTOGRAPHIC,
        severity=Severity.CRITICAL,
        regex=re.compile(r"-----BEGIN EC PRIVATE KEY-----"),
    ))

    patterns.append(SecretPattern(
        id="openssh_private_key",
        name="OpenSSH Private Key",
        description="OpenSSH private key",
        category=SecretCategory.CRYPTOGRAPHIC,
        severity=Severity.CRITICAL,
        regex=re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
    ))

    patterns.append(SecretPattern(
        id="pgp_private_key",
        name="PGP Private Key",
        description="PGP private key block",
        category=SecretCategory.CRYPTOGRAPHIC,
        severity=Severity.CRITICAL,
        regex=re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
    ))

    patterns.append(SecretPattern(
        id="pkcs8_private_key",
        name="PKCS#8 Private Key",
        description="PKCS#8 format private key",
        category=SecretCategory.CRYPTOGRAPHIC,
        severity=Severity.CRITICAL,
        regex=re.compile(r"-----BEGIN PRIVATE KEY-----"),
    ))

    # =========================================================================
    # Generic: High-entropy strings, URLs with auth, JWT
    # =========================================================================

    patterns.append(SecretPattern(
        id="generic_secret",
        name="Generic Secret",
        description="High-entropy string in secret context",
        category=SecretCategory.GENERIC,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(secret|password|passwd|pwd|token|api[_\-]?key|apikey|auth|credentials?|private[_\-]?key)['"]?\s*[:=]\s*['"]?([A-Za-z0-9_/+=-]{20,})['"]?"""),
        entropy_threshold=4.5,
    ))

    patterns.append(SecretPattern(
        id="basic_auth_url",
        name="URL with Basic Auth",
        description="URL containing embedded credentials",
        category=SecretCategory.GENERIC,
        severity=Severity.HIGH,
        regex=re.compile(r"https?://[A-Za-z0-9._~%!$&'()*+,;=-]+:[A-Za-z0-9._~%!$&'()*+,;=-]+@[^\s/]+"),
    ))

    patterns.append(SecretPattern(
        id="jwt_token",
        name="JSON Web Token",
        description="JWT token (may contain sensitive claims)",
        category=SecretCategory.GENERIC,
        severity=Severity.MEDIUM,
        regex=re.compile(r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"),
    ))

    # =========================================================================
    # Additional patterns not in the base Rust crate but useful for scanning
    # =========================================================================

    # Cloudflare
    patterns.append(SecretPattern(
        id="cloudflare_api_token",
        name="Cloudflare API Token",
        description="Cloudflare API token",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"[A-Za-z0-9_-]{40}"),
        context_keywords=["cloudflare", "CF_API_TOKEN", "CLOUDFLARE_API_TOKEN"],
        entropy_threshold=4.5,
    ))

    # Vercel
    patterns.append(SecretPattern(
        id="vercel_token",
        name="Vercel Token",
        description="Vercel deployment token",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(VERCEL_TOKEN|vercel_token)\s*[=:]\s*['"]?([A-Za-z0-9]{24,})['"]?"""),
    ))

    # Supabase
    patterns.append(SecretPattern(
        id="supabase_key",
        name="Supabase Key",
        description="Supabase API key (anon or service_role)",
        category=SecretCategory.DATABASE,
        severity=Severity.HIGH,
        regex=re.compile(r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
        context_keywords=["supabase", "SUPABASE_KEY", "SUPABASE_ANON_KEY"],
    ))

    # Doppler
    patterns.append(SecretPattern(
        id="doppler_token",
        name="Doppler Token",
        description="Doppler service token",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"dp\.st\.[a-z0-9_-]+\.[A-Za-z0-9]{40,}"),
    ))

    # Linear
    patterns.append(SecretPattern(
        id="linear_api_key",
        name="Linear API Key",
        description="Linear project management API key",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"lin_api_[A-Za-z0-9]{40}"),
    ))

    # Grafana
    patterns.append(SecretPattern(
        id="grafana_api_key",
        name="Grafana API Key",
        description="Grafana API key or service account token",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}"),
    ))

    # Datadog
    patterns.append(SecretPattern(
        id="datadog_api_key",
        name="Datadog API Key",
        description="Datadog API key",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(DD_API_KEY|DATADOG_API_KEY)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?"""),
        context_keywords=["datadog"],
    ))

    # Shopify
    patterns.append(SecretPattern(
        id="shopify_access_token",
        name="Shopify Access Token",
        description="Shopify Admin API access token",
        category=SecretCategory.PAYMENT,
        severity=Severity.CRITICAL,
        regex=re.compile(r"shpat_[a-fA-F0-9]{32}"),
    ))

    patterns.append(SecretPattern(
        id="shopify_shared_secret",
        name="Shopify Shared Secret",
        description="Shopify app shared secret",
        category=SecretCategory.PAYMENT,
        severity=Severity.CRITICAL,
        regex=re.compile(r"shpss_[a-fA-F0-9]{32}"),
    ))

    # Notion
    patterns.append(SecretPattern(
        id="notion_integration_token",
        name="Notion Integration Token",
        description="Notion API integration token",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"ntn_[A-Za-z0-9]{43}"),
    ))

    # Age encryption key
    patterns.append(SecretPattern(
        id="age_secret_key",
        name="Age Secret Key",
        description="Age encryption secret key",
        category=SecretCategory.CRYPTOGRAPHIC,
        severity=Severity.CRITICAL,
        regex=re.compile(r"AGE-SECRET-KEY-[A-Z0-9]{59}"),
    ))

    # =========================================================================
    # Ported from Rust crate: missing patterns
    # =========================================================================

    # Azure SAS Token
    patterns.append(SecretPattern(
        id="azure_sas_token",
        name="Azure SAS Token",
        description="Azure Shared Access Signature token",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.HIGH,
        regex=re.compile(r"sig=[A-Za-z0-9%]{43,}"),
        context_keywords=["azure", "blob", "sv="],
    ))

    # Alibaba Secret Key
    patterns.append(SecretPattern(
        id="alibaba_secret_key",
        name="Alibaba Cloud Secret Key",
        description="Alibaba Cloud AccessKey Secret",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.CRITICAL,
        regex=re.compile(r"""(?i)(AccessKeySecret|aliyun_secret)\s*[=:]\s*['"]?([A-Za-z0-9]{30})['"]?"""),
        context_keywords=["aliyun", "alibaba"],
        entropy_threshold=4.0,
    ))

    # Tencent Secret Key
    patterns.append(SecretPattern(
        id="tencent_secret_key",
        name="Tencent Cloud Secret Key",
        description="Tencent Cloud API SecretKey",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.CRITICAL,
        regex=re.compile(r"""(?i)(SecretKey|TENCENT_SECRET_KEY)\s*[=:]\s*['"]?([A-Za-z0-9]{32})['"]?"""),
        context_keywords=["tencent"],
        entropy_threshold=4.0,
    ))

    # Huawei Cloud
    patterns.append(SecretPattern(
        id="huawei_access_key",
        name="Huawei Cloud Access Key",
        description="Huawei Cloud AK/SK",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.CRITICAL,
        regex=re.compile(r"""(?i)(HUAWEI_ACCESS_KEY|hw_ak)\s*[=:]\s*['"]?([A-Z0-9]{20})['"]?"""),
        context_keywords=["huawei"],
    ))

    # Baidu Cloud
    patterns.append(SecretPattern(
        id="baidu_access_key",
        name="Baidu Cloud Access Key",
        description="Baidu Cloud BCE Access Key",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.CRITICAL,
        regex=re.compile(r"""(?i)(BAIDU_AK|bce_access_key)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?"""),
        context_keywords=["baidu", "bce"],
    ))

    # Chinese AI providers
    patterns.append(SecretPattern(
        id="zhipu_api_key",
        name="Zhipu AI API Key",
        description="Zhipu AI (ChatGLM) API key",
        category=SecretCategory.AI_SERVICE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"""(?i)(ZHIPU_API_KEY|zhipu_key)\s*[=:]\s*['"]?([A-Za-z0-9]{32,})['"]?"""),
        context_keywords=["zhipu", "glm"],
        entropy_threshold=4.0,
    ))

    patterns.append(SecretPattern(
        id="moonshot_api_key",
        name="Moonshot AI API Key",
        description="Moonshot AI (Kimi) API key",
        category=SecretCategory.AI_SERVICE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"""(?i)(MOONSHOT_API_KEY)\s*[=:]\s*['"]?([A-Za-z0-9]{32,})['"]?"""),
        context_keywords=["moonshot", "kimi"],
        entropy_threshold=4.0,
    ))

    # Encrypted Private Key
    patterns.append(SecretPattern(
        id="encrypted_private_key",
        name="Encrypted Private Key",
        description="Encrypted private key (lower risk)",
        category=SecretCategory.CRYPTOGRAPHIC,
        severity=Severity.HIGH,
        regex=re.compile(r"-----BEGIN ENCRYPTED PRIVATE KEY-----"),
    ))

    # =========================================================================
    # PII Patterns (from Rust crate)
    # =========================================================================

    patterns.append(SecretPattern(
        id="ssn",
        name="US Social Security Number",
        description="US SSN format XXX-XX-XXXX",
        category=SecretCategory.PII,
        severity=Severity.CRITICAL,
        regex=re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        context_keywords=["ssn", "social", "security"],
    ))

    patterns.append(SecretPattern(
        id="credit_card",
        name="Credit Card Number",
        description="Major credit card number patterns (Visa, MC, Amex, Discover)",
        category=SecretCategory.PII,
        severity=Severity.CRITICAL,
        regex=re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"),
    ))

    patterns.append(SecretPattern(
        id="email_address",
        name="Email Address",
        description="Email address (PII — potential data exfiltration)",
        category=SecretCategory.PII,
        severity=Severity.HIGH,
        regex=re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"),
        context_keywords=["email", "mailto", "customer", "patient", "employee", "recipient", "personal", "pii", "user_email", "user email"],
    ))

    patterns.append(SecretPattern(
        id="phone_number_us",
        name="US Phone Number",
        description="US phone number in various formats",
        category=SecretCategory.PII,
        severity=Severity.HIGH,
        regex=re.compile(r"(?:^|[\s,;:({])(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?[2-9]\d{2}[-.\s]?\d{4}\b"),
        context_keywords=["phone", "mobile", "cell", "tel", "call", "contact", "sms"],
    ))

    patterns.append(SecretPattern(
        id="phone_number_intl",
        name="International Phone Number",
        description="International phone number in E.164 or common formats",
        category=SecretCategory.PII,
        severity=Severity.HIGH,
        regex=re.compile(r"\+[1-9]\d{6,14}\b"),
        context_keywords=["phone", "mobile", "cell", "tel", "call", "contact", "whatsapp"],
    ))

    patterns.append(SecretPattern(
        id="iban",
        name="IBAN (International Bank Account Number)",
        description="IBAN bank account number (PII/financial)",
        category=SecretCategory.PII,
        severity=Severity.CRITICAL,
        regex=re.compile(r"\b(?:AL|AD|AT|AZ|BH|BY|BE|BA|BR|BG|CR|HR|CY|CZ|DK|DO|TL|EE|FO|FI|FR|GE|DE|GI|GR|GL|GT|HU|IS|IQ|IE|IL|IT|JO|KZ|XK|KW|LV|LB|LI|LT|LU|MT|MR|MU|MC|MD|ME|NL|MK|NO|PK|PS|PL|PT|QA|RO|LC|SM|ST|SA|RS|SC|SK|SI|ES|SE|CH|TN|TR|UA|AE|GB|VA|VG)\d{2}[A-Z0-9]{11,30}\b"),
        context_keywords=["iban", "bank", "account", "transfer", "wire", "payment"],
    ))

    patterns.append(SecretPattern(
        id="passport_us",
        name="US Passport Number",
        description="US passport number (9 digits)",
        category=SecretCategory.PII,
        severity=Severity.CRITICAL,
        regex=re.compile(r"\b[0-9]{9}\b"),
        context_keywords=["passport", "travel", "document", "visa"],
    ))

    patterns.append(SecretPattern(
        id="date_of_birth",
        name="Date of Birth",
        description="Date of birth in common formats (PII)",
        category=SecretCategory.PII,
        severity=Severity.HIGH,
        regex=re.compile(r"\b(?:0[1-9]|1[0-2])[/\-](?:0[1-9]|[12]\d|3[01])[/\-](?:19|20)\d{2}\b"),
        context_keywords=["dob", "birth", "born", "birthday", "date of birth"],
    ))

    patterns.append(SecretPattern(
        id="drivers_license",
        name="Driver's License Number",
        description="US driver's license number (various state formats)",
        category=SecretCategory.PII,
        severity=Severity.CRITICAL,
        regex=re.compile(r"\b[A-Z]\d{7,14}\b"),
        context_keywords=["license", "licence", "driver", "dl", "dmv", "driving"],
    ))

    # =========================================================================
    # Gitleaks-sourced patterns + additional research (MIT licensed)
    # =========================================================================

    # --- CI/CD ---

    patterns.append(SecretPattern(
        id="circleci_token",
        name="CircleCI Personal Token",
        description="CircleCI personal API token",
        category=SecretCategory.CI_CD,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(CIRCLECI_TOKEN|circle_token)\s*[=:]\s*['"]?([a-f0-9]{40})['"]?"""),
        context_keywords=["circleci"],
    ))

    patterns.append(SecretPattern(
        id="travis_ci_token",
        name="Travis CI Token",
        description="Travis CI API token",
        category=SecretCategory.CI_CD,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(TRAVIS_TOKEN|travis_api_token)\s*[=:]\s*['"]?([A-Za-z0-9_-]{20,})['"]?"""),
        context_keywords=["travis"],
        entropy_threshold=4.0,
    ))

    patterns.append(SecretPattern(
        id="jenkins_token",
        name="Jenkins API Token",
        description="Jenkins user API token",
        category=SecretCategory.CI_CD,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(JENKINS_TOKEN|jenkins_api_token)\s*[=:]\s*['"]?([a-f0-9]{34})['"]?"""),
        context_keywords=["jenkins"],
    ))

    patterns.append(SecretPattern(
        id="github_actions_secret",
        name="GitHub Actions Secret Reference",
        description="GitHub Actions secret in workflow context",
        category=SecretCategory.CI_CD,
        severity=Severity.MEDIUM,
        regex=re.compile(r"""(?i)(GITHUB_TOKEN|GH_TOKEN)\s*[=:]\s*['"]?(ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36})['"]?"""),
    ))

    patterns.append(SecretPattern(
        id="drone_ci_token",
        name="Drone CI Token",
        description="Drone CI personal token",
        category=SecretCategory.CI_CD,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(DRONE_TOKEN)\s*[=:]\s*['"]?([A-Za-z0-9]{32,})['"]?"""),
        context_keywords=["drone"],
        entropy_threshold=4.0,
    ))

    patterns.append(SecretPattern(
        id="buildkite_token",
        name="Buildkite Agent Token",
        description="Buildkite agent registration token",
        category=SecretCategory.CI_CD,
        severity=Severity.HIGH,
        regex=re.compile(r"bkua_[A-Za-z0-9]{40}"),
    ))

    patterns.append(SecretPattern(
        id="codecov_token",
        name="Codecov Token",
        description="Codecov upload token",
        category=SecretCategory.CI_CD,
        severity=Severity.MEDIUM,
        regex=re.compile(r"""(?i)(CODECOV_TOKEN)\s*[=:]\s*['"]?([a-f0-9-]{36})['"]?"""),
    ))

    # --- Cloud Providers (additional) ---

    patterns.append(SecretPattern(
        id="digitalocean_pat",
        name="DigitalOcean Personal Access Token",
        description="DigitalOcean API token",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.CRITICAL,
        regex=re.compile(r"dop_v1_[a-f0-9]{64}"),
    ))

    patterns.append(SecretPattern(
        id="digitalocean_oauth",
        name="DigitalOcean OAuth Token",
        description="DigitalOcean OAuth application token",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.CRITICAL,
        regex=re.compile(r"doo_v1_[a-f0-9]{64}"),
    ))

    patterns.append(SecretPattern(
        id="digitalocean_refresh",
        name="DigitalOcean Refresh Token",
        description="DigitalOcean OAuth refresh token",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.CRITICAL,
        regex=re.compile(r"dor_v1_[a-f0-9]{64}"),
    ))

    patterns.append(SecretPattern(
        id="linode_pat",
        name="Linode Personal Access Token",
        description="Linode/Akamai API token",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.CRITICAL,
        regex=re.compile(r"""(?i)(LINODE_TOKEN|linode_api_token)\s*[=:]\s*['"]?([a-f0-9]{64})['"]?"""),
        context_keywords=["linode"],
    ))

    patterns.append(SecretPattern(
        id="vultr_api_key",
        name="Vultr API Key",
        description="Vultr cloud API key",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.CRITICAL,
        regex=re.compile(r"""(?i)(VULTR_API_KEY)\s*[=:]\s*['"]?([A-Z0-9]{36})['"]?"""),
        context_keywords=["vultr"],
    ))

    patterns.append(SecretPattern(
        id="heroku_api_key",
        name="Heroku API Key",
        description="Heroku platform API key",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.CRITICAL,
        regex=re.compile(r"""(?i)(HEROKU_API_KEY|heroku_key)\s*[=:]\s*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?"""),
        context_keywords=["heroku"],
    ))

    patterns.append(SecretPattern(
        id="scaleway_secret_key",
        name="Scaleway Secret Key",
        description="Scaleway API secret key (UUID format)",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.CRITICAL,
        regex=re.compile(r"""(?i)(SCW_SECRET_KEY|scaleway_secret)\s*[=:]\s*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?"""),
        context_keywords=["scaleway"],
    ))

    patterns.append(SecretPattern(
        id="hetzner_api_token",
        name="Hetzner API Token",
        description="Hetzner Cloud API token",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.CRITICAL,
        regex=re.compile(r"""(?i)(HCLOUD_TOKEN|HETZNER_API_TOKEN)\s*[=:]\s*['"]?([A-Za-z0-9]{64})['"]?"""),
        context_keywords=["hetzner", "hcloud"],
        entropy_threshold=4.0,
    ))

    patterns.append(SecretPattern(
        id="ovh_api_key",
        name="OVH API Key",
        description="OVH cloud application key",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(OVH_APPLICATION_KEY|ovh_app_key)\s*[=:]\s*['"]?([A-Za-z0-9]{16})['"]?"""),
        context_keywords=["ovh"],
    ))

    # --- AI Services (additional) ---

    patterns.append(SecretPattern(
        id="mistral_api_key",
        name="Mistral AI API Key",
        description="Mistral AI API key",
        category=SecretCategory.AI_SERVICE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"""(?i)(MISTRAL_API_KEY)\s*[=:]\s*['"]?([A-Za-z0-9]{32})['"]?"""),
        context_keywords=["mistral"],
        entropy_threshold=4.0,
    ))

    patterns.append(SecretPattern(
        id="together_api_key",
        name="Together AI API Key",
        description="Together AI API key",
        category=SecretCategory.AI_SERVICE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"""(?i)(TOGETHER_API_KEY)\s*[=:]\s*['"]?([a-f0-9]{64})['"]?"""),
        context_keywords=["together"],
    ))

    patterns.append(SecretPattern(
        id="groq_api_key",
        name="Groq API Key",
        description="Groq inference API key",
        category=SecretCategory.AI_SERVICE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"gsk_[A-Za-z0-9]{48,}"),
    ))

    patterns.append(SecretPattern(
        id="perplexity_api_key",
        name="Perplexity API Key",
        description="Perplexity AI API key",
        category=SecretCategory.AI_SERVICE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"pplx-[a-f0-9]{48}"),
    ))

    patterns.append(SecretPattern(
        id="fireworks_api_key",
        name="Fireworks AI API Key",
        description="Fireworks AI inference API key",
        category=SecretCategory.AI_SERVICE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"""(?i)(FIREWORKS_API_KEY)\s*[=:]\s*['"]?([A-Za-z0-9]{48,})['"]?"""),
        context_keywords=["fireworks"],
        entropy_threshold=4.0,
    ))

    patterns.append(SecretPattern(
        id="stability_api_key",
        name="Stability AI API Key",
        description="Stability AI (Stable Diffusion) API key",
        category=SecretCategory.AI_SERVICE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"sk-[A-Za-z0-9]{48}"),
        context_keywords=["stability", "stable diffusion", "STABILITY_API_KEY"],
    ))

    patterns.append(SecretPattern(
        id="voyage_api_key",
        name="Voyage AI API Key",
        description="Voyage AI embeddings API key",
        category=SecretCategory.AI_SERVICE,
        severity=Severity.HIGH,
        regex=re.compile(r"pa-(?=[A-Za-z0-9_-]{43}\b)(?=(?:[A-Za-z0-9_-]*[A-Z]){2})(?=(?:[A-Za-z0-9_-]*[0-9]){2})[A-Za-z0-9_-]{43}"),
        context_keywords=["voyage", "VOYAGE_API_KEY", "embedding"],
        entropy_threshold=4.0,
    ))

    patterns.append(SecretPattern(
        id="pinecone_api_key",
        name="Pinecone API Key",
        description="Pinecone vector database API key",
        category=SecretCategory.AI_SERVICE,
        severity=Severity.HIGH,
        regex=re.compile(r"pcsk_[A-Za-z0-9_]{50,}"),
    ))

    patterns.append(SecretPattern(
        id="wandb_api_key",
        name="Weights & Biases API Key",
        description="Weights & Biases (wandb) API key",
        category=SecretCategory.AI_SERVICE,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(WANDB_API_KEY)\s*[=:]\s*['"]?([a-f0-9]{40})['"]?"""),
        context_keywords=["wandb", "weights"],
    ))

    patterns.append(SecretPattern(
        id="openrouter_api_key",
        name="OpenRouter API Key",
        description="OpenRouter LLM routing API key",
        category=SecretCategory.AI_SERVICE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"sk-or-v1-[a-f0-9]{64}"),
    ))

    # --- Communication (additional) ---

    patterns.append(SecretPattern(
        id="telegram_bot_token",
        name="Telegram Bot Token",
        description="Telegram Bot API token",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.CRITICAL,
        regex=re.compile(r"[0-9]{8,10}:AA[A-Za-z0-9_-]{33}"),
    ))

    patterns.append(SecretPattern(
        id="facebook_access_token",
        name="Facebook Access Token",
        description="Facebook/Meta Graph API access token",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.CRITICAL,
        regex=re.compile(r"EAA[A-Za-z0-9]{100,}"),
    ))

    patterns.append(SecretPattern(
        id="twitter_bearer_token",
        name="Twitter/X Bearer Token",
        description="Twitter API v2 bearer token",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.CRITICAL,
        regex=re.compile(r"AAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{30,}"),
    ))

    patterns.append(SecretPattern(
        id="twitter_api_key",
        name="Twitter/X API Key",
        description="Twitter API key (consumer key)",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(TWITTER_API_KEY|twitter_consumer_key)\s*[=:]\s*['"]?([A-Za-z0-9]{25})['"]?"""),
        context_keywords=["twitter"],
    ))

    patterns.append(SecretPattern(
        id="twitter_api_secret",
        name="Twitter/X API Secret",
        description="Twitter API secret (consumer secret)",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.CRITICAL,
        regex=re.compile(r"""(?i)(TWITTER_API_SECRET|twitter_consumer_secret)\s*[=:]\s*['"]?([A-Za-z0-9]{50})['"]?"""),
        context_keywords=["twitter"],
    ))

    patterns.append(SecretPattern(
        id="postmark_server_token",
        name="Postmark Server Token",
        description="Postmark email API server token",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(POSTMARK_SERVER_TOKEN|postmark_token)\s*[=:]\s*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?"""),
        context_keywords=["postmark"],
    ))

    patterns.append(SecretPattern(
        id="mailgun_api_key",
        name="Mailgun API Key",
        description="Mailgun email API key",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.HIGH,
        regex=re.compile(r"key-[a-f0-9]{32}"),
        context_keywords=["mailgun"],
    ))

    patterns.append(SecretPattern(
        id="messagebird_api_key",
        name="MessageBird API Key",
        description="MessageBird communications API key",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(MESSAGEBIRD_API_KEY)\s*[=:]\s*['"]?([A-Za-z0-9]{25})['"]?"""),
        context_keywords=["messagebird"],
    ))

    patterns.append(SecretPattern(
        id="vonage_api_secret",
        name="Vonage API Secret",
        description="Vonage (Nexmo) API secret",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(NEXMO_API_SECRET|VONAGE_API_SECRET)\s*[=:]\s*['"]?([A-Za-z0-9]{16})['"]?"""),
        context_keywords=["vonage", "nexmo"],
    ))

    # --- Payment (additional) ---

    patterns.append(SecretPattern(
        id="adyen_api_key",
        name="Adyen API Key",
        description="Adyen payment platform API key",
        category=SecretCategory.PAYMENT,
        severity=Severity.CRITICAL,
        regex=re.compile(r"""(?i)(ADYEN_API_KEY)\s*[=:]\s*['"]?(AQE[a-z0-9]{50,})['"]?"""),
        context_keywords=["adyen"],
    ))

    patterns.append(SecretPattern(
        id="razorpay_key",
        name="Razorpay Key",
        description="Razorpay API key",
        category=SecretCategory.PAYMENT,
        severity=Severity.CRITICAL,
        regex=re.compile(r"rzp_(live|test)_[A-Za-z0-9]{14,}"),
    ))

    patterns.append(SecretPattern(
        id="shopify_private_app",
        name="Shopify Private App Token",
        description="Shopify private app API password",
        category=SecretCategory.PAYMENT,
        severity=Severity.CRITICAL,
        regex=re.compile(r"shppa_[a-fA-F0-9]{32}"),
    ))

    patterns.append(SecretPattern(
        id="shopify_custom_app",
        name="Shopify Custom App Token",
        description="Shopify custom app access token",
        category=SecretCategory.PAYMENT,
        severity=Severity.CRITICAL,
        regex=re.compile(r"shpca_[a-fA-F0-9]{32}"),
    ))

    patterns.append(SecretPattern(
        id="plaid_client_id",
        name="Plaid Client ID",
        description="Plaid financial API client ID",
        category=SecretCategory.PAYMENT,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(PLAID_CLIENT_ID)\s*[=:]\s*['"]?([a-f0-9]{24})['"]?"""),
        context_keywords=["plaid"],
    ))

    patterns.append(SecretPattern(
        id="plaid_secret",
        name="Plaid Secret",
        description="Plaid financial API secret key",
        category=SecretCategory.PAYMENT,
        severity=Severity.CRITICAL,
        regex=re.compile(r"""(?i)(PLAID_SECRET)\s*[=:]\s*['"]?([a-f0-9]{30})['"]?"""),
        context_keywords=["plaid"],
    ))

    # --- Infrastructure (additional) ---

    patterns.append(SecretPattern(
        id="netlify_token",
        name="Netlify Token",
        description="Netlify personal access token",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(NETLIFY_AUTH_TOKEN|netlify_token)\s*[=:]\s*['"]?([A-Za-z0-9_-]{40,})['"]?"""),
        context_keywords=["netlify"],
        entropy_threshold=4.0,
    ))

    patterns.append(SecretPattern(
        id="fly_api_token",
        name="Fly.io API Token",
        description="Fly.io deployment token",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"fo1_[A-Za-z0-9_-]{30,50}"),
    ))

    patterns.append(SecretPattern(
        id="railway_token",
        name="Railway Token",
        description="Railway deployment platform token",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(RAILWAY_TOKEN)\s*[=:]\s*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?"""),
        context_keywords=["railway"],
    ))

    patterns.append(SecretPattern(
        id="render_api_key",
        name="Render API Key",
        description="Render cloud platform API key",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"rnd_[A-Za-z0-9]{32,}"),
    ))

    patterns.append(SecretPattern(
        id="pulumi_access_token",
        name="Pulumi Access Token",
        description="Pulumi IaC platform access token",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"pul-[a-f0-9]{40}"),
    ))

    patterns.append(SecretPattern(
        id="snyk_token",
        name="Snyk Token",
        description="Snyk security platform API token",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(SNYK_TOKEN)\s*[=:]\s*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?"""),
        context_keywords=["snyk"],
    ))

    patterns.append(SecretPattern(
        id="sonarqube_token",
        name="SonarQube Token",
        description="SonarQube/SonarCloud API token",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"sqp_[a-f0-9]{40}"),
    ))

    patterns.append(SecretPattern(
        id="sentry_auth_token",
        name="Sentry Auth Token",
        description="Sentry error monitoring auth token",
        category=SecretCategory.MONITORING,
        severity=Severity.HIGH,
        regex=re.compile(r"sntrys_[A-Za-z0-9]{60,}"),
    ))

    patterns.append(SecretPattern(
        id="sentry_dsn",
        name="Sentry DSN",
        description="Sentry Data Source Name (contains project key)",
        category=SecretCategory.MONITORING,
        severity=Severity.MEDIUM,
        regex=re.compile(r"https://[a-f0-9]{32}@[a-z0-9.]+\.ingest\.sentry\.io/[0-9]+"),
    ))

    patterns.append(SecretPattern(
        id="new_relic_license_key",
        name="New Relic License Key",
        description="New Relic license/ingest key",
        category=SecretCategory.MONITORING,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(NEW_RELIC_LICENSE_KEY|newrelic_key)\s*[=:]\s*['"]?([a-f0-9]{40})['"]?"""),
        context_keywords=["newrelic", "new_relic"],
    ))

    patterns.append(SecretPattern(
        id="new_relic_api_key",
        name="New Relic API Key",
        description="New Relic user/REST API key",
        category=SecretCategory.MONITORING,
        severity=Severity.HIGH,
        regex=re.compile(r"NRAK-[A-Z0-9]{27}"),
    ))

    patterns.append(SecretPattern(
        id="pagerduty_token",
        name="PagerDuty Token",
        description="PagerDuty API token",
        category=SecretCategory.MONITORING,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(PAGERDUTY_TOKEN|pd_api_key)\s*[=:]\s*['"]?([A-Za-z0-9_+/=-]{20})['"]?"""),
        context_keywords=["pagerduty"],
    ))

    patterns.append(SecretPattern(
        id="splunk_hec_token",
        name="Splunk HEC Token",
        description="Splunk HTTP Event Collector token",
        category=SecretCategory.MONITORING,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(SPLUNK_HEC_TOKEN|splunk_token)\s*[=:]\s*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?"""),
        context_keywords=["splunk"],
    ))

    patterns.append(SecretPattern(
        id="elastic_api_key",
        name="Elasticsearch API Key",
        description="Elasticsearch/Elastic Cloud API key",
        category=SecretCategory.MONITORING,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(ELASTIC_API_KEY)\s*[=:]\s*['"]?([A-Za-z0-9_-]{40,})['"]?"""),
        context_keywords=["elastic"],
        entropy_threshold=4.0,
    ))

    # --- Database (additional) ---

    patterns.append(SecretPattern(
        id="cassandra_uri",
        name="Cassandra Connection String",
        description="Cassandra CQL URI with credentials",
        category=SecretCategory.DATABASE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"cassandra://[^:]+:[^@]+@[^\s]+"),
    ))

    patterns.append(SecretPattern(
        id="cockroachdb_uri",
        name="CockroachDB Connection String",
        description="CockroachDB URI with credentials",
        category=SecretCategory.DATABASE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"cockroachdb://[^:]+:[^@]+@[^\s]+"),
    ))

    patterns.append(SecretPattern(
        id="neon_db_uri",
        name="Neon Database URI",
        description="Neon serverless PostgreSQL URI",
        category=SecretCategory.DATABASE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"postgres(ql)?://[^:]+:[^@]+@[^.]+\.neon\.tech[^\s]*"),
    ))

    patterns.append(SecretPattern(
        id="planetscale_password",
        name="PlanetScale Password",
        description="PlanetScale database branch password",
        category=SecretCategory.DATABASE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"pscale_pw_[A-Za-z0-9_-]{43}"),
    ))

    patterns.append(SecretPattern(
        id="planetscale_token",
        name="PlanetScale Service Token",
        description="PlanetScale service token",
        category=SecretCategory.DATABASE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"pscale_tkn_[A-Za-z0-9_-]{43}"),
    ))

    patterns.append(SecretPattern(
        id="turso_auth_token",
        name="Turso Auth Token",
        description="Turso/LibSQL database auth token",
        category=SecretCategory.DATABASE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
        context_keywords=["turso", "libsql"],
    ))

    patterns.append(SecretPattern(
        id="fauna_key",
        name="Fauna Secret Key",
        description="Fauna database secret key",
        category=SecretCategory.DATABASE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"fnAE[A-Za-z0-9_-]{36,}"),
    ))

    patterns.append(SecretPattern(
        id="upstash_redis_token",
        name="Upstash Redis REST Token",
        description="Upstash Redis REST API token",
        category=SecretCategory.DATABASE,
        severity=Severity.HIGH,
        regex=re.compile(r"AX[A-Za-z0-9]{44,}"),
        context_keywords=["upstash", "redis"],
    ))

    # --- Version Control (additional) ---

    patterns.append(SecretPattern(
        id="gitlab_oauth_app_secret",
        name="GitLab OAuth App Secret",
        description="GitLab OAuth application secret",
        category=SecretCategory.VERSION_CONTROL,
        severity=Severity.CRITICAL,
        regex=re.compile(r"gloas-[A-Za-z0-9_-]{64}"),
    ))

    patterns.append(SecretPattern(
        id="github_server_to_server",
        name="GitHub App Server-to-Server Token",
        description="GitHub App installation access token",
        category=SecretCategory.VERSION_CONTROL,
        severity=Severity.CRITICAL,
        regex=re.compile(r"ghs_[A-Za-z0-9]{30,40}"),
    ))

    # --- Infrastructure (additional) ---

    patterns.append(SecretPattern(
        id="aws_cognito_pool",
        name="AWS Cognito User Pool",
        description="AWS Cognito user pool ID (may reveal account/region)",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.MEDIUM,
        regex=re.compile(r"[a-z]{2}-[a-z]+-\d_[A-Za-z0-9]{9}"),
        context_keywords=["cognito", "user_pool"],
    ))

    patterns.append(SecretPattern(
        id="gcp_client_id",
        name="GCP OAuth Client ID",
        description="Google Cloud OAuth client ID",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.MEDIUM,
        regex=re.compile(r"[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com"),
    ))

    patterns.append(SecretPattern(
        id="algolia_api_key",
        name="Algolia API Key",
        description="Algolia search API key",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(ALGOLIA_API_KEY|algolia_key)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?"""),
        context_keywords=["algolia"],
    ))

    patterns.append(SecretPattern(
        id="contentful_delivery_token",
        name="Contentful Delivery Token",
        description="Contentful CMS delivery API token",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(CONTENTFUL_ACCESS_TOKEN|contentful_delivery)\s*[=:]\s*['"]?([A-Za-z0-9_-]{43})['"]?"""),
        context_keywords=["contentful"],
    ))

    patterns.append(SecretPattern(
        id="mapbox_access_token",
        name="Mapbox Access Token",
        description="Mapbox maps API access token",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"pk\.[a-zA-Z0-9]{60}\.[a-zA-Z0-9_-]{22}"),
    ))

    patterns.append(SecretPattern(
        id="twitch_client_secret",
        name="Twitch Client Secret",
        description="Twitch API client secret",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.CRITICAL,
        regex=re.compile(r"""(?i)(TWITCH_CLIENT_SECRET)\s*[=:]\s*['"]?([a-z0-9]{30})['"]?"""),
        context_keywords=["twitch"],
    ))

    patterns.append(SecretPattern(
        id="okta_api_token",
        name="Okta API Token",
        description="Okta identity platform API token",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"00[A-Za-z0-9_-]{40}"),
        context_keywords=["okta", "OKTA_API_TOKEN"],
        entropy_threshold=4.5,
    ))

    patterns.append(SecretPattern(
        id="auth0_management_token",
        name="Auth0 Management Token",
        description="Auth0 management API token",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"""(?i)(AUTH0_MANAGEMENT_TOKEN|auth0_token)\s*[=:]\s*['"]?(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)['"]?"""),
        context_keywords=["auth0"],
    ))

    patterns.append(SecretPattern(
        id="clerk_secret_key",
        name="Clerk Secret Key",
        description="Clerk authentication secret key",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"sk_live_[A-Za-z0-9]{27,}"),
        context_keywords=["clerk"],
    ))

    patterns.append(SecretPattern(
        id="supabase_service_role",
        name="Supabase Service Role Key",
        description="Supabase service role key (full DB access)",
        category=SecretCategory.DATABASE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"""(?i)(SUPABASE_SERVICE_ROLE_KEY)\s*[=:]\s*['"]?(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)['"]?"""),
        context_keywords=["supabase", "service_role"],
    ))

    patterns.append(SecretPattern(
        id="convex_deploy_key",
        name="Convex Deploy Key",
        description="Convex backend platform deploy key",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"prod:[a-z0-9-]+\|[a-f0-9]{64}"),
        context_keywords=["convex"],
    ))

    patterns.append(SecretPattern(
        id="upstash_kafka_password",
        name="Upstash Kafka Password",
        description="Upstash Kafka REST API password",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(UPSTASH_KAFKA_REST_PASSWORD)\s*[=:]\s*['"]?([A-Za-z0-9_=-]{40,})['"]?"""),
        context_keywords=["upstash", "kafka"],
        entropy_threshold=4.0,
    ))

    patterns.append(SecretPattern(
        id="confluent_api_key",
        name="Confluent Cloud API Key",
        description="Confluent Cloud (Kafka) API key",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(CONFLUENT_API_KEY|confluent_key)\s*[=:]\s*['"]?([A-Z0-9]{16})['"]?"""),
        context_keywords=["confluent", "kafka"],
    ))

    patterns.append(SecretPattern(
        id="launchdarkly_sdk_key",
        name="LaunchDarkly SDK Key",
        description="LaunchDarkly feature flag SDK key",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"sdk-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"),
        context_keywords=["launchdarkly"],
    ))

    patterns.append(SecretPattern(
        id="launchdarkly_api_key",
        name="LaunchDarkly API Key",
        description="LaunchDarkly REST API access token",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"api-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"),
        context_keywords=["launchdarkly"],
    ))

    patterns.append(SecretPattern(
        id="airtable_api_key",
        name="Airtable API Key",
        description="Airtable personal access token",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"pat[A-Za-z0-9]{14}\.[a-f0-9]{64}"),
    ))

    patterns.append(SecretPattern(
        id="asana_pat",
        name="Asana Personal Access Token",
        description="Asana project management PAT",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"[0-9]/[0-9]{16}:[A-Za-z0-9]{32}"),
    ))

    patterns.append(SecretPattern(
        id="atlassian_api_token",
        name="Atlassian API Token",
        description="Atlassian (Jira/Confluence) API token",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(ATLASSIAN_API_TOKEN|jira_token)\s*[=:]\s*['"]?([A-Za-z0-9]{24})['"]?"""),
        context_keywords=["atlassian", "jira", "confluence"],
    ))

    patterns.append(SecretPattern(
        id="figma_pat",
        name="Figma Personal Access Token",
        description="Figma design platform PAT",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"figd_[A-Za-z0-9_-]{40,}"),
    ))

    patterns.append(SecretPattern(
        id="hubspot_api_key",
        name="HubSpot API Key",
        description="HubSpot CRM private app token",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"pat-na1-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"),
    ))

    patterns.append(SecretPattern(
        id="intercom_access_token",
        name="Intercom Access Token",
        description="Intercom messaging API token",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(INTERCOM_ACCESS_TOKEN)\s*[=:]\s*['"]?([a-zA-Z0-9=_-]{60})['"]?"""),
        context_keywords=["intercom"],
        entropy_threshold=4.0,
    ))

    patterns.append(SecretPattern(
        id="zendesk_api_token",
        name="Zendesk API Token",
        description="Zendesk support API token",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(ZENDESK_API_TOKEN)\s*[=:]\s*['"]?([A-Za-z0-9]{40})['"]?"""),
        context_keywords=["zendesk"],
    ))

    patterns.append(SecretPattern(
        id="freshdesk_api_key",
        name="Freshdesk API Key",
        description="Freshdesk support API key",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(FRESHDESK_API_KEY)\s*[=:]\s*['"]?([A-Za-z0-9]{20})['"]?"""),
        context_keywords=["freshdesk"],
    ))

    patterns.append(SecretPattern(
        id="segment_write_key",
        name="Segment Write Key",
        description="Segment analytics write key",
        category=SecretCategory.MONITORING,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(SEGMENT_WRITE_KEY)\s*[=:]\s*['"]?([A-Za-z0-9]{32})['"]?"""),
        context_keywords=["segment"],
    ))

    patterns.append(SecretPattern(
        id="mixpanel_token",
        name="Mixpanel Token",
        description="Mixpanel project token",
        category=SecretCategory.MONITORING,
        severity=Severity.MEDIUM,
        regex=re.compile(r"""(?i)(MIXPANEL_TOKEN)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?"""),
        context_keywords=["mixpanel"],
    ))

    patterns.append(SecretPattern(
        id="amplitude_api_key",
        name="Amplitude API Key",
        description="Amplitude analytics API key",
        category=SecretCategory.MONITORING,
        severity=Severity.MEDIUM,
        regex=re.compile(r"""(?i)(AMPLITUDE_API_KEY)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?"""),
        context_keywords=["amplitude"],
    ))

    patterns.append(SecretPattern(
        id="loggly_token",
        name="Loggly Token",
        description="Loggly customer token",
        category=SecretCategory.MONITORING,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(LOGGLY_TOKEN)\s*[=:]\s*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?"""),
        context_keywords=["loggly"],
    ))

    patterns.append(SecretPattern(
        id="logdna_key",
        name="LogDNA/Mezmo Ingestion Key",
        description="LogDNA (Mezmo) log ingestion key",
        category=SecretCategory.MONITORING,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(LOGDNA_INGESTION_KEY|MEZMO_KEY)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?"""),
        context_keywords=["logdna", "mezmo"],
    ))

    # --- Cryptographic (additional) ---

    patterns.append(SecretPattern(
        id="dsa_private_key",
        name="DSA Private Key",
        description="DSA private key in PEM format",
        category=SecretCategory.CRYPTOGRAPHIC,
        severity=Severity.CRITICAL,
        regex=re.compile(r"-----BEGIN DSA PRIVATE KEY-----"),
    ))

    # NOTE: X.509 certificates (-----BEGIN CERTIFICATE-----) are intentionally
    # NOT detected — certificates are public by design.  Only private keys are
    # secrets.  Removed to eliminate false positives.

    patterns.append(SecretPattern(
        id="pkcs12_file",
        name="PKCS#12 Key Indicator",
        description="Reference to PKCS#12/PFX keystore with password",
        category=SecretCategory.CRYPTOGRAPHIC,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(pkcs12|\.pfx|\.p12)\s*[=:]\s*['"]?([^\s'"]+)['"]?"""),
        context_keywords=["password", "secret", "key"],
    ))

    # --- Generic (additional) ---

    patterns.append(SecretPattern(
        id="bearer_token",
        name="Bearer Token",
        description="HTTP Authorization bearer token",
        category=SecretCategory.GENERIC,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)Authorization['":\s]+Bearer\s+([A-Za-z0-9_\-.~+/]+=*)"""),
        entropy_threshold=4.0,
    ))

    patterns.append(SecretPattern(
        id="base64_encoded_secret",
        name="Base64-Encoded Secret",
        description="Base64-encoded value in a secret context",
        category=SecretCategory.GENERIC,
        severity=Severity.MEDIUM,
        regex=re.compile(r"""(?i)(secret|password|token|key)_?b(?:ase)?64\s*[=:]\s*['"]?([A-Za-z0-9+/]{40,}={0,2})['"]?"""),
        entropy_threshold=4.0,
    ))

    patterns.append(SecretPattern(
        id="env_file_password",
        name="Password in Env File",
        description="Password assignment in environment/config file",
        category=SecretCategory.GENERIC,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD|REDIS_PASSWORD|MONGO_PASSWORD|ADMIN_PASSWORD|ROOT_PASSWORD)\s*[=:]\s*['"]?([^\s'"]{8,})['"]?"""),
        entropy_threshold=3.0,
    ))

    patterns.append(SecretPattern(
        id="connection_string_generic",
        name="Generic Connection String",
        description="Generic database/service connection string with credentials",
        category=SecretCategory.DATABASE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"(?:amqp|amqps|mssql|couchbase)://[^:]+:[^@]+@[^\s]+"),
    ))

    patterns.append(SecretPattern(
        id="private_key_hex",
        name="Private Key (Hex)",
        description="Private key in hex format (e.g. Ethereum wallet)",
        category=SecretCategory.CRYPTOGRAPHIC,
        severity=Severity.CRITICAL,
        regex=re.compile(r"""(?i)(private[_\s]?key|priv[_\s]?key)\s*[=:]\s*['"]?(0x)?([a-fA-F0-9]{64})['"]?"""),
        entropy_threshold=4.0,
    ))

    patterns.append(SecretPattern(
        id="ethereum_private_key",
        name="Ethereum Private Key",
        description="Ethereum/EVM wallet private key",
        category=SecretCategory.CRYPTOGRAPHIC,
        severity=Severity.CRITICAL,
        regex=re.compile(r"0x[a-fA-F0-9]{64}"),
        context_keywords=["wallet", "ethereum", "private", "key", "web3"],
        entropy_threshold=4.0,
    ))

    # NOTE: Private/Internal IP Address pattern removed — RFC 1918 IPs are
    # ubiquitous in dev conversations (Docker, k8s, local networking) and
    # produced 1000+ false positives per scan. They are not credentials.
    # If needed, re-add with much stricter context (e.g. only in .env files).

    patterns.append(SecretPattern(
        id="slack_config_token",
        name="Slack Configuration Token",
        description="Slack legacy configuration/refresh token",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.HIGH,
        regex=re.compile(r"xoxe\.xoxp-[0-9]-[A-Za-z0-9]{163}"),
    ))

    patterns.append(SecretPattern(
        id="slack_legacy_token",
        name="Slack Legacy Token",
        description="Slack legacy API token",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.CRITICAL,
        regex=re.compile(r"xoxs-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}"),
    ))

    patterns.append(SecretPattern(
        id="openai_admin_key",
        name="OpenAI Admin Key",
        description="OpenAI admin-level API key",
        category=SecretCategory.AI_SERVICE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"sk-admin-[A-Za-z0-9_-]{20,}"),
    ))

    patterns.append(SecretPattern(
        id="openai_sess_key",
        name="OpenAI Session Key",
        description="OpenAI session-scoped key",
        category=SecretCategory.AI_SERVICE,
        severity=Severity.HIGH,
        regex=re.compile(r"sess-[A-Za-z0-9]{40,}"),
        context_keywords=["openai"],
    ))

    patterns.append(SecretPattern(
        id="anthropic_session_key",
        name="Anthropic Session Key",
        description="Anthropic console session key",
        category=SecretCategory.AI_SERVICE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"sk-ant-sid01-[A-Za-z0-9_-]{86}-[A-Za-z0-9_-]{6}-AA"),
    ))

    patterns.append(SecretPattern(
        id="google_cloud_run_key",
        name="Google Cloud Run Invoker Key",
        description="Google Cloud Run service invoker key",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(CLOUD_RUN_KEY|cloud_run_invoker)\s*[=:]\s*['"]?([A-Za-z0-9_-]{40,})['"]?"""),
        context_keywords=["cloud_run", "gcp"],
        entropy_threshold=4.0,
    ))

    patterns.append(SecretPattern(
        id="vercel_access_token",
        name="Vercel Access Token (Bearer)",
        description="Vercel bearer access token with known prefix",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"""(?i)vercel[_\s]*(access[_\s]*)?token\s*[=:]\s*['"]?([A-Za-z0-9]{24,})['"]?"""),
    ))

    patterns.append(SecretPattern(
        id="cloudflare_global_api_key",
        name="Cloudflare Global API Key",
        description="Cloudflare account global API key",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"""(?i)(CLOUDFLARE_API_KEY|CF_API_KEY)\s*[=:]\s*['"]?([a-f0-9]{37})['"]?"""),
        context_keywords=["cloudflare"],
    ))

    patterns.append(SecretPattern(
        id="cloudflare_origin_ca_key",
        name="Cloudflare Origin CA Key",
        description="Cloudflare Origin CA certificate API key",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"v1\.0-[a-f0-9]{24}-[a-f0-9]{146}"),
    ))

    patterns.append(SecretPattern(
        id="fastly_api_token",
        name="Fastly API Token",
        description="Fastly CDN API token",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(FASTLY_API_TOKEN)\s*[=:]\s*['"]?([A-Za-z0-9_-]{32})['"]?"""),
        context_keywords=["fastly"],
    ))

    patterns.append(SecretPattern(
        id="mux_token_secret",
        name="Mux Token Secret",
        description="Mux video platform token secret",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(MUX_TOKEN_SECRET)\s*[=:]\s*['"]?([A-Za-z0-9/+]{64,}={0,2})['"]?"""),
        context_keywords=["mux"],
    ))

    patterns.append(SecretPattern(
        id="uploadthing_secret",
        name="UploadThing Secret",
        description="UploadThing file upload API secret",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"sk_live_[A-Za-z0-9]{32,}"),
        context_keywords=["uploadthing", "UPLOADTHING_SECRET"],
    ))

    patterns.append(SecretPattern(
        id="resend_api_key",
        name="Resend API Key",
        description="Resend email API key",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.HIGH,
        regex=re.compile(r"re_[A-Za-z0-9]{32,}"),
        context_keywords=["resend", "RESEND_API_KEY"],
    ))

    patterns.append(SecretPattern(
        id="novu_api_key",
        name="Novu API Key",
        description="Novu notification API key",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(NOVU_API_KEY)\s*[=:]\s*['"]?([A-Za-z0-9]{32,})['"]?"""),
        context_keywords=["novu"],
        entropy_threshold=4.0,
    ))

    patterns.append(SecretPattern(
        id="expo_access_token",
        name="Expo Access Token",
        description="Expo (React Native) access token",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(EXPO_ACCESS_TOKEN)\s*[=:]\s*['"]?([A-Za-z0-9_-]{40,})['"]?"""),
        context_keywords=["expo"],
        entropy_threshold=4.0,
    ))

    patterns.append(SecretPattern(
        id="livekit_api_secret",
        name="LiveKit API Secret",
        description="LiveKit WebRTC platform API secret",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(LIVEKIT_API_SECRET)\s*[=:]\s*['"]?([A-Za-z0-9]{32,})['"]?"""),
        context_keywords=["livekit"],
        entropy_threshold=4.0,
    ))

    patterns.append(SecretPattern(
        id="ably_api_key",
        name="Ably API Key",
        description="Ably realtime messaging API key",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.HIGH,
        regex=re.compile(r"[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}:[A-Za-z0-9_-]{20,}"),
        context_keywords=["ably", "ABLY_API_KEY"],
    ))

    patterns.append(SecretPattern(
        id="pusher_secret",
        name="Pusher Secret",
        description="Pusher channels API secret",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(PUSHER_SECRET|pusher_app_secret)\s*[=:]\s*['"]?([a-f0-9]{20})['"]?"""),
        context_keywords=["pusher"],
    ))

    # =========================================================================
    # Additional patterns ported from Gitleaks (MIT license)
    # =========================================================================

    # --- Prefix-based patterns (low false-positive risk) ---

    patterns.append(SecretPattern(
        id="databricks_api_token",
        name="Databricks API Token",
        description="Databricks personal access token (dapi prefix)",
        category=SecretCategory.AI_SERVICE,
        severity=Severity.HIGH,
        regex=re.compile(r"\b(dapi[a-f0-9]{32}(?:-\d)?)\b"),
    ))

    patterns.append(SecretPattern(
        id="dynatrace_api_token",
        name="Dynatrace API Token",
        description="Dynatrace monitoring API token (dt0c01 prefix)",
        category=SecretCategory.MONITORING,
        severity=Severity.HIGH,
        regex=re.compile(r"dt0c01\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{64}"),
    ))

    patterns.append(SecretPattern(
        id="easypost_api_token",
        name="EasyPost API Token",
        description="EasyPost shipping API token (EZAK prefix)",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"\bEZAK[a-zA-Z0-9]{54}\b"),
    ))

    patterns.append(SecretPattern(
        id="easypost_test_api_token",
        name="EasyPost Test API Token",
        description="EasyPost test API token (EZTK prefix)",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.LOW,
        regex=re.compile(r"\bEZTK[a-zA-Z0-9]{54}\b"),
    ))

    patterns.append(SecretPattern(
        id="duffel_api_token",
        name="Duffel API Token",
        description="Duffel travel API token",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"duffel_(?:test|live)_[a-zA-Z0-9_\-=]{43}"),
    ))

    patterns.append(SecretPattern(
        id="frameio_api_token",
        name="Frame.io API Token",
        description="Frame.io video API token (fio-u- prefix)",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"fio-u-[a-zA-Z0-9\-_=]{64}"),
    ))

    patterns.append(SecretPattern(
        id="grafana_cloud_api_token",
        name="Grafana Cloud API Token",
        description="Grafana Cloud API token (glc_ prefix)",
        category=SecretCategory.MONITORING,
        severity=Severity.HIGH,
        regex=re.compile(r"\b(glc_[A-Za-z0-9+/]{32,400}={0,3})\b"),
    ))

    patterns.append(SecretPattern(
        id="grafana_service_account_token",
        name="Grafana Service Account Token",
        description="Grafana service account token (glsa_ prefix)",
        category=SecretCategory.MONITORING,
        severity=Severity.HIGH,
        regex=re.compile(r"\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})\b"),
    ))

    patterns.append(SecretPattern(
        id="hashicorp_tf_api_token",
        name="HashiCorp Terraform API Token",
        description="HashiCorp Terraform Cloud/Enterprise API token (atlasv1)",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9\-_=]{60,70}"),
    ))

    patterns.append(SecretPattern(
        id="harness_api_key",
        name="Harness API Key",
        description="Harness CI/CD platform API key",
        category=SecretCategory.CI_CD,
        severity=Severity.HIGH,
        regex=re.compile(r"(?:pat|sat)\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{20}"),
    ))

    patterns.append(SecretPattern(
        id="infracost_api_token",
        name="Infracost API Token",
        description="Infracost cloud cost estimation API token (ico- prefix)",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.MEDIUM,
        regex=re.compile(r"\b(ico-[a-zA-Z0-9]{32})\b"),
    ))

    patterns.append(SecretPattern(
        id="maxmind_license_key",
        name="MaxMind License Key",
        description="MaxMind GeoIP license key (_mmk suffix)",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.MEDIUM,
        regex=re.compile(r"\b([A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk)\b"),
    ))

    patterns.append(SecretPattern(
        id="postman_api_token",
        name="Postman API Token",
        description="Postman API token (PMAK- prefix)",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"\b(PMAK-[a-f0-9]{24}-[a-f0-9]{34})\b"),
    ))

    patterns.append(SecretPattern(
        id="prefect_api_token",
        name="Prefect API Token",
        description="Prefect workflow orchestration API token (pnu_ prefix)",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"\b(pnu_[a-zA-Z0-9]{36})\b"),
    ))

    patterns.append(SecretPattern(
        id="readme_api_token",
        name="ReadMe API Token",
        description="ReadMe documentation API token (rdme_ prefix)",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.MEDIUM,
        regex=re.compile(r"\b(rdme_[a-z0-9]{70})\b"),
    ))

    patterns.append(SecretPattern(
        id="rubygems_api_token",
        name="RubyGems API Token",
        description="RubyGems package registry API token",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"\b(rubygems_[a-f0-9]{48})\b"),
    ))

    patterns.append(SecretPattern(
        id="scalingo_api_token",
        name="Scalingo API Token",
        description="Scalingo PaaS API token (tk-us- prefix)",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"\b(tk-us-[a-zA-Z0-9_-]{48})\b"),
    ))

    patterns.append(SecretPattern(
        id="sendinblue_api_token",
        name="Brevo (Sendinblue) API Token",
        description="Brevo/Sendinblue email API token (xkeysib- prefix)",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.HIGH,
        regex=re.compile(r"\b(xkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16})\b"),
    ))

    patterns.append(SecretPattern(
        id="shippo_api_token",
        name="Shippo API Token",
        description="Shippo shipping API token (shippo_live/test_ prefix)",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"\b(shippo_(?:live|test)_[a-fA-F0-9]{40})\b"),
    ))

    patterns.append(SecretPattern(
        id="typeform_api_token",
        name="Typeform API Token",
        description="Typeform survey/form API token (tfp_ prefix)",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.MEDIUM,
        regex=re.compile(r"\b(tfp_[a-z0-9\-_.=]{59})\b"),
    ))

    patterns.append(SecretPattern(
        id="vault_service_token",
        name="HashiCorp Vault Service Token",
        description="HashiCorp Vault service token (hvs. or s. prefix)",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"\b(hvs\.[a-zA-Z0-9_-]{90,120}|s\.[a-zA-Z0-9]{24})\b"),
    ))

    patterns.append(SecretPattern(
        id="anthropic_admin_api_key",
        name="Anthropic Admin API Key",
        description="Anthropic admin API key (sk-ant-admin01 prefix)",
        category=SecretCategory.AI_SERVICE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"\b(sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA)\b"),
    ))

    patterns.append(SecretPattern(
        id="artifactory_api_key",
        name="JFrog Artifactory API Key",
        description="JFrog Artifactory API key (AKCp prefix)",
        category=SecretCategory.CI_CD,
        severity=Severity.HIGH,
        regex=re.compile(r"\bAKCp[A-Za-z0-9]{69}\b"),
    ))

    patterns.append(SecretPattern(
        id="artifactory_reference_token",
        name="JFrog Artifactory Reference Token",
        description="JFrog Artifactory reference token (cmVmd prefix)",
        category=SecretCategory.CI_CD,
        severity=Severity.HIGH,
        regex=re.compile(r"\bcmVmd[A-Za-z0-9]{59}\b"),
    ))

    patterns.append(SecretPattern(
        id="clojars_api_token",
        name="Clojars API Token",
        description="Clojars package registry API token (CLOJARS_ prefix)",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"(?i)CLOJARS_[a-z0-9]{60}"),
    ))

    patterns.append(SecretPattern(
        id="clickhouse_api_secret",
        name="ClickHouse Cloud API Secret",
        description="ClickHouse Cloud API secret key (4b1d prefix)",
        category=SecretCategory.DATABASE,
        severity=Severity.HIGH,
        regex=re.compile(r"\b(4b1d[A-Za-z0-9]{38})\b"),
    ))

    patterns.append(SecretPattern(
        id="facebook_page_access_token",
        name="Facebook Page Access Token",
        description="Facebook/Meta page access token (EAA prefix)",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.HIGH,
        regex=re.compile(r"\b(EAA[MC][a-zA-Z0-9]{100,})\b"),
    ))

    patterns.append(SecretPattern(
        id="adobe_client_secret",
        name="Adobe Client Secret",
        description="Adobe API client secret (p8e- prefix)",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"\b(p8e-[a-zA-Z0-9]{32})\b"),
    ))

    patterns.append(SecretPattern(
        id="flutterwave_secret_key",
        name="Flutterwave Secret Key",
        description="Flutterwave payment secret key",
        category=SecretCategory.PAYMENT,
        severity=Severity.CRITICAL,
        regex=re.compile(r"FLWSECK_TEST-[a-hA-H0-9]{32}-X"),
    ))

    patterns.append(SecretPattern(
        id="flutterwave_public_key",
        name="Flutterwave Public Key",
        description="Flutterwave payment public key",
        category=SecretCategory.PAYMENT,
        severity=Severity.MEDIUM,
        regex=re.compile(r"FLWPUBK_TEST-[a-hA-H0-9]{32}-X"),
    ))

    patterns.append(SecretPattern(
        id="flutterwave_encryption_key",
        name="Flutterwave Encryption Key",
        description="Flutterwave payment encryption key",
        category=SecretCategory.PAYMENT,
        severity=Severity.CRITICAL,
        regex=re.compile(r"FLWSECK_TEST-[a-hA-H0-9]{12}"),
    ))

    patterns.append(SecretPattern(
        id="octopus_deploy_api_key",
        name="Octopus Deploy API Key",
        description="Octopus Deploy CI/CD API key (API- prefix)",
        category=SecretCategory.CI_CD,
        severity=Severity.HIGH,
        regex=re.compile(r"\b(API-[A-Z0-9]{26})\b"),
    ))

    patterns.append(SecretPattern(
        id="openshift_user_token",
        name="OpenShift User Token",
        description="OpenShift user token (sha256~ prefix)",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"\b(sha256~[a-zA-Z0-9_-]{43})\b"),
    ))

    patterns.append(SecretPattern(
        id="plaid_access_token",
        name="Plaid Access Token",
        description="Plaid financial API access token",
        category=SecretCategory.PAYMENT,
        severity=Severity.CRITICAL,
        regex=re.compile(r"access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    ))

    patterns.append(SecretPattern(
        id="planetscale_api_token",
        name="PlanetScale API Token",
        description="PlanetScale database API token (pscale_tkn_ prefix)",
        category=SecretCategory.DATABASE,
        severity=Severity.HIGH,
        regex=re.compile(r"\b(pscale_tkn_[a-zA-Z0-9=._-]{32,64})\b"),
    ))

    patterns.append(SecretPattern(
        id="planetscale_oauth_token",
        name="PlanetScale OAuth Token",
        description="PlanetScale OAuth token (pscale_oauth_ prefix)",
        category=SecretCategory.DATABASE,
        severity=Severity.HIGH,
        regex=re.compile(r"\b(pscale_oauth_[a-zA-Z0-9=._-]{32,64})\b"),
    ))

    patterns.append(SecretPattern(
        id="sentry_org_token",
        name="Sentry Organization Token",
        description="Sentry organization auth token (sntrys_eyJ prefix)",
        category=SecretCategory.MONITORING,
        severity=Severity.HIGH,
        regex=re.compile(r"\bsntrys_eyJpYXQiO[a-zA-Z0-9+/]{10,400}={0,2}_[a-zA-Z0-9+/]{43}\b"),
    ))

    patterns.append(SecretPattern(
        id="sentry_user_token",
        name="Sentry User Token",
        description="Sentry user auth token (sntryu_ prefix)",
        category=SecretCategory.MONITORING,
        severity=Severity.HIGH,
        regex=re.compile(r"\b(sntryu_[a-f0-9]{64})\b"),
    ))

    patterns.append(SecretPattern(
        id="sourcegraph_access_token",
        name="Sourcegraph Access Token",
        description="Sourcegraph code search access token (sgp_ prefix)",
        category=SecretCategory.VERSION_CONTROL,
        severity=Severity.HIGH,
        regex=re.compile(r"\b(sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40})\b"),
    ))

    patterns.append(SecretPattern(
        id="yandex_api_key",
        name="Yandex API Key",
        description="Yandex Cloud API key (AQVN prefix)",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.HIGH,
        regex=re.compile(r"\b(AQVN[A-Za-z0-9_-]{35,38})\b"),
    ))

    patterns.append(SecretPattern(
        id="yandex_aws_access_token",
        name="Yandex AWS-Compatible Access Token",
        description="Yandex Cloud AWS-compatible access token (YC prefix)",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.HIGH,
        regex=re.compile(r"(?i)(?:yandex)[\s=:]+['\"]*\b(YC[a-zA-Z0-9_-]{38})\b"),
    ))

    patterns.append(SecretPattern(
        id="slack_legacy_workspace_token",
        name="Slack Legacy Workspace Token",
        description="Slack legacy workspace token (xoxa-/xoxr- prefix)",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.HIGH,
        regex=re.compile(r"xox[ar]-(?:\d-)?[0-9a-zA-Z]{8,48}"),
    ))

    # =========================================================================
    # Batch 2: Gitleaks patterns (MIT license) — prefix-based, low FP risk
    # =========================================================================

    patterns.append(SecretPattern(
        id="onepassword_secret_key",
        name="1Password Secret Key",
        description="1Password account secret key (A3- prefix)",
        category=SecretCategory.CRYPTOGRAPHIC,
        severity=Severity.CRITICAL,
        regex=re.compile(r"\bA3-[A-Z0-9]{6}-(?:[A-Z0-9]{11}|[A-Z0-9]{6}-[A-Z0-9]{5})-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b"),
    ))

    patterns.append(SecretPattern(
        id="onepassword_service_account_token",
        name="1Password Service Account Token",
        description="1Password service account token (ops_eyJ prefix)",
        category=SecretCategory.CRYPTOGRAPHIC,
        severity=Severity.CRITICAL,
        regex=re.compile(r"ops_eyJ[a-zA-Z0-9+/]{250,}={0,3}"),
    ))

    patterns.append(SecretPattern(
        id="aws_bedrock_api_key",
        name="AWS Bedrock API Key",
        description="AWS Amazon Bedrock long-lived API key (ABSK prefix)",
        category=SecretCategory.AI_SERVICE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"\bABSK[A-Za-z0-9+/]{109,269}={0,2}\b"),
    ))

    patterns.append(SecretPattern(
        id="authress_service_client_key",
        name="Authress Service Client Access Key",
        description="Authress service client access key (sc_/ext_/scauth_ prefix)",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"\b(?:sc|ext|scauth|authress)_[a-zA-Z0-9]{5,30}\.[a-zA-Z0-9]{4,6}\.acc[_-][a-zA-Z0-9-]{10,32}\.[a-zA-Z0-9+/_=-]{30,120}\b"),
    ))

    patterns.append(SecretPattern(
        id="beamer_api_token",
        name="Beamer API Token",
        description="Beamer in-app notification API token (b_ prefix)",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.MEDIUM,
        regex=re.compile(r"""(?i)(?:beamer)[\w.\s-]{0,20}[=:]\s*['"]?(b_[a-z0-9=_\-]{44})['"]?"""),
        context_keywords=["beamer"],
    ))

    patterns.append(SecretPattern(
        id="defined_networking_api_token",
        name="Defined Networking API Token",
        description="Defined Networking API token (dnkey- prefix)",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"\b(dnkey-[a-z0-9=_\-]{26}-[a-z0-9=_\-]{52})\b"),
    ))

    patterns.append(SecretPattern(
        id="gitlab_cicd_job_token",
        name="GitLab CI/CD Job Token",
        description="GitLab CI/CD job token (glcbt- prefix)",
        category=SecretCategory.CI_CD,
        severity=Severity.HIGH,
        regex=re.compile(r"glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}"),
    ))

    patterns.append(SecretPattern(
        id="gitlab_deploy_token",
        name="GitLab Deploy Token",
        description="GitLab deploy token (gldt- prefix)",
        category=SecretCategory.CI_CD,
        severity=Severity.HIGH,
        regex=re.compile(r"gldt-[0-9a-zA-Z_\-]{20}"),
    ))

    patterns.append(SecretPattern(
        id="gitlab_feature_flag_token",
        name="GitLab Feature Flag Client Token",
        description="GitLab feature flag client token (glffct- prefix)",
        category=SecretCategory.CI_CD,
        severity=Severity.MEDIUM,
        regex=re.compile(r"glffct-[0-9a-zA-Z_\-]{20}"),
    ))

    patterns.append(SecretPattern(
        id="gitlab_feed_token",
        name="GitLab Feed Token",
        description="GitLab feed token (glft- prefix)",
        category=SecretCategory.VERSION_CONTROL,
        severity=Severity.MEDIUM,
        regex=re.compile(r"glft-[0-9a-zA-Z_\-]{20}"),
    ))

    patterns.append(SecretPattern(
        id="gitlab_incoming_mail_token",
        name="GitLab Incoming Mail Token",
        description="GitLab incoming mail token (glimt- prefix)",
        category=SecretCategory.VERSION_CONTROL,
        severity=Severity.MEDIUM,
        regex=re.compile(r"glimt-[0-9a-zA-Z_\-]{25}"),
    ))

    patterns.append(SecretPattern(
        id="gitlab_kubernetes_agent_token",
        name="GitLab Kubernetes Agent Token",
        description="GitLab Kubernetes agent token (glagent- prefix)",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"glagent-[0-9a-zA-Z_\-]{50}"),
    ))

    patterns.append(SecretPattern(
        id="gitlab_runner_registration_token",
        name="GitLab Runner Registration Token",
        description="GitLab runner registration token (GR1348941 prefix)",
        category=SecretCategory.CI_CD,
        severity=Severity.HIGH,
        regex=re.compile(r"GR1348941[\w-]{20}"),
    ))

    patterns.append(SecretPattern(
        id="gitlab_runner_auth_token",
        name="GitLab Runner Authentication Token",
        description="GitLab runner authentication token (glrt- prefix)",
        category=SecretCategory.CI_CD,
        severity=Severity.HIGH,
        regex=re.compile(r"glrt-[0-9a-zA-Z_\-]{20}"),
    ))

    patterns.append(SecretPattern(
        id="gitlab_scim_token",
        name="GitLab SCIM Token",
        description="GitLab SCIM provisioning token (glsoat- prefix)",
        category=SecretCategory.VERSION_CONTROL,
        severity=Severity.HIGH,
        regex=re.compile(r"glsoat-[0-9a-zA-Z_\-]{20}"),
    ))

    patterns.append(SecretPattern(
        id="gitlab_session_cookie",
        name="GitLab Session Cookie",
        description="GitLab session cookie value (_gitlab_session=)",
        category=SecretCategory.VERSION_CONTROL,
        severity=Severity.HIGH,
        regex=re.compile(r"_gitlab_session=[0-9a-z]{32}"),
    ))

    patterns.append(SecretPattern(
        id="heroku_api_key_v2",
        name="Heroku API Key v2",
        description="Heroku API key v2 format (HRKU-AA prefix)",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.CRITICAL,
        regex=re.compile(r"\b(HRKU-AA[0-9a-zA-Z_-]{58})\b"),
    ))

    patterns.append(SecretPattern(
        id="huggingface_org_api_token",
        name="HuggingFace Organization API Token",
        description="HuggingFace organization API token (api_org_ prefix)",
        category=SecretCategory.AI_SERVICE,
        severity=Severity.HIGH,
        regex=re.compile(r"\b(api_org_[a-zA-Z]{34})\b"),
    ))

    patterns.append(SecretPattern(
        id="new_relic_browser_api_token",
        name="New Relic Browser API Token",
        description="New Relic browser API token (NRJS- prefix)",
        category=SecretCategory.MONITORING,
        severity=Severity.MEDIUM,
        regex=re.compile(r"\b(NRJS-[a-f0-9]{19})\b"),
    ))

    patterns.append(SecretPattern(
        id="new_relic_insert_key",
        name="New Relic Insert Key",
        description="New Relic insert/ingest key (NRII- prefix)",
        category=SecretCategory.MONITORING,
        severity=Severity.HIGH,
        regex=re.compile(r"\b(NRII-[a-z0-9-]{32})\b"),
    ))

    patterns.append(SecretPattern(
        id="new_relic_user_api_key",
        name="New Relic User API Key",
        description="New Relic user API key (NRAK- prefix)",
        category=SecretCategory.MONITORING,
        severity=Severity.HIGH,
        regex=re.compile(r"\b(NRAK-[a-z0-9]{27})\b"),
    ))

    patterns.append(SecretPattern(
        id="slack_config_refresh_token",
        name="Slack Configuration Refresh Token",
        description="Slack configuration refresh token (xoxe- prefix)",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.HIGH,
        regex=re.compile(r"xoxe-\d-[A-Z0-9]{146}"),
    ))

    patterns.append(SecretPattern(
        id="settlemint_app_access_token",
        name="SettleMint Application Access Token",
        description="SettleMint application access token (sm_aat_ prefix)",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"\b(sm_aat_[a-zA-Z0-9]{16})\b"),
    ))

    patterns.append(SecretPattern(
        id="settlemint_pat",
        name="SettleMint Personal Access Token",
        description="SettleMint personal access token (sm_pat_ prefix)",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"\b(sm_pat_[a-zA-Z0-9]{16})\b"),
    ))

    patterns.append(SecretPattern(
        id="settlemint_service_access_token",
        name="SettleMint Service Access Token",
        description="SettleMint service access token (sm_sat_ prefix)",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"\b(sm_sat_[a-zA-Z0-9]{16})\b"),
    ))

    patterns.append(SecretPattern(
        id="microsoft_teams_webhook",
        name="Microsoft Teams Webhook",
        description="Microsoft Teams incoming webhook URL",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.HIGH,
        regex=re.compile(r"https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}/IncomingWebhook/[a-z0-9]{32}/[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}"),
    ))

    patterns.append(SecretPattern(
        id="sumologic_access_id",
        name="SumoLogic Access ID",
        description="SumoLogic log management access ID (su prefix)",
        category=SecretCategory.MONITORING,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(?:sumo)[\w.\s-]{0,20}[=:]\s*['"]?(su[a-zA-Z0-9]{12})['"]?"""),
        context_keywords=["sumo"],
    ))

    patterns.append(SecretPattern(
        id="lob_api_key",
        name="Lob API Key",
        description="Lob mail API key (live_/test_ prefix + 35 hex chars)",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"\b((?:live|test)_[a-f0-9]{35})\b"),
        context_keywords=["lob"],
    ))

    patterns.append(SecretPattern(
        id="lob_pub_api_key",
        name="Lob Publishable API Key",
        description="Lob publishable API key (live_pub_/test_pub_ prefix)",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.MEDIUM,
        regex=re.compile(r"\b((?:test|live)_pub_[a-f0-9]{31})\b"),
        context_keywords=["lob"],
    ))

    patterns.append(SecretPattern(
        id="mailgun_pub_key",
        name="Mailgun Public Key",
        description="Mailgun public validation key (pubkey- prefix)",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.MEDIUM,
        regex=re.compile(r"\b(pubkey-[a-f0-9]{32})\b"),
        context_keywords=["mailgun"],
    ))

    patterns.append(SecretPattern(
        id="mailgun_signing_key",
        name="Mailgun Signing Key",
        description="Mailgun webhook signing key (hex-hex-hex format)",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(?:mailgun)[\w.\s-]{0,20}[=:]\s*['"]?([a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})['"]?"""),
        context_keywords=["mailgun"],
    ))

    # =========================================================================
    # Batch 2: Context-keyword patterns (crypto exchanges, SaaS, misc)
    # =========================================================================

    patterns.append(SecretPattern(
        id="adafruit_api_key",
        name="Adafruit IO API Key",
        description="Adafruit IO API key",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.MEDIUM,
        regex=re.compile(r"""(?i)(?:adafruit)[\w.\s-]{0,20}[=:]\s*['"]?([a-z0-9_-]{32})['"]?"""),
        context_keywords=["adafruit"],
    ))

    patterns.append(SecretPattern(
        id="bittrex_access_key",
        name="Bittrex Access Key",
        description="Bittrex cryptocurrency exchange access key",
        category=SecretCategory.PAYMENT,
        severity=Severity.CRITICAL,
        regex=re.compile(r"""(?i)(?:bittrex)[\w.\s-]{0,20}[=:]\s*['"]?([a-z0-9]{32})['"]?"""),
        context_keywords=["bittrex"],
        entropy_threshold=3.5,
    ))

    patterns.append(SecretPattern(
        id="cisco_meraki_api_key",
        name="Cisco Meraki API Key",
        description="Cisco Meraki dashboard API key",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(?:meraki)[\w.\s-]{0,20}[=:]\s*['"]?([0-9a-f]{40})['"]?"""),
        context_keywords=["meraki"],
        entropy_threshold=3.5,
    ))

    patterns.append(SecretPattern(
        id="coinbase_access_token",
        name="Coinbase Access Token",
        description="Coinbase cryptocurrency exchange access token",
        category=SecretCategory.PAYMENT,
        severity=Severity.CRITICAL,
        regex=re.compile(r"""(?i)(?:coinbase)[\w.\s-]{0,20}[=:]\s*['"]?([a-z0-9_-]{64})['"]?"""),
        context_keywords=["coinbase"],
        entropy_threshold=3.5,
    ))

    patterns.append(SecretPattern(
        id="dropbox_api_token",
        name="Dropbox API Token",
        description="Dropbox short-lived API token (sl. prefix)",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"\b(sl\.[a-z0-9\-=_]{135,})\b"),
        context_keywords=["dropbox"],
    ))

    patterns.append(SecretPattern(
        id="facebook_secret",
        name="Facebook App Secret",
        description="Facebook/Meta application secret",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(?:facebook|fb)[\w.\s-]{0,20}(?:secret|app_secret)[\w.\s-]{0,10}[=:]\s*['"]?([a-f0-9]{32})['"]?"""),
        context_keywords=["facebook", "fb_secret"],
        entropy_threshold=3.5,
    ))

    patterns.append(SecretPattern(
        id="finnhub_access_token",
        name="Finnhub Access Token",
        description="Finnhub financial data API token",
        category=SecretCategory.PAYMENT,
        severity=Severity.MEDIUM,
        regex=re.compile(r"""(?i)(?:finnhub)[\w.\s-]{0,20}[=:]\s*['"]?([a-z0-9]{20})['"]?"""),
        context_keywords=["finnhub"],
    ))

    patterns.append(SecretPattern(
        id="freshbooks_access_token",
        name="FreshBooks Access Token",
        description="FreshBooks accounting API token",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(?:freshbooks)[\w.\s-]{0,20}[=:]\s*['"]?([a-z0-9]{64})['"]?"""),
        context_keywords=["freshbooks"],
        entropy_threshold=3.5,
    ))

    patterns.append(SecretPattern(
        id="gocardless_api_token",
        name="GoCardless API Token",
        description="GoCardless payment API token (live_ prefix)",
        category=SecretCategory.PAYMENT,
        severity=Severity.CRITICAL,
        regex=re.compile(r"\b(live_[a-zA-Z0-9\-_=]{40})\b"),
        context_keywords=["gocardless"],
    ))

    patterns.append(SecretPattern(
        id="gitter_access_token",
        name="Gitter Access Token",
        description="Gitter chat API access token",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.MEDIUM,
        regex=re.compile(r"""(?i)(?:gitter)[\w.\s-]{0,20}[=:]\s*['"]?([a-z0-9_-]{40})['"]?"""),
        context_keywords=["gitter"],
        entropy_threshold=3.5,
    ))

    patterns.append(SecretPattern(
        id="kraken_access_token",
        name="Kraken Access Token",
        description="Kraken cryptocurrency exchange API key",
        category=SecretCategory.PAYMENT,
        severity=Severity.CRITICAL,
        regex=re.compile(r"""(?i)(?:kraken)[\w.\s-]{0,20}[=:]\s*['"]?([a-z0-9/+]{80,90}={0,2})['"]?"""),
        context_keywords=["kraken"],
        entropy_threshold=3.5,
    ))

    patterns.append(SecretPattern(
        id="kucoin_access_token",
        name="KuCoin Access Token",
        description="KuCoin cryptocurrency exchange access token",
        category=SecretCategory.PAYMENT,
        severity=Severity.CRITICAL,
        regex=re.compile(r"""(?i)(?:kucoin)[\w.\s-]{0,20}[=:]\s*['"]?([a-f0-9]{24})['"]?"""),
        context_keywords=["kucoin"],
    ))

    patterns.append(SecretPattern(
        id="kucoin_secret_key",
        name="KuCoin Secret Key",
        description="KuCoin cryptocurrency exchange secret key (UUID format)",
        category=SecretCategory.PAYMENT,
        severity=Severity.CRITICAL,
        regex=re.compile(r"""(?i)(?:kucoin)[\w.\s-]{0,20}(?:secret)[\w.\s-]{0,10}[=:]\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?"""),
        context_keywords=["kucoin"],
    ))

    patterns.append(SecretPattern(
        id="linkedin_client_id",
        name="LinkedIn Client ID",
        description="LinkedIn OAuth client ID",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.MEDIUM,
        regex=re.compile(r"""(?i)(?:linked[_-]?in)[\w.\s-]{0,20}(?:client[_\s-]*id)[\w.\s-]{0,10}[=:]\s*['"]?([a-z0-9]{14})['"]?"""),
        context_keywords=["linkedin"],
    ))

    patterns.append(SecretPattern(
        id="linkedin_client_secret",
        name="LinkedIn Client Secret",
        description="LinkedIn OAuth client secret",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(?:linked[_-]?in)[\w.\s-]{0,20}(?:client[_\s-]*secret)[\w.\s-]{0,10}[=:]\s*['"]?([a-z0-9]{16})['"]?"""),
        context_keywords=["linkedin"],
    ))

    patterns.append(SecretPattern(
        id="looker_client_secret",
        name="Looker Client Secret",
        description="Looker BI platform client secret",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(?:looker)[\w.\s-]{0,20}(?:secret)[\w.\s-]{0,10}[=:]\s*['"]?([a-z0-9]{24})['"]?"""),
        context_keywords=["looker"],
        entropy_threshold=3.5,
    ))

    patterns.append(SecretPattern(
        id="mattermost_access_token",
        name="Mattermost Access Token",
        description="Mattermost team messaging access token",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(?:mattermost)[\w.\s-]{0,20}[=:]\s*['"]?([a-z0-9]{26})['"]?"""),
        context_keywords=["mattermost"],
        entropy_threshold=3.5,
    ))

    patterns.append(SecretPattern(
        id="nytimes_access_token",
        name="NYTimes Access Token",
        description="New York Times API access token",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.MEDIUM,
        regex=re.compile(r"""(?i)(?:nytimes|newyorktimes|new.york.times)[\w.\s-]{0,20}[=:]\s*['"]?([a-z0-9=_\-]{32})['"]?"""),
        context_keywords=["nytimes", "newyorktimes"],
    ))

    patterns.append(SecretPattern(
        id="rapidapi_access_token",
        name="RapidAPI Access Token",
        description="RapidAPI marketplace access token",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(?:rapidapi)[\w.\s-]{0,20}[=:]\s*['"]?([a-z0-9_-]{50})['"]?"""),
        context_keywords=["rapidapi"],
        entropy_threshold=3.5,
    ))

    patterns.append(SecretPattern(
        id="sendbird_access_id",
        name="Sendbird Access ID",
        description="Sendbird chat API access ID (UUID format)",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(?:sendbird)[\w.\s-]{0,20}[=:]\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?"""),
        context_keywords=["sendbird"],
    ))

    patterns.append(SecretPattern(
        id="sendbird_access_token",
        name="Sendbird Access Token",
        description="Sendbird chat API access token",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(?:sendbird)[\w.\s-]{0,20}[=:]\s*['"]?([a-f0-9]{40})['"]?"""),
        context_keywords=["sendbird"],
        entropy_threshold=3.5,
    ))

    patterns.append(SecretPattern(
        id="squarespace_access_token",
        name="Squarespace Access Token",
        description="Squarespace website management API token (UUID format)",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(?:squarespace)[\w.\s-]{0,20}[=:]\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?"""),
        context_keywords=["squarespace"],
    ))

    patterns.append(SecretPattern(
        id="twitter_access_secret",
        name="Twitter/X Access Secret",
        description="Twitter/X OAuth access secret",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(?:twitter|x_access)[\w.\s-]{0,20}(?:secret)[\w.\s-]{0,10}[=:]\s*['"]?([a-z0-9]{45})['"]?"""),
        context_keywords=["twitter"],
        entropy_threshold=3.5,
    ))

    patterns.append(SecretPattern(
        id="twitter_access_token",
        name="Twitter/X Access Token",
        description="Twitter/X OAuth access token (numeric-alphanumeric format)",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(?:twitter)[\w.\s-]{0,20}(?:access[_\s-]*token)[\w.\s-]{0,10}[=:]\s*['"]?([0-9]{15,25}-[a-zA-Z0-9]{20,40})['"]?"""),
        context_keywords=["twitter"],
    ))

    patterns.append(SecretPattern(
        id="zendesk_secret_key",
        name="Zendesk Secret Key",
        description="Zendesk support platform secret key",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(?:zendesk)[\w.\s-]{0,20}(?:secret)[\w.\s-]{0,10}[=:]\s*['"]?([a-z0-9]{40})['"]?"""),
        context_keywords=["zendesk"],
        entropy_threshold=3.5,
    ))

    patterns.append(SecretPattern(
        id="discord_client_secret",
        name="Discord Client Secret",
        description="Discord OAuth2 client secret",
        category=SecretCategory.COMMUNICATION,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(?:discord)[\w.\s-]{0,20}(?:client[_\s-]*secret)[\w.\s-]{0,10}[=:]\s*['"]?([a-z0-9=_\-]{32})['"]?"""),
        context_keywords=["discord"],
        entropy_threshold=3.5,
    ))

    patterns.append(SecretPattern(
        id="bitbucket_client_secret",
        name="Bitbucket Client Secret",
        description="Bitbucket OAuth client secret",
        category=SecretCategory.VERSION_CONTROL,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(?:bitbucket)[\w.\s-]{0,20}(?:client[_\s-]*secret)[\w.\s-]{0,10}[=:]\s*['"]?([a-z0-9=_\-]{64})['"]?"""),
        context_keywords=["bitbucket"],
        entropy_threshold=3.5,
    ))

    patterns.append(SecretPattern(
        id="etsy_access_token",
        name="Etsy Access Token",
        description="Etsy marketplace API access token",
        category=SecretCategory.PAYMENT,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(?:etsy)[\w.\s-]{0,20}[=:]\s*['"]?([a-z0-9]{24})['"]?"""),
        context_keywords=["etsy"],
        entropy_threshold=3.5,
    ))

    patterns.append(SecretPattern(
        id="flickr_access_token",
        name="Flickr Access Token",
        description="Flickr photo API access token",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.MEDIUM,
        regex=re.compile(r"""(?i)(?:flickr)[\w.\s-]{0,20}[=:]\s*['"]?([a-z0-9]{32})['"]?"""),
        context_keywords=["flickr"],
        entropy_threshold=3.5,
    ))

    patterns.append(SecretPattern(
        id="jfrog_identity_token",
        name="JFrog Identity Token",
        description="JFrog platform identity token",
        category=SecretCategory.CI_CD,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(?:jfrog|artifactory|bintray|xray)[\w.\s-]{0,20}(?:identity|token)[\w.\s-]{0,10}[=:]\s*['"]?([a-z0-9]{64})['"]?"""),
        context_keywords=["jfrog", "artifactory"],
        entropy_threshold=3.5,
    ))

    patterns.append(SecretPattern(
        id="privateai_api_token",
        name="Private AI API Token",
        description="Private AI data privacy API token",
        category=SecretCategory.AI_SERVICE,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(?:private[_-]?ai)[\w.\s-]{0,20}[=:]\s*['"]?([a-z0-9]{32})['"]?"""),
        context_keywords=["privateai", "private_ai"],
        entropy_threshold=3.5,
    ))

    patterns.append(SecretPattern(
        id="sidekiq_secret",
        name="Sidekiq Enterprise Secret",
        description="Sidekiq Pro/Enterprise license credential",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(?:BUNDLE_ENTERPRISE__CONTRIBSYS__COM|BUNDLE_GEMS__CONTRIBSYS__COM)\s*[=:]\s*['"]?([a-f0-9]{8}:[a-f0-9]{8})['"]?"""),
    ))

    patterns.append(SecretPattern(
        id="sidekiq_sensitive_url",
        name="Sidekiq Sensitive URL",
        description="Sidekiq Pro/Enterprise URL with embedded credentials",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)https?://([a-f0-9]{8}:[a-f0-9]{8})@(?:gems|enterprise)\.contribsys\.com"""),
    ))

    patterns.append(SecretPattern(
        id="confluent_secret_key",
        name="Confluent Cloud Secret Key",
        description="Confluent Cloud (Kafka) API secret key",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(?:confluent)[\w.\s-]{0,20}(?:secret)[\w.\s-]{0,10}[=:]\s*['"]?([a-z0-9]{64})['"]?"""),
        context_keywords=["confluent", "kafka"],
        entropy_threshold=3.5,
    ))

    patterns.append(SecretPattern(
        id="linear_client_secret",
        name="Linear Client Secret",
        description="Linear project management OAuth client secret",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(?:linear)[\w.\s-]{0,20}(?:client[_\s-]*secret)[\w.\s-]{0,10}[=:]\s*['"]?([a-f0-9]{32})['"]?"""),
        context_keywords=["linear"],
        entropy_threshold=3.5,
    ))

    patterns.append(SecretPattern(
        id="asana_client_secret",
        name="Asana Client Secret",
        description="Asana OAuth client secret",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(?:asana)[\w.\s-]{0,20}(?:client[_\s-]*secret)[\w.\s-]{0,10}[=:]\s*['"]?([a-z0-9]{32})['"]?"""),
        context_keywords=["asana"],
        entropy_threshold=3.5,
    ))

    patterns.append(SecretPattern(
        id="finicity_api_token",
        name="Finicity API Token",
        description="Finicity financial data API token",
        category=SecretCategory.PAYMENT,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(?:finicity)[\w.\s-]{0,20}[=:]\s*['"]?([a-f0-9]{32})['"]?"""),
        context_keywords=["finicity"],
        entropy_threshold=3.5,
    ))

    patterns.append(SecretPattern(
        id="sumologic_access_token",
        name="SumoLogic Access Token",
        description="SumoLogic log analytics access token",
        category=SecretCategory.MONITORING,
        severity=Severity.HIGH,
        regex=re.compile(r"""(?i)(?:sumo)[\w.\s-]{0,20}(?:access[_\s-]*(?:token|key))[\w.\s-]{0,10}[=:]\s*['"]?([a-z0-9]{64})['"]?"""),
        context_keywords=["sumo"],
        entropy_threshold=3.5,
    ))

    return patterns


# Singleton for performance
_PATTERNS: Optional[List[SecretPattern]] = None


def get_patterns() -> List[SecretPattern]:
    """Get the singleton pattern list (compiled once)."""
    global _PATTERNS
    if _PATTERNS is None:
        _PATTERNS = build_patterns()
    return _PATTERNS
