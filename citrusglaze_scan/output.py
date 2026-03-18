"""
Output formatting for the secret scanner.

Supports:
- Pretty terminal output with colors and emojis
- JSON output for programmatic use
"""

from __future__ import annotations

import json
import os
import sys
from typing import Optional

from .patterns import Severity, SecretCategory
from .scanner import FullScanResult, ScanResult, SecretFinding


# ANSI color codes
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"

    @classmethod
    def disable(cls):
        """Disable colors (for non-TTY output)."""
        cls.RESET = ""
        cls.BOLD = ""
        cls.DIM = ""
        cls.RED = ""
        cls.GREEN = ""
        cls.YELLOW = ""
        cls.BLUE = ""
        cls.MAGENTA = ""
        cls.CYAN = ""
        cls.WHITE = ""
        cls.BG_RED = ""
        cls.BG_GREEN = ""
        cls.BG_YELLOW = ""


# Check if output supports colors
if not sys.stdout.isatty():
    Colors.disable()


SEVERITY_COLORS = {
    Severity.CRITICAL: Colors.RED,
    Severity.HIGH: Colors.YELLOW,
    Severity.MEDIUM: Colors.CYAN,
    Severity.LOW: Colors.DIM,
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "\U0001f534",  # red circle
    Severity.HIGH: "\U0001f7e0",      # orange circle
    Severity.MEDIUM: "\U0001f7e1",    # yellow circle
    Severity.LOW: "\u26aa",            # white circle
}

SEVERITY_LABELS = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
}


def print_header():
    """Print the scanner header."""
    print()
    print(f"{Colors.BOLD}\U0001f50d CitrusGlaze Secret Scanner{Colors.RESET}")
    print(f"   Scanning AI chat histories for leaked secrets...")
    print(f"   {Colors.DIM}100% local - no data leaves your machine{Colors.RESET}")
    print()


def print_source_result(result: ScanResult):
    """Print results for a single source."""
    icon = "\U0001f4c1"  # folder icon

    if not result.found:
        print(f"{icon} Scanning {result.source_name} {Colors.DIM}(not found){Colors.RESET}")
        return

    info_parts = []
    if result.conversation_count > 0:
        info_parts.append(f"{result.conversation_count:,} conversations")
    if result.message_count > 0:
        info_parts.append(f"{result.message_count:,} messages")
    info_str = ", ".join(info_parts) if info_parts else "empty"

    if result.error:
        print(f"{icon} Scanning {result.source_name} {Colors.RED}(error: {result.error}){Colors.RESET}")
        return

    if result.secret_count == 0:
        print(f"{icon} Scanning {result.source_name} ({info_str})")
        print(f"   {Colors.GREEN}No secrets found{Colors.RESET}")
    else:
        affected = result.affected_conversations
        print(f"{icon} Scanning {result.source_name} ({info_str})")
        print(f"   {Colors.RED}{Colors.BOLD}Found: {result.secret_count} secrets in {affected} conversations{Colors.RESET}")


def print_separator():
    """Print a visual separator."""
    print()
    # Box-drawing horizontal line
    print("\u2501" * 50)


def print_summary(full_result: FullScanResult, days: int):
    """Print the aggregate summary."""
    print_separator()

    total = full_result.total_secrets

    if total == 0:
        print()
        print(f"\U0001f4ca {Colors.GREEN}{Colors.BOLD}RESULTS: No secrets found in AI chat histories (last {days} days){Colors.RESET}")
        print()
        print(f"   \u2705 Your AI conversations look clean — for now.")
        print()
        print(f"   {Colors.DIM}A Samsung engineer pasted source code into ChatGPT once. It became training data.")
        print(f"   It only takes one prompt. CitrusGlaze catches it before it leaves your machine.{Colors.RESET}")
        print(f"   {Colors.BOLD}{Colors.CYAN}https://citrusglaze.dev{Colors.RESET}")
        print()
        return

    print()
    print(f"\U0001f4ca {Colors.RED}{Colors.BOLD}RESULTS: {total} secrets leaked to AI in the last {days} days{Colors.RESET}")
    print()

    # By severity
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        count = full_result.by_severity.get(sev, 0)
        if count == 0:
            continue

        icon = SEVERITY_ICONS[sev]
        color = SEVERITY_COLORS[sev]
        label = SEVERITY_LABELS[sev]
        print(f"   {icon} {color}{Colors.BOLD}{label} ({count}):{Colors.RESET}")

        # Group findings by pattern name for this severity
        pattern_counts = {}
        for r in full_result.results:
            for f in r.findings:
                if f.severity == sev:
                    pattern_counts[f.pattern_name] = pattern_counts.get(f.pattern_name, 0) + 1

        for name, cnt in sorted(pattern_counts.items(), key=lambda x: -x[1]):
            print(f"      {color}\u2022 {cnt}\u00d7 {name}{Colors.RESET}")

        print()

    # CTA
    print(f"\u26a0\ufe0f  {Colors.BOLD}This is how breaches start.{Colors.RESET}")
    print()
    print(f"   {Colors.DIM}\u2022 A Samsung engineer pasted proprietary source code into ChatGPT — it became")
    print(f"     training data. Samsung banned AI tools company-wide.{Colors.RESET}")
    print(f"   {Colors.DIM}\u2022 An AWS key leaked through a Copilot prompt led to a $28K bill overnight")
    print(f"     from cryptomining. The developer was let go.{Colors.RESET}")
    print(f"   {Colors.DIM}\u2022 AI providers can log, train on, or be compelled to hand over your prompts.{Colors.RESET}")
    print()
    print(f"   {Colors.BOLD}Stop it before it happens:{Colors.RESET}")
    print(f"   {Colors.BOLD}{Colors.CYAN}https://citrusglaze.dev{Colors.RESET} — local proxy that blocks secrets from reaching AI")
    print()

    print_separator()
    print()


def print_details(full_result: FullScanResult, verbose: bool = False):
    """Print detailed findings (only if verbose)."""
    if not verbose:
        return

    has_findings = any(r.findings for r in full_result.results)
    if not has_findings:
        return

    print()
    print(f"{Colors.BOLD}Detailed Findings:{Colors.RESET}")
    print()

    for result in full_result.results:
        if not result.findings:
            continue

        print(f"  {Colors.BOLD}{result.source_name}:{Colors.RESET}")
        for i, finding in enumerate(result.findings, 1):
            sev_color = SEVERITY_COLORS[finding.severity]
            sev_label = SEVERITY_LABELS[finding.severity]
            print(f"    {i}. {sev_color}[{sev_label}]{Colors.RESET} {finding.pattern_name}")
            print(f"       Value: {finding.redacted_text}")
            if finding.source_file:
                # Abbreviate home directory
                display_path = finding.source_file.replace(os.path.expanduser("~"), "~")
                print(f"       File: {Colors.DIM}{display_path}{Colors.RESET}")
            if finding.line_number:
                print(f"       Line: {finding.line_number}")
            print()


def format_json(full_result: FullScanResult, days: int) -> str:
    """Format results as JSON."""
    output = {
        "scanner": "citrusglaze-scan",
        "version": "0.1.2",
        "scan_period_days": days,
        "total_secrets": full_result.total_secrets,
        "by_severity": {
            sev.value: count
            for sev, count in full_result.by_severity.items()
        },
        "by_category": full_result.by_category,
        "by_pattern": full_result.by_pattern,
        "sources": [],
    }

    for result in full_result.results:
        source_data = {
            "name": result.source_name,
            "path": result.source_path,
            "found": result.found,
            "conversations": result.conversation_count,
            "messages": result.message_count,
            "secrets_found": result.secret_count,
            "findings": [],
        }

        if result.error:
            source_data["error"] = result.error

        for finding in result.findings:
            source_data["findings"].append({
                "pattern_id": finding.pattern_id,
                "pattern_name": finding.pattern_name,
                "category": finding.category.value,
                "severity": finding.severity.value,
                "redacted_value": finding.redacted_text,
                "source_file": finding.source_file,
                "line_number": finding.line_number,
            })

        output["sources"].append(source_data)

    return json.dumps(output, indent=2)


def print_full_report(full_result: FullScanResult, days: int,
                       json_output: bool = False, verbose: bool = False,
                       skip_header: bool = False):
    """Print the complete scan report."""
    if json_output:
        print(format_json(full_result, days))
        return

    if not skip_header:
        print_header()

    for result in full_result.results:
        print_source_result(result)

    print_summary(full_result, days)
    print_details(full_result, verbose)
