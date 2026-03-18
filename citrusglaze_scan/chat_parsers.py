"""
Parsers for AI tool chat history formats.

Supported tools:
- Claude Code (~/.claude/)
- Cursor (~/.cursor/ and ~/Library/Application Support/Cursor/)
- Continue.dev (~/.continue/)
- GitHub Copilot (~/Library/Application Support/GitHub Copilot Chat/)
- Windsurf (~/.codeium/ or ~/.windsurf/)
- Aider (~/.aider/)
- Codex CLI (~/.codex/)
- Kiro (~/.kiro/ and ~/Library/Application Support/Kiro/)
- Claude Desktop (~/Library/Application Support/Claude/)
- Roo Code (~/.roo/)
- Gemini CLI (~/.gemini/)
- Amazon Q Developer (~/.aws/amazonq/)
- Shell history (~/.zsh_history, ~/.bash_history)
- .env files
"""

from __future__ import annotations

import json
import os
import platform
import sqlite3
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class ChatMessage:
    """A single message extracted from a chat history file."""
    text: str
    source_file: str
    timestamp: Optional[datetime] = None
    role: Optional[str] = None  # "user", "assistant", etc.


@dataclass
class ChatSource:
    """An AI tool chat history source."""
    name: str
    path: Path
    found: bool = False
    message_count: int = 0
    conversation_count: int = 0
    messages: list[ChatMessage] = field(default_factory=list)
    error: Optional[str] = None


def _home() -> Path:
    return Path.home()


def _is_macos() -> bool:
    return platform.system() == "Darwin"


def _is_linux() -> bool:
    return platform.system() == "Linux"


def _epoch_ms_to_datetime(ms: int) -> datetime:
    """Convert epoch milliseconds to datetime."""
    return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)


def _is_within_days(dt: Optional[datetime], days: int) -> bool:
    """Check if a datetime is within the last N days."""
    if dt is None or days <= 0:
        return True
    cutoff = datetime.now(tz=timezone.utc) - timedelta(days=days)
    return dt >= cutoff


# ============================================================================
# Claude Code parser
# ============================================================================

def parse_claude_code(days: int = 30) -> ChatSource:
    """Parse Claude Code chat history from ~/.claude/."""
    claude_dir = _home() / ".claude"
    source = ChatSource(name="Claude Code", path=claude_dir)

    if not claude_dir.exists():
        return source
    source.found = True

    conversations_seen = set()

    # 1. Parse the main history.jsonl (command history/prompts)
    history_file = claude_dir / "history.jsonl"
    if history_file.exists():
        try:
            with open(history_file, "r", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        ts = entry.get("timestamp")
                        dt = _epoch_ms_to_datetime(ts) if ts else None
                        if not _is_within_days(dt, days):
                            continue
                        text = entry.get("display", "")
                        if text:
                            session_id = entry.get("sessionId", "unknown")
                            conversations_seen.add(session_id)
                            source.messages.append(ChatMessage(
                                text=text,
                                source_file=str(history_file),
                                timestamp=dt,
                                role="user",
                            ))
                    except (json.JSONDecodeError, KeyError):
                        continue
        except (OSError, IOError):
            pass

    # 2. Parse project conversation JSONL files
    projects_dir = claude_dir / "projects"
    if projects_dir.exists():
        for jsonl_file in projects_dir.rglob("*.jsonl"):
            try:
                with open(jsonl_file, "r", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                            ts = entry.get("timestamp")
                            if isinstance(ts, str):
                                try:
                                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                                except ValueError:
                                    dt = None
                            elif isinstance(ts, (int, float)):
                                dt = _epoch_ms_to_datetime(int(ts))
                            else:
                                dt = None

                            if not _is_within_days(dt, days):
                                continue

                            session_id = entry.get("sessionId", str(jsonl_file))
                            conversations_seen.add(session_id)

                            # Extract message content
                            msg = entry.get("message", {})
                            if isinstance(msg, dict):
                                content = msg.get("content", "")
                                role = msg.get("role", "")
                                if isinstance(content, str) and content:
                                    source.messages.append(ChatMessage(
                                        text=content,
                                        source_file=str(jsonl_file),
                                        timestamp=dt,
                                        role=role,
                                    ))
                                elif isinstance(content, list):
                                    for block in content:
                                        if isinstance(block, dict):
                                            text = block.get("text", "")
                                            if text:
                                                source.messages.append(ChatMessage(
                                                    text=text,
                                                    source_file=str(jsonl_file),
                                                    timestamp=dt,
                                                    role=role,
                                                ))
                                            # Also check tool input
                                            inp = block.get("input", {})
                                            if isinstance(inp, dict):
                                                for v in inp.values():
                                                    if isinstance(v, str) and len(v) > 10:
                                                        source.messages.append(ChatMessage(
                                                            text=v,
                                                            source_file=str(jsonl_file),
                                                            timestamp=dt,
                                                            role=role,
                                                        ))

                            # Also check top-level "content" field (queue operations)
                            top_content = entry.get("content", "")
                            if isinstance(top_content, str) and len(top_content) > 20:
                                source.messages.append(ChatMessage(
                                    text=top_content,
                                    source_file=str(jsonl_file),
                                    timestamp=dt,
                                    role="system",
                                ))

                        except (json.JSONDecodeError, KeyError):
                            continue
            except (OSError, IOError):
                continue

    source.conversation_count = len(conversations_seen)
    source.message_count = len(source.messages)
    return source


# ============================================================================
# Cursor parser
# ============================================================================

def parse_cursor(days: int = 30) -> ChatSource:
    """Parse Cursor chat history."""
    # Cursor stores data in various locations depending on version
    cursor_paths = [
        _home() / ".cursor",
        _home() / ".cursor-tutor",
    ]
    if _is_macos():
        cursor_paths.extend([
            _home() / "Library" / "Application Support" / "Cursor",
            _home() / "Library" / "Application Support" / "Cursor" / "User" / "workspaceStorage",
        ])
    elif _is_linux():
        cursor_paths.extend([
            _home() / ".config" / "Cursor",
            _home() / ".config" / "Cursor" / "User" / "workspaceStorage",
        ])

    source = ChatSource(name="Cursor", path=_home() / ".cursor")

    for base_path in cursor_paths:
        if not base_path.exists():
            continue
        source.found = True
        source.path = base_path

        # Look for chat-related JSON/JSONL/SQLite files
        # Cursor stores conversations in workspaceStorage as JSON
        for json_file in base_path.rglob("*.json"):
            if json_file.stat().st_size > 50_000_000:  # Skip files > 50MB
                continue
            try:
                stat = json_file.stat()
                mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                if not _is_within_days(mtime, days):
                    continue

                with open(json_file, "r", errors="replace") as f:
                    content = f.read(5_000_000)  # Max 5MB per file
                    # Check if it looks like chat data
                    if any(keyword in content.lower() for keyword in
                           ["message", "prompt", "completion", "chat", "conversation"]):
                        try:
                            data = json.loads(content)
                            texts = _extract_texts_recursive(data, max_depth=5)
                            for text in texts:
                                source.messages.append(ChatMessage(
                                    text=text,
                                    source_file=str(json_file),
                                    timestamp=mtime,
                                ))
                        except json.JSONDecodeError:
                            # Not valid JSON, scan as raw text
                            source.messages.append(ChatMessage(
                                text=content,
                                source_file=str(json_file),
                                timestamp=mtime,
                            ))
            except (OSError, IOError):
                continue

    source.message_count = len(source.messages)
    source.conversation_count = max(1, source.message_count // 10) if source.messages else 0
    return source


# ============================================================================
# Continue.dev parser
# ============================================================================

def parse_continue(days: int = 30) -> ChatSource:
    """Parse Continue.dev chat history."""
    continue_paths = [
        _home() / ".continue",
    ]
    if _is_macos():
        continue_paths.append(_home() / "Library" / "Application Support" / "Continue")
    elif _is_linux():
        continue_paths.append(_home() / ".config" / "continue")

    source = ChatSource(name="Continue.dev", path=_home() / ".continue")

    for base_path in continue_paths:
        if not base_path.exists():
            continue
        source.found = True
        source.path = base_path

        # Continue.dev stores sessions in sessions/ directory as JSON
        sessions_dir = base_path / "sessions"
        if sessions_dir.exists():
            for session_file in sessions_dir.rglob("*.json"):
                try:
                    stat = session_file.stat()
                    mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                    if not _is_within_days(mtime, days):
                        continue

                    with open(session_file, "r", errors="replace") as f:
                        data = json.load(f)
                        # Continue stores messages in a "history" or "messages" array
                        messages = data.get("history", data.get("messages", []))
                        if isinstance(messages, list):
                            source.conversation_count += 1
                            for msg in messages:
                                if isinstance(msg, dict):
                                    content = msg.get("content", msg.get("text", ""))
                                    if isinstance(content, str) and content:
                                        source.messages.append(ChatMessage(
                                            text=content,
                                            source_file=str(session_file),
                                            timestamp=mtime,
                                            role=msg.get("role"),
                                        ))
                except (json.JSONDecodeError, OSError, IOError):
                    continue

        # Also check for dev_data or logs
        for log_file in base_path.rglob("*.log"):
            try:
                stat = log_file.stat()
                mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                if not _is_within_days(mtime, days):
                    continue
                with open(log_file, "r", errors="replace") as f:
                    content = f.read(2_000_000)
                    source.messages.append(ChatMessage(
                        text=content,
                        source_file=str(log_file),
                        timestamp=mtime,
                    ))
            except (OSError, IOError):
                continue

    source.message_count = len(source.messages)
    return source


# ============================================================================
# GitHub Copilot parser
# ============================================================================

def parse_copilot(days: int = 30) -> ChatSource:
    """Parse GitHub Copilot chat history."""
    copilot_paths = []
    if _is_macos():
        copilot_paths.extend([
            _home() / "Library" / "Application Support" / "GitHub Copilot",
            _home() / "Library" / "Application Support" / "GitHub Copilot Chat",
        ])
    elif _is_linux():
        copilot_paths.extend([
            _home() / ".config" / "github-copilot",
        ])

    # Also check VS Code extension directories
    vscode_ext = _home() / ".vscode" / "extensions"
    if vscode_ext.exists():
        for ext_dir in vscode_ext.iterdir():
            if "copilot" in ext_dir.name.lower():
                copilot_paths.append(ext_dir)

    source = ChatSource(name="GitHub Copilot", path=_home() / "Library" / "Application Support" / "GitHub Copilot")

    for base_path in copilot_paths:
        if not base_path.exists():
            continue
        source.found = True
        source.path = base_path

        for json_file in base_path.rglob("*.json"):
            if json_file.stat().st_size > 50_000_000:
                continue
            try:
                stat = json_file.stat()
                mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                if not _is_within_days(mtime, days):
                    continue
                with open(json_file, "r", errors="replace") as f:
                    content = f.read(5_000_000)
                    try:
                        data = json.loads(content)
                        texts = _extract_texts_recursive(data, max_depth=5)
                        for text in texts:
                            source.messages.append(ChatMessage(
                                text=text,
                                source_file=str(json_file),
                                timestamp=mtime,
                            ))
                    except json.JSONDecodeError:
                        source.messages.append(ChatMessage(
                            text=content,
                            source_file=str(json_file),
                            timestamp=mtime,
                        ))
            except (OSError, IOError):
                continue

    source.message_count = len(source.messages)
    source.conversation_count = max(1, source.message_count // 5) if source.messages else 0
    return source


# ============================================================================
# Windsurf / Codeium parser
# ============================================================================

def parse_windsurf(days: int = 30) -> ChatSource:
    """Parse Windsurf/Codeium chat history."""
    windsurf_paths = [
        _home() / ".codeium",
        _home() / ".windsurf",
    ]
    if _is_macos():
        windsurf_paths.append(_home() / "Library" / "Application Support" / "Windsurf")

    source = ChatSource(name="Windsurf", path=_home() / ".windsurf")

    for base_path in windsurf_paths:
        if not base_path.exists():
            continue
        source.found = True
        source.path = base_path

        for json_file in base_path.rglob("*.json"):
            if json_file.stat().st_size > 50_000_000:
                continue
            try:
                stat = json_file.stat()
                mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                if not _is_within_days(mtime, days):
                    continue
                with open(json_file, "r", errors="replace") as f:
                    content = f.read(5_000_000)
                    try:
                        data = json.loads(content)
                        texts = _extract_texts_recursive(data, max_depth=5)
                        for text in texts:
                            source.messages.append(ChatMessage(
                                text=text,
                                source_file=str(json_file),
                                timestamp=mtime,
                            ))
                    except json.JSONDecodeError:
                        pass
            except (OSError, IOError):
                continue

    source.message_count = len(source.messages)
    source.conversation_count = max(1, source.message_count // 10) if source.messages else 0
    return source


# ============================================================================
# Aider parser
# ============================================================================

def parse_aider(days: int = 30) -> ChatSource:
    """Parse Aider chat history."""
    aider_paths = [
        _home() / ".aider",
        _home() / ".aider.chat.history.md",
    ]

    source = ChatSource(name="Aider", path=_home() / ".aider")

    for base_path in aider_paths:
        if not base_path.exists():
            continue
        source.found = True

        if base_path.is_file():
            try:
                stat = base_path.stat()
                mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                if _is_within_days(mtime, days):
                    with open(base_path, "r", errors="replace") as f:
                        content = f.read(10_000_000)
                        source.messages.append(ChatMessage(
                            text=content,
                            source_file=str(base_path),
                            timestamp=mtime,
                        ))
                        source.conversation_count = content.count("# aider chat") or 1
            except (OSError, IOError):
                pass
        elif base_path.is_dir():
            for hist_file in base_path.rglob("*.md"):
                try:
                    stat = hist_file.stat()
                    mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                    if not _is_within_days(mtime, days):
                        continue
                    with open(hist_file, "r", errors="replace") as f:
                        content = f.read(5_000_000)
                        source.messages.append(ChatMessage(
                            text=content,
                            source_file=str(hist_file),
                            timestamp=mtime,
                        ))
                        source.conversation_count += 1
                except (OSError, IOError):
                    continue

    source.message_count = len(source.messages)
    return source


# ============================================================================
# Shell history parser
# ============================================================================

def parse_shell_history(days: int = 30) -> ChatSource:
    """Parse shell history for secrets."""
    shell_files = [
        _home() / ".zsh_history",
        _home() / ".bash_history",
        _home() / ".zshrc",
        _home() / ".bashrc",
        _home() / ".bash_profile",
        _home() / ".profile",
    ]

    source = ChatSource(name="Shell History", path=_home())

    for hist_file in shell_files:
        if not hist_file.exists():
            continue
        source.found = True
        try:
            stat = hist_file.stat()
            mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
            # Always scan shell config files regardless of date
            is_config = hist_file.name in (".zshrc", ".bashrc", ".bash_profile", ".profile")
            if not is_config and not _is_within_days(mtime, days):
                continue
            with open(hist_file, "r", errors="replace") as f:
                content = f.read(10_000_000)
                source.messages.append(ChatMessage(
                    text=content,
                    source_file=str(hist_file),
                    timestamp=mtime,
                ))
                source.conversation_count += 1
        except (OSError, IOError):
            continue

    source.message_count = len(source.messages)
    return source


# ============================================================================
# .env file scanner
# ============================================================================

def parse_env_files(days: int = 30) -> ChatSource:
    """Scan .env files in home directory (non-recursive, 1 level)."""
    source = ChatSource(name=".env Files", path=_home())

    home = _home()
    env_patterns = [".env", ".env.local", ".env.production", ".env.development"]

    for env_name in env_patterns:
        env_file = home / env_name
        if env_file.exists():
            source.found = True
            try:
                with open(env_file, "r", errors="replace") as f:
                    content = f.read(1_000_000)
                    source.messages.append(ChatMessage(
                        text=content,
                        source_file=str(env_file),
                        timestamp=datetime.fromtimestamp(env_file.stat().st_mtime, tz=timezone.utc),
                    ))
                    source.conversation_count += 1
            except (OSError, IOError):
                continue

    source.message_count = len(source.messages)
    return source


# ============================================================================
# Codex CLI parser (OpenAI)
# ============================================================================

def parse_codex(days: int = 30) -> ChatSource:
    """Parse OpenAI Codex CLI chat history from ~/.codex/."""
    codex_dir = _home() / ".codex"
    source = ChatSource(name="Codex CLI", path=codex_dir)

    if not codex_dir.exists():
        return source
    source.found = True

    # 1. Parse JSONL session files in sessions/ directory
    sessions_dir = codex_dir / "sessions"
    if sessions_dir.exists():
        for jsonl_file in sessions_dir.rglob("*.jsonl"):
            try:
                stat = jsonl_file.stat()
                mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                if not _is_within_days(mtime, days):
                    continue
                with open(jsonl_file, "r", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                            entry_type = entry.get("type", "")
                            payload = entry.get("payload", {})

                            # Extract user/assistant messages
                            if entry_type == "response_item" and isinstance(payload, dict):
                                role = payload.get("role", "")
                                content = payload.get("content", [])
                                if isinstance(content, list):
                                    for block in content:
                                        if isinstance(block, dict):
                                            text = block.get("text", "")
                                            if text and len(text) > 5:
                                                source.messages.append(ChatMessage(
                                                    text=text,
                                                    source_file=str(jsonl_file),
                                                    timestamp=mtime,
                                                    role=role,
                                                ))

                            # Extract event messages (user prompts)
                            elif entry_type == "event_msg" and isinstance(payload, dict):
                                msg = payload.get("message", "")
                                if msg and len(msg) > 5:
                                    source.messages.append(ChatMessage(
                                        text=msg,
                                        source_file=str(jsonl_file),
                                        timestamp=mtime,
                                        role="user",
                                    ))

                            # Extract tool call inputs/outputs
                            elif entry_type in ("tool_call", "tool_output") and isinstance(payload, dict):
                                for key in ("input", "output", "arguments"):
                                    val = payload.get(key)
                                    if isinstance(val, str) and len(val) > 10:
                                        source.messages.append(ChatMessage(
                                            text=val,
                                            source_file=str(jsonl_file),
                                            timestamp=mtime,
                                            role="tool",
                                        ))
                                    elif isinstance(val, dict):
                                        for v in val.values():
                                            if isinstance(v, str) and len(v) > 10:
                                                source.messages.append(ChatMessage(
                                                    text=v,
                                                    source_file=str(jsonl_file),
                                                    timestamp=mtime,
                                                    role="tool",
                                                ))

                            source.conversation_count = max(source.conversation_count, 1)
                        except (json.JSONDecodeError, KeyError):
                            continue
            except (OSError, IOError):
                continue

    # 2. Parse SQLite logs for message content (if available)
    for db_name in ("state_5.sqlite", "state_4.sqlite", "state.sqlite"):
        db_path = codex_dir / db_name
        if db_path.exists():
            try:
                conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT message, ts FROM logs WHERE message IS NOT NULL "
                    "AND length(message) > 20 ORDER BY ts DESC LIMIT 5000"
                )
                for row in cursor.fetchall():
                    msg, ts = row
                    dt = datetime.fromtimestamp(ts, tz=timezone.utc) if ts else None
                    if not _is_within_days(dt, days):
                        continue
                    source.messages.append(ChatMessage(
                        text=msg,
                        source_file=str(db_path),
                        timestamp=dt,
                        role="system",
                    ))
                conn.close()
            except (sqlite3.Error, OSError):
                pass
            break  # Only use first found DB

    source.message_count = len(source.messages)
    return source


# ============================================================================
# Kiro parser (AWS)
# ============================================================================

def parse_kiro(days: int = 30) -> ChatSource:
    """Parse Kiro (AWS AI IDE) chat history."""
    kiro_paths = [
        _home() / ".kiro",
    ]
    if _is_macos():
        kiro_paths.append(_home() / "Library" / "Application Support" / "Kiro")
    elif _is_linux():
        kiro_paths.append(_home() / ".config" / "Kiro")

    source = ChatSource(name="Kiro", path=_home() / ".kiro")

    for base_path in kiro_paths:
        if not base_path.exists():
            continue
        source.found = True
        source.path = base_path

        # Kiro uses Continue-based format: workspace-sessions/ with JSON files
        for session_file in base_path.rglob("*.json"):
            if session_file.stat().st_size > 50_000_000:
                continue
            try:
                stat = session_file.stat()
                mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                if not _is_within_days(mtime, days):
                    continue

                with open(session_file, "r", errors="replace") as f:
                    data = json.load(f)

                # Sessions index: list of {sessionId, title, dateCreated}
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and "sessionId" in item:
                            source.conversation_count += 1
                    continue

                # Session detail: {history: [{message: {role, content}}]}
                if isinstance(data, dict):
                    history = data.get("history", [])
                    if isinstance(history, list) and history:
                        source.conversation_count += 1
                        for msg_entry in history:
                            if not isinstance(msg_entry, dict):
                                continue
                            msg = msg_entry.get("message", {})
                            if not isinstance(msg, dict):
                                continue
                            role = msg.get("role", "")
                            content = msg.get("content", [])
                            if isinstance(content, str) and content:
                                source.messages.append(ChatMessage(
                                    text=content,
                                    source_file=str(session_file),
                                    timestamp=mtime,
                                    role=role,
                                ))
                            elif isinstance(content, list):
                                for block in content:
                                    if isinstance(block, dict):
                                        text = block.get("text", "")
                                        if text and len(text) > 5:
                                            source.messages.append(ChatMessage(
                                                text=text,
                                                source_file=str(session_file),
                                                timestamp=mtime,
                                                role=role,
                                            ))
                                    elif isinstance(block, str) and len(block) > 5:
                                        source.messages.append(ChatMessage(
                                            text=block,
                                            source_file=str(session_file),
                                            timestamp=mtime,
                                            role=role,
                                        ))

            except (json.JSONDecodeError, OSError, IOError):
                continue

    source.message_count = len(source.messages)
    return source


# ============================================================================
# Claude Desktop parser
# ============================================================================

def parse_claude_desktop(days: int = 30) -> ChatSource:
    """Parse Claude Desktop app data (Electron/Local Storage)."""
    claude_paths = []
    if _is_macos():
        claude_paths.append(_home() / "Library" / "Application Support" / "Claude")
    elif _is_linux():
        claude_paths.append(_home() / ".config" / "Claude")

    source = ChatSource(name="Claude Desktop", path=_home() / "Library" / "Application Support" / "Claude")

    for base_path in claude_paths:
        if not base_path.exists():
            continue
        source.found = True
        source.path = base_path

        # Scan Local Storage LevelDB files (contain key-value pairs as text)
        local_storage = base_path / "Local Storage" / "leveldb"
        if local_storage.exists():
            for ldb_file in local_storage.iterdir():
                if ldb_file.suffix not in (".log", ".ldb"):
                    continue
                try:
                    stat = ldb_file.stat()
                    mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                    if not _is_within_days(mtime, days):
                        continue
                    # Read as binary and extract readable strings
                    with open(ldb_file, "rb") as f:
                        raw = f.read(10_000_000)
                    # Extract UTF-8 string segments
                    text = raw.decode("utf-8", errors="replace")
                    if len(text) > 20:
                        source.messages.append(ChatMessage(
                            text=text,
                            source_file=str(ldb_file),
                            timestamp=mtime,
                        ))
                except (OSError, IOError):
                    continue

        # Also scan Session Storage
        session_storage = base_path / "Session Storage"
        if session_storage.exists():
            for ss_file in session_storage.iterdir():
                if ss_file.suffix not in (".log", ".ldb"):
                    continue
                try:
                    stat = ss_file.stat()
                    mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                    if not _is_within_days(mtime, days):
                        continue
                    with open(ss_file, "rb") as f:
                        raw = f.read(10_000_000)
                    text = raw.decode("utf-8", errors="replace")
                    if len(text) > 20:
                        source.messages.append(ChatMessage(
                            text=text,
                            source_file=str(ss_file),
                            timestamp=mtime,
                        ))
                except (OSError, IOError):
                    continue

        # Scan config.json for any tokens
        config_file = base_path / "config.json"
        if config_file.exists():
            try:
                with open(config_file, "r", errors="replace") as f:
                    content = f.read(1_000_000)
                    source.messages.append(ChatMessage(
                        text=content,
                        source_file=str(config_file),
                        timestamp=datetime.fromtimestamp(
                            config_file.stat().st_mtime, tz=timezone.utc
                        ),
                    ))
            except (OSError, IOError):
                pass

    source.message_count = len(source.messages)
    source.conversation_count = max(1, source.message_count // 5) if source.messages else 0
    return source


# ============================================================================
# Roo Code parser (VS Code extension)
# ============================================================================

def parse_roo_code(days: int = 30) -> ChatSource:
    """Parse Roo Code chat history."""
    roo_paths = [
        _home() / ".roo",
    ]
    if _is_macos():
        roo_paths.append(
            _home() / "Library" / "Application Support" / "Code" / "User"
            / "globalStorage" / "rooveterinaryinc.roo-cline"
        )
    elif _is_linux():
        roo_paths.append(
            _home() / ".config" / "Code" / "User"
            / "globalStorage" / "rooveterinaryinc.roo-cline"
        )

    source = ChatSource(name="Roo Code", path=_home() / ".roo")

    for base_path in roo_paths:
        if not base_path.exists():
            continue
        source.found = True
        source.path = base_path

        # Roo Code stores task histories as JSON
        for json_file in base_path.rglob("*.json"):
            if json_file.stat().st_size > 50_000_000:
                continue
            try:
                stat = json_file.stat()
                mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                if not _is_within_days(mtime, days):
                    continue
                with open(json_file, "r", errors="replace") as f:
                    content = f.read(5_000_000)
                    if any(kw in content.lower() for kw in
                           ("message", "prompt", "content", "task", "conversation")):
                        try:
                            data = json.loads(content)
                            texts = _extract_texts_recursive(data, max_depth=5)
                            for text in texts:
                                source.messages.append(ChatMessage(
                                    text=text,
                                    source_file=str(json_file),
                                    timestamp=mtime,
                                ))
                        except json.JSONDecodeError:
                            pass
            except (OSError, IOError):
                continue

        # Also check for .roo/task-history/ markdown files
        for md_file in base_path.rglob("*.md"):
            try:
                stat = md_file.stat()
                mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                if not _is_within_days(mtime, days):
                    continue
                with open(md_file, "r", errors="replace") as f:
                    content = f.read(5_000_000)
                    if len(content) > 20:
                        source.messages.append(ChatMessage(
                            text=content,
                            source_file=str(md_file),
                            timestamp=mtime,
                        ))
                        source.conversation_count += 1
            except (OSError, IOError):
                continue

    source.message_count = len(source.messages)
    if not source.conversation_count:
        source.conversation_count = max(1, source.message_count // 10) if source.messages else 0
    return source


# ============================================================================
# Gemini CLI parser (Google)
# ============================================================================

def parse_gemini_cli(days: int = 30) -> ChatSource:
    """Parse Gemini CLI chat history."""
    gemini_paths = [
        _home() / ".gemini",
    ]
    if _is_macos():
        gemini_paths.append(_home() / "Library" / "Application Support" / "gemini")
    elif _is_linux():
        gemini_paths.extend([
            _home() / ".config" / "gemini",
            _home() / ".local" / "share" / "gemini",
        ])

    source = ChatSource(name="Gemini CLI", path=_home() / ".gemini")

    for base_path in gemini_paths:
        if not base_path.exists():
            continue
        source.found = True
        source.path = base_path

        # Scan JSONL files (session logs)
        for jsonl_file in base_path.rglob("*.jsonl"):
            try:
                stat = jsonl_file.stat()
                mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                if not _is_within_days(mtime, days):
                    continue
                with open(jsonl_file, "r", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                            texts = _extract_texts_recursive(entry, max_depth=4)
                            for text in texts:
                                source.messages.append(ChatMessage(
                                    text=text,
                                    source_file=str(jsonl_file),
                                    timestamp=mtime,
                                ))
                        except json.JSONDecodeError:
                            continue
                source.conversation_count += 1
            except (OSError, IOError):
                continue

        # Scan JSON files (config, sessions)
        for json_file in base_path.rglob("*.json"):
            if json_file.stat().st_size > 50_000_000:
                continue
            try:
                stat = json_file.stat()
                mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                if not _is_within_days(mtime, days):
                    continue
                with open(json_file, "r", errors="replace") as f:
                    data = json.load(f)
                    texts = _extract_texts_recursive(data, max_depth=5)
                    for text in texts:
                        source.messages.append(ChatMessage(
                            text=text,
                            source_file=str(json_file),
                            timestamp=mtime,
                        ))
            except (json.JSONDecodeError, OSError, IOError):
                continue

    source.message_count = len(source.messages)
    return source


# ============================================================================
# Amazon Q Developer parser
# ============================================================================

def parse_amazon_q(days: int = 30) -> ChatSource:
    """Parse Amazon Q Developer (formerly CodeWhisperer) chat history."""
    q_paths = [
        _home() / ".aws" / "amazonq",
        _home() / ".aws" / "codewhisperer",
    ]
    if _is_macos():
        q_paths.extend([
            _home() / "Library" / "Application Support" / "amazon-q",
            _home() / "Library" / "Application Support" / "aws.amazon.q",
            _home() / "Library" / "Application Support" / "Code" / "User"
            / "globalStorage" / "amazonwebservices.amazon-q-vscode",
        ])
    elif _is_linux():
        q_paths.extend([
            _home() / ".config" / "amazon-q",
            _home() / ".config" / "Code" / "User"
            / "globalStorage" / "amazonwebservices.amazon-q-vscode",
        ])

    source = ChatSource(name="Amazon Q", path=_home() / ".aws" / "amazonq")

    for base_path in q_paths:
        if not base_path.exists():
            continue
        source.found = True
        source.path = base_path

        # Scan JSON files for chat sessions
        for json_file in base_path.rglob("*.json"):
            if json_file.stat().st_size > 50_000_000:
                continue
            try:
                stat = json_file.stat()
                mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                if not _is_within_days(mtime, days):
                    continue
                with open(json_file, "r", errors="replace") as f:
                    content = f.read(5_000_000)
                    try:
                        data = json.loads(content)
                        texts = _extract_texts_recursive(data, max_depth=5)
                        for text in texts:
                            source.messages.append(ChatMessage(
                                text=text,
                                source_file=str(json_file),
                                timestamp=mtime,
                            ))
                    except json.JSONDecodeError:
                        # Scan raw content for secrets
                        if len(content) > 20:
                            source.messages.append(ChatMessage(
                                text=content,
                                source_file=str(json_file),
                                timestamp=mtime,
                            ))
            except (OSError, IOError):
                continue

        # Scan JSONL log files
        for jsonl_file in base_path.rglob("*.jsonl"):
            try:
                stat = jsonl_file.stat()
                mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                if not _is_within_days(mtime, days):
                    continue
                with open(jsonl_file, "r", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                            texts = _extract_texts_recursive(entry, max_depth=4)
                            for text in texts:
                                source.messages.append(ChatMessage(
                                    text=text,
                                    source_file=str(jsonl_file),
                                    timestamp=mtime,
                                ))
                        except json.JSONDecodeError:
                            continue
            except (OSError, IOError):
                continue

    source.message_count = len(source.messages)
    source.conversation_count = max(1, source.message_count // 10) if source.messages else 0
    return source


# ============================================================================
# Custom directory scanner
# ============================================================================

def parse_directory(path: str, days: int = 30) -> ChatSource:
    """Scan an arbitrary directory for secrets."""
    target = Path(path).expanduser().resolve()
    source = ChatSource(name=f"Custom: {path}", path=target)

    if not target.exists():
        source.error = f"Path does not exist: {path}"
        return source

    source.found = True
    scannable_extensions = {
        ".json", ".jsonl", ".txt", ".md", ".log", ".env", ".cfg", ".ini",
        ".yaml", ".yml", ".toml", ".conf", ".sh", ".bash", ".zsh",
        ".py", ".js", ".ts", ".rb", ".go", ".rs", ".java", ".kt",
        ".swift", ".c", ".cpp", ".h", ".hpp", ".cs", ".php", ".pl",
        ".r", ".R", ".sql", ".xml", ".html", ".css", ".scss",
        ".dockerfile", ".tf", ".hcl", ".gradle", ".properties",
    }

    if target.is_file():
        try:
            with open(target, "r", errors="replace") as f:
                content = f.read(10_000_000)
                source.messages.append(ChatMessage(
                    text=content,
                    source_file=str(target),
                    timestamp=datetime.fromtimestamp(target.stat().st_mtime, tz=timezone.utc),
                ))
                source.conversation_count = 1
        except (OSError, IOError) as e:
            source.error = str(e)
    else:
        file_count = 0
        for root, dirs, files in os.walk(target):
            # Skip hidden directories and common non-useful dirs
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in
                       ("node_modules", "__pycache__", "venv", ".git", "target", "build")]
            for fname in files:
                if file_count >= 10000:  # Safety limit
                    break
                fpath = Path(root) / fname
                suffix = fpath.suffix.lower()
                # Also scan files with no extension if small
                if suffix not in scannable_extensions and suffix != "":
                    continue
                if fpath.stat().st_size > 10_000_000:  # Skip >10MB
                    continue
                try:
                    stat = fpath.stat()
                    mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                    if not _is_within_days(mtime, days):
                        continue
                    with open(fpath, "r", errors="replace") as f:
                        content = f.read(5_000_000)
                        source.messages.append(ChatMessage(
                            text=content,
                            source_file=str(fpath),
                        ))
                        file_count += 1
                except (OSError, IOError):
                    continue

        source.conversation_count = file_count

    source.message_count = len(source.messages)
    return source


# ============================================================================
# Helpers
# ============================================================================

def _extract_texts_recursive(data, max_depth: int = 5, current_depth: int = 0) -> list[str]:
    """Recursively extract string values from JSON data."""
    if current_depth >= max_depth:
        return []

    texts = []

    if isinstance(data, str):
        if len(data) > 10:  # Skip tiny strings
            texts.append(data)
    elif isinstance(data, dict):
        for key, value in data.items():
            texts.extend(_extract_texts_recursive(value, max_depth, current_depth + 1))
    elif isinstance(data, list):
        for item in data[:500]:  # Limit list traversal
            texts.extend(_extract_texts_recursive(item, max_depth, current_depth + 1))

    return texts


# ============================================================================
# Main dispatcher
# ============================================================================

ALL_PARSERS = {
    "claude": parse_claude_code,
    "cursor": parse_cursor,
    "continue": parse_continue,
    "copilot": parse_copilot,
    "windsurf": parse_windsurf,
    "aider": parse_aider,
    "codex": parse_codex,
    "kiro": parse_kiro,
    "claude-desktop": parse_claude_desktop,
    "roo": parse_roo_code,
    "gemini-cli": parse_gemini_cli,
    "amazon-q": parse_amazon_q,
    "shell": parse_shell_history,
    "env": parse_env_files,
}


def get_all_sources(days: int = 30, tools: Optional[list[str]] = None) -> list[ChatSource]:
    """Parse all (or selected) AI tool chat histories."""
    parsers = ALL_PARSERS
    if tools:
        parsers = {k: v for k, v in ALL_PARSERS.items() if k in tools}

    sources = []
    for name, parser_fn in parsers.items():
        try:
            source = parser_fn(days=days)
            sources.append(source)
        except Exception as e:
            source = ChatSource(name=name, path=Path("."), error=str(e))
            sources.append(source)

    return sources
