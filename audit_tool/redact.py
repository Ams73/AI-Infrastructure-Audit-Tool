"""Pseudonymize sensitive values before audit data leaves the machine.

Each distinct sensitive value is replaced with a stable placeholder such as
[HOST-1] or [IP-2], so relationships between findings survive ("the same
account appears in two checks") while the values themselves are not sent.
restore() maps placeholders in the model's answer back to the real values for
the local report.

Redacted by default: the target host name and this machine's name, IPv4/IPv6
and MAC addresses, e-mail addresses, Windows domain SIDs (the well-known RID
suffix such as -500 is kept), DOMAIN\\ prefixes of account names, user names
in home directory paths, private keys, and values of password/secret/token/key
assignments. Plain local account names (e.g. "ubuntu", "helpdesk") are not
recognizable by pattern: pass them as extra terms, or send no evidence at all.
"""
from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Pattern, Tuple

# Domains that appear in SSH algorithm names (aes128-gcm@openssh.com), not e-mail.
_NON_EMAIL_DOMAINS = {"openssh.com", "libssh.org", "ssh.com"}

_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b((?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)\w*)"
    r"(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_EMAIL = re.compile(r"\b[\w.+-]+@([\w-]+(?:\.[\w-]+)+)\b")
_DOMAIN_SID = re.compile(r"\bS-1-5-21-\d+-\d+-\d+")
_MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
# Not preceded/followed by word chars, dots or dashes, so version strings such as
# "6.18.58.1-microsoft" are left alone.
_IPV4 = re.compile(r"(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\w.-])")
_IPV6_CANDIDATE = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
# NetBIOS-style DOMAIN\ prefix at the start of a token (not a path segment).
_DOMAIN_PREFIX = re.compile(r"(?<![\\/:\w.-])([A-Z0-9][A-Z0-9-]{0,14})\\(?=[\w$])")
_LINUX_HOME = re.compile(r"(/home/)([^/\s:]+)")
_WINDOWS_HOME = re.compile(r"(?i)\b([A-Z]:\\Users\\)([^\\\s]+)")

_SKIP_HOST_TERMS = {"localhost", "127.0.0.1", "::1", ""}


class Redactor:
    def __init__(self) -> None:
        self._placeholders: Dict[Tuple[str, str], str] = {}
        self._originals: Dict[str, str] = {}
        self._counters: Dict[str, int] = {}
        self._terms: List[Tuple[Pattern[str], str]] = []

    # --- configuration -------------------------------------------------------

    def add_term(self, value: Optional[str], kind: str = "TERM") -> None:
        """Always replace this exact value (case-insensitive, whole token)."""
        value = (value or "").strip()
        if len(value) < 2 or value.lower() in _SKIP_HOST_TERMS:
            return
        pattern = re.compile(r"(?<![\w-])" + re.escape(value) + r"(?![\w-])", re.I)
        self._terms.append((pattern, kind))
        # Longest first, so "web01.corp.example" wins over "web01".
        self._terms.sort(key=lambda item: -len(item[0].pattern))

    def add_host(self, host: Optional[str]) -> None:
        host = (host or "").strip()
        self.add_term(host, "HOST")
        if "." in host and not _IPV4.fullmatch(host):
            self.add_term(host.split(".", 1)[0], "HOST")

    # --- core ------------------------------------------------------------------

    def placeholder(self, kind: str, value: str) -> str:
        key = (kind, value.lower())
        if key not in self._placeholders:
            self._counters[kind] = self._counters.get(kind, 0) + 1
            token = f"[{kind}-{self._counters[kind]}]"
            self._placeholders[key] = token
            self._originals[token] = value
        return self._placeholders[key]

    def redact(self, text: str) -> str:
        if not text:
            return text
        text = _PRIVATE_KEY.sub(lambda m: self.placeholder("PRIVATE-KEY", m.group(0)), text)
        text = _SECRET_ASSIGNMENT.sub(
            lambda m: m.group(1) + m.group(2) + self.placeholder("SECRET", m.group(3)), text
        )
        for pattern, kind in self._terms:
            text = pattern.sub(lambda m, kind=kind: self.placeholder(kind, m.group(0)), text)
        text = _EMAIL.sub(self._email, text)
        text = _DOMAIN_SID.sub(lambda m: self.placeholder("DOMAIN-SID", m.group(0)), text)
        text = _MAC.sub(lambda m: self.placeholder("MAC", m.group(0)), text)
        text = _IPV4.sub(lambda m: self.placeholder("IP", m.group(0)), text)
        text = _IPV6_CANDIDATE.sub(self._ipv6, text)
        text = _DOMAIN_PREFIX.sub(lambda m: self.placeholder("DOMAIN", m.group(1)) + "\\", text)
        text = _LINUX_HOME.sub(lambda m: m.group(1) + self.placeholder("USER", m.group(2)), text)
        text = _WINDOWS_HOME.sub(lambda m: m.group(1) + self.placeholder("USER", m.group(2)), text)
        return text

    def restore(self, text: str) -> str:
        """Replace placeholders produced by this redactor with the real values."""
        if not text or not self._originals:
            return text
        return re.sub(r"\[[A-Z-]+-\d+\]", lambda m: self._originals.get(m.group(0), m.group(0)), text)

    def restore_all(self, value):
        """restore() applied recursively to strings in dicts and lists."""
        if isinstance(value, str):
            return self.restore(value)
        if isinstance(value, list):
            return [self.restore_all(item) for item in value]
        if isinstance(value, dict):
            return {key: self.restore_all(item) for key, item in value.items()}
        return value

    @property
    def mapping_size(self) -> int:
        return len(self._originals)

    # --- pattern callbacks -------------------------------------------------------

    def _email(self, match: "re.Match[str]") -> str:
        if match.group(1).lower() in _NON_EMAIL_DOMAINS:
            return match.group(0)
        return self.placeholder("EMAIL", match.group(0))

    def _ipv6(self, match: "re.Match[str]") -> str:
        value = match.group(0)
        # Require "::" or 6+ groups, so times like 10:00:00 are left alone.
        if "::" in value or value.count(":") >= 5:
            return self.placeholder("IP", value)
        return value


# Built-in accounts and groups whose names carry meaning ("root has UID 0",
# "the built-in Administrator is enabled") and identify nobody. Kept as-is.
WELL_KNOWN_ACCOUNTS = frozenset(
    name.lower()
    for name in (
        "root", "daemon", "bin", "sys", "nobody", "sudo", "admin", "wheel", "%sudo", "%admin", "%wheel",
        "ALL", "Administrator", "Administrators", "Guest", "DefaultAccount", "WDAGUtilityAccount",
        "krbtgt", "SYSTEM", "Domain Admins", "Enterprise Admins", "Domain Users",
    )
)


def make_redactor(
    hosts: Iterable[Optional[str]] = (),
    terms: Iterable[str] = (),
    accounts: Iterable[str] = (),
) -> Redactor:
    """hosts become [HOST-n], accounts [USER-n] or [GROUP-n], terms [TERM-n]."""
    redactor = Redactor()
    for host in hosts:
        redactor.add_host(host)
    for account in accounts:
        if account and account.lower() not in WELL_KNOWN_ACCOUNTS:
            redactor.add_term(account, "GROUP" if account.startswith("%") else "USER")
    for term in terms:
        redactor.add_term(term, "TERM")
    return redactor

