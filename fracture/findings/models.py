import math
from dataclasses import dataclass, field
from datetime import datetime
import uuid

VULN_TYPES = [
    "SQL Injection", "XSS - Reflected", "XSS - Stored", "XSS - DOM",
    "LFI", "RFI", "RCE", "Command Injection", "IDOR", "SSRF", "XXE",
    "Path Traversal", "Authentication Bypass", "Privilege Escalation",
    "Broken Access Control", "CSRF", "Open Redirect", "Information Disclosure",
    "Weak Credentials", "Buffer Overflow", "Deserialization", "Other",
]

SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]

PHASES = [
    "Reconnaissance", "Scanning", "Enumeration", "Exploitation",
    "Post-Exploitation", "Privilege Escalation", "Lateral Movement",
    "Persistence", "Exfiltration", "Reporting",
]

STATUSES = ["Open", "Verified", "Reported", "Fixed", "False Positive"]

SEVERITY_COLORS = {
    "Critical": "#ff4444",
    "High": "#ff8800",
    "Medium": "#ffcc00",
    "Low": "#44cc44",
    "Informational": "#8888ff",
}

CVSS_RANGES = {
    "Critical": "9.0 – 10.0",
    "High": "7.0 – 8.9",
    "Medium": "4.0 – 6.9",
    "Low": "0.1 – 3.9",
    "Informational": "0.0",
}

REMEDIATION = {
    "SQL Injection": "Use parameterized queries and prepared statements. Never concatenate user input into SQL strings. Apply input validation and least-privilege DB accounts.",
    "XSS - Reflected": "Escape all output. Implement a strict Content Security Policy. Validate and sanitize inputs server-side.",
    "XSS - Stored": "Sanitize data on write and escape on render. Implement CSP. Use HTTPOnly cookies.",
    "XSS - DOM": "Avoid innerHTML. Use textContent or createElement. Sanitize before any DOM insertion.",
    "LFI": "Whitelist allowed file paths. Never pass raw user input to include/require functions. Chroot or containerize where possible.",
    "RFI": "Disable remote includes in server configuration. Whitelist allowed file sources.",
    "RCE": "Never pass user input to shell commands. Use subprocess with argument lists, not shell=True. Containerize services.",
    "Command Injection": "Use parameterized system calls. Whitelist allowed commands. Escape shell metacharacters.",
    "IDOR": "Implement server-side authorization on every resource access. Use indirect object references (GUIDs over sequential IDs).",
    "SSRF": "Whitelist allowed outbound destinations. Block internal IP ranges at the network layer. Validate and sanitize URLs.",
    "XXE": "Disable external entity processing in XML parsers. Use JSON where possible.",
    "Path Traversal": "Normalize and validate paths. Chroot services. Never use raw user input in file path construction.",
    "Authentication Bypass": "Audit authentication logic for edge cases. Enforce MFA. Use well-tested auth libraries.",
    "Privilege Escalation": "Audit SUID/GUID binaries, cron jobs, and writable paths. Apply principle of least privilege.",
    "Broken Access Control": "Implement server-side access control checks on every request. Use RBAC. Deny by default.",
    "CSRF": "Implement CSRF tokens on all state-changing requests. Use SameSite cookie attribute.",
    "Open Redirect": "Whitelist allowed redirect destinations. Validate redirect URLs against a known-safe list.",
    "Information Disclosure": "Remove verbose error messages. Restrict access to sensitive files. Review HTTP response headers.",
    "Weak Credentials": "Enforce strong password policies. Implement account lockout. Require MFA.",
    "Buffer Overflow": "Use memory-safe languages. Enable ASLR, DEP, stack canaries. Audit with static analysis tools.",
    "Deserialization": "Validate and sign serialized data. Avoid deserializing untrusted input. Use allowlists.",
    "Other": "Review applicable security best practices and OWASP guidance for this vulnerability type.",
}

# ---------------------------------------------------------------------------
# CVSS v3.1 calculator
# ---------------------------------------------------------------------------

CVSS_METRICS = {
    "Attack Vector":        {"Network": 0.85, "Adjacent": 0.62, "Local": 0.55, "Physical": 0.20},
    "Attack Complexity":    {"Low": 0.77, "High": 0.44},
    "User Interaction":     {"None": 0.85, "Required": 0.62},
    "Scope":                {"Unchanged": "U", "Changed": "C"},
    "Confidentiality":      {"None": 0.00, "Low": 0.22, "High": 0.56},
    "Integrity":            {"None": 0.00, "Low": 0.22, "High": 0.56},
    "Availability":         {"None": 0.00, "Low": 0.22, "High": 0.56},
    # Privileges Required weights depend on Scope
    "Privileges Required":  {
        "None":  {"U": 0.85, "C": 0.85},
        "Low":   {"U": 0.62, "C": 0.68},
        "High":  {"U": 0.27, "C": 0.50},
    },
}

CVSS_DEFAULTS = {
    "Attack Vector": "Network",
    "Attack Complexity": "Low",
    "Privileges Required": "None",
    "User Interaction": "None",
    "Scope": "Unchanged",
    "Confidentiality": "None",
    "Integrity": "None",
    "Availability": "None",
}


def _roundup(val: float) -> float:
    return math.ceil(val * 10) / 10


def calculate_cvss(
    attack_vector: str,
    attack_complexity: str,
    privileges_required: str,
    user_interaction: str,
    scope: str,
    confidentiality: str,
    integrity: str,
    availability: str,
) -> tuple[float, str]:
    """Return (score, severity_label) for CVSS v3.1 base score."""
    scope_key = CVSS_METRICS["Scope"][scope]

    av  = CVSS_METRICS["Attack Vector"][attack_vector]
    ac  = CVSS_METRICS["Attack Complexity"][attack_complexity]
    pr  = CVSS_METRICS["Privileges Required"][privileges_required][scope_key]
    ui  = CVSS_METRICS["User Interaction"][user_interaction]
    isc = CVSS_METRICS["Confidentiality"][confidentiality]
    isi = CVSS_METRICS["Integrity"][integrity]
    isa = CVSS_METRICS["Availability"][availability]

    isc_base = 1 - (1 - isc) * (1 - isi) * (1 - isa)

    if scope_key == "U":
        impact = 6.42 * isc_base
    else:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        score = 0.0
    elif scope_key == "U":
        score = _roundup(min(impact + exploitability, 10))
    else:
        score = _roundup(min(1.08 * (impact + exploitability), 10))

    if score == 0.0:
        label = "None"
    elif score < 4.0:
        label = "Low"
    elif score < 7.0:
        label = "Medium"
    elif score < 9.0:
        label = "High"
    else:
        label = "Critical"

    av_abbr  = attack_vector[0]
    ac_abbr  = attack_complexity[0]
    pr_abbr  = privileges_required[0]
    ui_abbr  = user_interaction[0]
    sc_abbr  = scope_key
    c_abbr   = confidentiality[0]
    i_abbr   = integrity[0]
    a_abbr   = availability[0]
    vector = f"CVSS:3.1/AV:{av_abbr}/AC:{ac_abbr}/PR:{pr_abbr}/UI:{ui_abbr}/S:{sc_abbr}/C:{c_abbr}/I:{i_abbr}/A:{a_abbr}"

    return round(score, 1), label, vector


@dataclass
class Finding:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    vuln_type: str = "SQL Injection"
    target: str = ""
    severity: str = "Medium"
    phase: str = "Exploitation"
    status: str = "Open"
    payload: str = ""
    request_raw: str = ""
    response_raw: str = ""
    accessed: str = ""
    notes: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    images: list = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def display_name(self) -> str:
        target = self.target or "unknown target"
        return f"{self.vuln_type} — {target}"

    def short_name(self) -> str:
        target = self.target[:28] + "…" if len(self.target) > 28 else self.target
        return f"{self.vuln_type}\n{target or 'no target'}"


@dataclass
class Session:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = "New Engagement"
    target_host: str = ""
    exec_summary: str = ""
    recon_notes: str = ""
    important_notes: str = ""
    findings: list = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
