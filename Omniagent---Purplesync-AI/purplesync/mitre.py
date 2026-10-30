"""Small MITRE ATT&CK lookup used to annotate Red Team tests.

Technique names and IDs are public ATT&CK knowledge (enterprise matrix).
This is a curated subset for the prototype rather than the full STIX bundle.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    technique_id: str
    name: str
    tactic: str
    description: str


TECHNIQUES: dict[str, Technique] = {
    "T1566": Technique(
        "T1566",
        "Phishing",
        "Initial Access",
        "Adversary sends malicious messages to gain access via user action.",
    ),
    "T1078": Technique(
        "T1078",
        "Valid Accounts",
        "Defense Evasion / Persistence / Privilege Escalation / Initial Access",
        "Adversary uses legitimate credentials to access systems.",
    ),
    "T1059": Technique(
        "T1059",
        "Command and Scripting Interpreter",
        "Execution",
        "Adversary executes code via interpreters such as PowerShell or Bash.",
    ),
    "T1059.001": Technique(
        "T1059.001",
        "PowerShell",
        "Execution",
        "Adversary uses PowerShell to execute commands and scripts.",
    ),
    "T1046": Technique(
        "T1046",
        "Network Service Discovery",
        "Discovery",
        "Adversary attempts to identify services running on remote hosts.",
    ),
    "T1071": Technique(
        "T1071",
        "Application Layer Protocol",
        "Command and Control",
        "Adversary communicates using application-layer protocols such as HTTP.",
    ),
    "T1071.001": Technique(
        "T1071.001",
        "Web Protocols",
        "Command and Control",
        "Adversary uses HTTP/HTTPS for C2 or data transfer.",
    ),
    "T1048": Technique(
        "T1048",
        "Exfiltration Over Alternative Protocol",
        "Exfiltration",
        "Adversary exfiltrates data using a different protocol than the C2 channel.",
    ),
    "T1041": Technique(
        "T1041",
        "Exfiltration Over C2 Channel",
        "Exfiltration",
        "Adversary exfiltrates stolen data over their existing C2 channel.",
    ),
    "T1021": Technique(
        "T1021",
        "Remote Services",
        "Lateral Movement",
        "Adversary uses remote services such as RDP or SSH to move laterally.",
    ),
    "T1110": Technique(
        "T1110",
        "Brute Force",
        "Credential Access",
        "Adversary attempts to guess credentials by brute force.",
    ),
    "T1547": Technique(
        "T1547",
        "Boot or Logon Autostart Execution",
        "Persistence",
        "Adversary configures autostart mechanisms to persist.",
    ),
    "T1003": Technique(
        "T1003",
        "OS Credential Dumping",
        "Credential Access",
        "Adversary dumps credentials from the operating system.",
    ),
}

SCENARIO_ALIASES: dict[str, str] = {
    "simulated phishing": "T1566",
    "phishing": "T1566",
    "spearphishing": "T1566",
    "valid accounts": "T1078",
    "stolen credentials": "T1078",
    "powershell": "T1059.001",
    "malicious script": "T1059",
    "command interpreter": "T1059",
    "port scan": "T1046",
    "network scan": "T1046",
    "service discovery": "T1046",
    "malicious http": "T1071.001",
    "c2 over http": "T1071.001",
    "web protocols": "T1071.001",
    "exfiltration": "T1048",
    "exfiltration over c2": "T1041",
    "data exfil": "T1048",
    "rdp lateral": "T1021",
    "lateral movement": "T1021",
    "brute force": "T1110",
    "password spray": "T1110",
    "persistence": "T1547",
    "credential dump": "T1003",
    "mimikatz": "T1003",
}


def normalize_technique_id(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.strip().upper()
    if cleaned.startswith("MITRE "):
        cleaned = cleaned[6:].strip()
    if cleaned in TECHNIQUES:
        return cleaned
    parent = cleaned.split(".")[0]
    if parent in TECHNIQUES:
        return cleaned if cleaned in TECHNIQUES else parent
    return None


def lookup_technique(
    test_name: str, technique_id: str | None = None
) -> Technique | None:
    tid = normalize_technique_id(technique_id)
    if tid and tid in TECHNIQUES:
        return TECHNIQUES[tid]
    if tid:
        parent = tid.split(".")[0]
        if parent in TECHNIQUES:
            return TECHNIQUES[parent]
    haystack = (test_name or "").strip().lower()
    for alias, mapped in SCENARIO_ALIASES.items():
        if alias in haystack:
            return TECHNIQUES[mapped]
    return None
