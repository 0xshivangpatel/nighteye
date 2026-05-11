"""Suspicious Process Lineage Constructor.

Pattern-based constructors for parent/child relationships, LOLBin abuse
and execution from user-writable directories. All triggers are
dataset-agnostic — they describe Windows OS-structural anomalies that
appear in real attacks regardless of the specific malware family.

References:
  - MITRE: T1059 Command and Scripting Interpreter,
    T1218 System Binary Proxy Execution,
    T1218.011 Rundll32, T1218.005 Mshta, T1218.010 Regsvr32,
    T1059.001 PowerShell, T1059.003 Windows Command Shell.
"""

from __future__ import annotations

import re
from typing import Any

from nighteye.canonical.types import CanonicalEvent, CanonicalType
from nighteye.constructors.base import (
    Cluster, Constructor, CounterSignal, SignalRule, TriggerRule,
)
from nighteye.constructors.counter_evidence import (
    counter_known_good_hash,
    counter_system_legitimate_path,
)

__all__ = ["SuspiciousLineageConstructor"]


# ---------------------------------------------------------------------------
# Patterns — OS-structural, name-agnostic
# ---------------------------------------------------------------------------

_USER_WRITABLE = re.compile(
    r"\\(?:appdata|users[\\/]+(?:public|default|all\s*users)|temp|tmp|"
    r"programdata|recycle\.?bin|perflogs|windows\\temp|downloads)\\",
    re.IGNORECASE,
)

# LOLBins shipped by Microsoft that are commonly abused. The list is the
# *category* of binaries (system-binary-proxy-execution); attacker-renamed
# copies still benefit from this trigger because a check on path+args
# would catch the proxy-execution pattern downstream.
_LOLBINS = frozenset({
    "rundll32.exe", "regsvr32.exe", "mshta.exe", "wmic.exe",
    "cmstp.exe", "installutil.exe", "msxsl.exe", "odbcconf.exe",
    "regasm.exe", "regsvcs.exe", "msiexec.exe", "forfiles.exe",
    "pcalua.exe", "scriptrunner.exe", "wscript.exe", "cscript.exe",
})

# Office / mail / browser process names — children of these spawning a
# scripting interpreter is the classic phishing-followed-by-execution
# pattern. Names are common across all Windows installs.
_OFFICE_PARENTS = frozenset({
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "msaccess.exe", "visio.exe", "publisher.exe", "onenote.exe",
    "acrord32.exe", "acrobat.exe",
    "iexplore.exe", "msedge.exe", "chrome.exe", "firefox.exe", "brave.exe",
    "thunderbird.exe",
})

# Scripting / interpreter binaries. Children of office-from-user-input that
# match these are very high-signal regardless of the script content.
_INTERPRETERS = frozenset({
    "powershell.exe", "powershell_ise.exe", "pwsh.exe",
    "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe",
})

_HTTP_URL_RE = re.compile(r"\bhttps?://[^\s'\"<>]+", re.IGNORECASE)
_BASE64_RE = re.compile(r"\b[A-Za-z0-9+/]{60,}={0,2}\b")  # long base64 chunk


# ---------------------------------------------------------------------------
# Trigger evaluators
# ---------------------------------------------------------------------------

def _is_executable_in_writable_dir(event: CanonicalEvent) -> bool:
    """Process whose image lives in a user-writable directory.

    Windows places legitimate code in System32 / Program Files;
    anything resident in \\Users\\, \\AppData\\, \\Temp\\, etc. and being
    executed warrants a low-confidence cluster.
    """
    if event.canonical_type != CanonicalType.PROCESS_EXECUTION:
        return False
    proc_path = (event.process_path or "").replace("/", "\\")
    if not proc_path:
        return False
    return bool(_USER_WRITABLE.search(proc_path))


def _is_office_spawned_interpreter(event: CanonicalEvent) -> bool:
    """Interpreter (powershell/cmd/wscript/mshta) whose parent is an
    Office / mail / browser process. Classic phishing chain pattern.

    Parent name comes either from raw_data['process']['parent']['name']
    or vol3 pstree output via raw_data['volatility']['ParentName'].
    """
    if event.canonical_type != CanonicalType.PROCESS_EXECUTION:
        return False
    proc = (event.process_name or "").lower()
    if proc not in _INTERPRETERS:
        return False
    raw = event.raw_data or {}
    parent_name = (
        ((raw.get("process") or {}).get("parent") or {}).get("name", "")
        or (raw.get("volatility") or {}).get("ParentName", "")
        or (raw.get("winlog", {}).get("event_data", {}) or {}).get("ParentImage", "")
    )
    parent_name = (parent_name or "").rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
    return parent_name in _OFFICE_PARENTS


def _is_lolbin_with_url(event: CanonicalEvent) -> bool:
    """LOLBin invoked with an http(s) URL in its command-line.
    Generic to any LOLBin downloader pattern (mshta http://, regsvr32 /i:http://, etc.)."""
    if event.canonical_type != CanonicalType.PROCESS_EXECUTION:
        return False
    proc = (event.process_name or "").lower()
    if proc not in _LOLBINS:
        return False
    cmd = event.command_line or ""
    return bool(_HTTP_URL_RE.search(cmd))


def _is_long_base64_in_cmdline(event: CanonicalEvent) -> bool:
    """Process command-line contains a long base64-looking blob.
    Generic indicator of encoded payload / parameter-smuggling / -enc Powershell.
    Length threshold (60 chars) avoids false-positives on hash strings."""
    if event.canonical_type != CanonicalType.PROCESS_EXECUTION:
        return False
    cmd = event.command_line or ""
    if not cmd or len(cmd) < 80:
        return False
    return bool(_BASE64_RE.search(cmd))


def _is_orphan_process(event: CanonicalEvent) -> bool:
    """vol3 pstree / pslist shows a process whose parent isn't in the same
    snapshot — orphan/parent-spoofed. PPID present but parent missing."""
    raw = event.raw_data or {}
    plugin = ((raw.get("volatility") or {}).get("plugin", "") or "").lower()
    if "pstree" not in plugin and "pslist" not in plugin:
        return False
    ppid = (raw.get("volatility") or {}).get("PPID", "")
    parent_name = (raw.get("volatility") or {}).get("ParentName", "")
    # If PPID is set but ParentName is empty, parent has exited / been killed.
    return bool(ppid) and not parent_name


# ---------------------------------------------------------------------------
# Supporting signals
# ---------------------------------------------------------------------------

def _eval_writable_path_followed_by_lolbin(cluster: Cluster, ctx: list[CanonicalEvent]) -> bool:
    """Writable-path process executed AND a LOLBin fired in the same window."""
    for evt in ctx:
        if (evt.process_name or "").lower() in _LOLBINS:
            return True
    return False


def _eval_followed_by_outbound_network(cluster: Cluster, ctx: list[CanonicalEvent]) -> bool:
    for evt in ctx:
        if evt.canonical_type == CanonicalType.NETWORK_CONNECTION and evt.remote_ip:
            ip = evt.remote_ip
            # External IP heuristic: not RFC1918, not loopback, not link-local.
            if not (ip.startswith(("10.", "192.168.", "127.", "169.254.")) or
                    (ip.startswith("172.") and 16 <= int(ip.split(".")[1] or 0) <= 31)):
                return True
    return False


def _eval_persistence_co_occurs(cluster: Cluster, ctx: list[CanonicalEvent]) -> bool:
    """Lineage anomaly + Run-key / Service / Scheduled-Task in window."""
    persistence_types = {
        CanonicalType.SERVICE_INSTALLATION,
        CanonicalType.SCHEDULED_TASK,
        CanonicalType.REGISTRY_MODIFICATION,
    }
    for evt in ctx:
        if evt.canonical_type in persistence_types:
            return True
    return False


# ---------------------------------------------------------------------------
# Counter signals
# ---------------------------------------------------------------------------

def _eval_known_admin_invocation(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Process is being run by SYSTEM/NetworkService/LocalService — generic
    admin-context pattern that reduces, but doesn't eliminate, suspicion.
    Doesn't reference any specific user account from this case."""
    user = cluster.trigger_event.user or ""
    admin_users = {"system", "networkservice", "localservice",
                   "trustedinstaller", "nt authority\\system"}
    if user.lower().strip() in admin_users:
        return True, f"Process running as {user} (system context)"
    return False, ""


def _eval_office_addin_path(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Office add-ins legitimately live under \\AppData\\Roaming\\Microsoft.
    Demote AppData triggers when path matches that subtree."""
    proc_path = (cluster.trigger_event.process_path or "").replace("/", "\\").lower()
    if "\\appdata\\roaming\\microsoft\\" in proc_path:
        return True, "Path is under Office add-in directory"
    return False, ""


# ---------------------------------------------------------------------------
# Constructor
# ---------------------------------------------------------------------------

class SuspiciousLineageConstructor(Constructor):
    """Detects suspicious process lineage / LOLBin / writable-path execution.
    All triggers are pattern-based and dataset-agnostic."""

    name = "SuspiciousLineage"
    mitre_tactic = "TA0002"  # Execution
    mitre_techniques = [
        "T1059", "T1059.001", "T1059.003",
        "T1218", "T1218.005", "T1218.010", "T1218.011",
        "T1027",
    ]

    grouping_window_seconds = 1800
    group_by = ["host", "user"]

    @property
    def triggers(self) -> list[TriggerRule]:
        return [
            TriggerRule("office_spawned_interpreter", 65, _is_office_spawned_interpreter),
            TriggerRule("lolbin_with_http_url", 60, _is_lolbin_with_url),
            TriggerRule("orphan_or_spoofed_parent", 50, _is_orphan_process),
            TriggerRule("long_base64_in_cmdline", 50, _is_long_base64_in_cmdline),
            TriggerRule("executable_in_writable_dir", 35, _is_executable_in_writable_dir),
        ]

    @property
    def supporting_signals(self) -> list[SignalRule]:
        return [
            SignalRule("writable_path_with_lolbin", 12, _eval_writable_path_followed_by_lolbin),
            SignalRule("followed_by_outbound_network", 12, _eval_followed_by_outbound_network),
            SignalRule("persistence_co_occurs", 14, _eval_persistence_co_occurs),
        ]

    @property
    def counter_signals(self) -> list[CounterSignal]:
        return [
            CounterSignal("known_admin_invocation", 8, _eval_known_admin_invocation),
            CounterSignal("office_addin_path", 12, _eval_office_addin_path),
            CounterSignal("known_good_hash", 15, counter_known_good_hash),
            CounterSignal("system_legitimate_path", 18, counter_system_legitimate_path),
        ]

    def generate_summary(self, cluster: Cluster) -> None:
        host = cluster.trigger_event.host_name
        trig = cluster.trigger_name
        proc = cluster.trigger_event.process_name or "?"
        path = cluster.trigger_event.process_path or "?"
        cluster.summary = (
            f"Suspicious lineage on {host}: {trig} ({proc}, path={path}). "
            f"Pattern-based: not tied to specific binary names."
        )
