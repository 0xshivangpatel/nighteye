"""Memory Anomaly Constructor.

Consumes Volatility 3 / MemProcFS / Hayabusa-Sigma evidence to surface
process-injection, in-memory PE, DLL-sideloading, and orphan-process
patterns. All triggers are dataset-agnostic — they look for OS-structural
anomalies (private-memory PE headers, DLLs loaded from user-writable
paths, etc.) rather than specific binary names.

References:
  - MITRE: T1055 Process Injection (and subtechniques),
    T1574.002 DLL Side-Loading, T1055.012 Process Hollowing.
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

__all__ = ["MemoryAnomalyConstructor"]


# ---------------------------------------------------------------------------
# Trigger evaluators — every check is name-agnostic, pattern-based
# ---------------------------------------------------------------------------

# User-writable / non-system directories where any executable code is
# inherently more suspicious than the same code in System32.
_WRITABLE_PATH_PATTERNS = re.compile(
    r"\\(?:appdata|users[\\/]+(?:public|default|all\s*users)|temp|tmp|"
    r"programdata|recycle\.?bin|perflogs|windows\\temp)\\",
    re.IGNORECASE,
)

# Paths that imply legitimate system code (used by counter signals)
_SYSTEM_PATH_PATTERNS = re.compile(
    r"\\(?:windows[\\/]+system32|windows[\\/]+syswow64|windows[\\/]+winsxs|"
    r"program\s*files(?:\s*\(x86\))?)\\",
    re.IGNORECASE,
)

_INJECTION_KEYWORDS = re.compile(
    r"\b(?:process\s+injection|process\s+hollowing|reflective\s+load|"
    r"shellcode|inject(?:ion|ed)|apc\s+injection|virtualalloc(?:ex)?|"
    r"writeprocessmemory|createremotethread)\b",
    re.IGNORECASE,
)


def _vol_plugin(event: CanonicalEvent) -> str:
    """Return the Volatility plugin name if this event is a Vol3 doc."""
    raw = event.raw_data or {}
    return (raw.get("volatility", {}) or {}).get("plugin", "") if isinstance(raw, dict) else ""


def _is_pe_in_private_memory(event: CanonicalEvent) -> bool:
    """vol3 windows.malfind reports a PE header in non-image memory."""
    if "malfind" not in _vol_plugin(event).lower():
        return False
    raw = event.raw_data or {}
    # malfind columns: Process, PID, Start VPN, End VPN, Tag, Protection,
    # CommitCharge, PrivateMemory, File output, Notes, Hexdump, Disasm
    if str((raw.get("volatility", {}) or {}).get("PrivateMemory", "1")) == "0":
        return False
    notes = str((raw.get("volatility", {}) or {}).get("Notes", "")).lower()
    # malfind always emits a PE-or-not flag in Notes; we treat any malfind
    # finding with PrivateMemory=1 as suspicious regardless of Notes —
    # private RWX with content is the anomaly.
    return True


def _is_unsigned_dll_in_writable_path(event: CanonicalEvent) -> bool:
    """vol3 windows.dlllist or canonical FILE_CREATION shows a DLL loaded
    from a user-writable directory. Generic to any DLL hijack chain."""
    raw = event.raw_data or {}
    plugin = _vol_plugin(event).lower()
    candidate_path = ""
    if "dlllist" in plugin:
        candidate_path = str((raw.get("volatility", {}) or {}).get("Path", "")
                             or (raw.get("volatility", {}) or {}).get("BaseName", ""))
    elif event.canonical_type == CanonicalType.FILE_CREATION:
        candidate_path = event.target_file or ""
    if not candidate_path or not candidate_path.lower().endswith(".dll"):
        return False
    return bool(_WRITABLE_PATH_PATTERNS.search(candidate_path))


def _is_process_no_image_path(event: CanonicalEvent) -> bool:
    """vol3 pslist returns a process with empty / missing ImageFileName.
    Pure memory-resident processes usually mean injection or process hollowing."""
    if event.canonical_type != CanonicalType.PROCESS_EXECUTION:
        return False
    plugin = _vol_plugin(event).lower()
    if "pslist" not in plugin and "pstree" not in plugin and "psscan" not in plugin:
        return False
    return not (event.process_name or event.process_path)


def _is_sigma_injection_alert(event: CanonicalEvent) -> bool:
    """Hayabusa / Chainsaw alert that fired on an injection rule."""
    if event.canonical_type != CanonicalType.ALERT:
        return False
    name = (event.alert_name or "").lower()
    return bool(_INJECTION_KEYWORDS.search(name))


def _is_writable_path_execution(event: CanonicalEvent) -> bool:
    """Any process whose executable lives in a user-writable directory."""
    if event.canonical_type != CanonicalType.PROCESS_EXECUTION:
        return False
    proc_path = (event.process_path or "").replace("/", "\\")
    if not proc_path:
        return False
    return bool(_WRITABLE_PATH_PATTERNS.search(proc_path))


# ---------------------------------------------------------------------------
# Supporting signal evaluators
# ---------------------------------------------------------------------------

def _eval_co_occurs_with_lolbin(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Within the same time window, was a LOLBin invoked? Pattern-based."""
    lolbins = {"rundll32.exe", "regsvr32.exe", "mshta.exe", "wmic.exe",
               "cmstp.exe", "installutil.exe", "msxsl.exe", "odbcconf.exe"}
    for evt in context:
        if (evt.process_name or "").lower() in lolbins:
            return True
    return False


def _eval_followed_by_network_connection(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Anomaly + outbound network within the cluster window = stronger."""
    for evt in context:
        if evt.canonical_type == CanonicalType.NETWORK_CONNECTION and evt.remote_ip:
            return True
    return False


def _eval_co_occurs_with_credential_access(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Memory anomaly near LSASS access = much stronger signal."""
    for evt in context:
        if evt.canonical_type == CanonicalType.LSASS_ACCESS:
            return True
        if evt.canonical_type == CanonicalType.ALERT and "lsass" in (evt.alert_name or "").lower():
            return True
    return False


# ---------------------------------------------------------------------------
# Counter signal evaluators
# ---------------------------------------------------------------------------

def _eval_dll_in_system_path(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """If the DLL/process path is in System32 or Program Files, the
    structural-anomaly trigger no longer applies."""
    raw = cluster.trigger_event.raw_data or {}
    candidate = (
        cluster.trigger_event.process_path or ""
    ) or str((raw.get("volatility", {}) or {}).get("Path", ""))
    if candidate and _SYSTEM_PATH_PATTERNS.search(candidate):
        return True, f"Path {candidate} is in a system-managed directory"
    return False, ""


def _eval_signed_microsoft_dll(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """If the cluster trigger is on a Microsoft-signed binary path, demote.
    Pattern-based: the path being a known Windows component is a counter."""
    raw = cluster.trigger_event.raw_data or {}
    base = str((raw.get("volatility", {}) or {}).get("BaseName", "") or "").lower()
    # Microsoft system DLLs that legitimately load from many locations.
    common_ms_dlls = {"kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll",
                      "ole32.dll", "msvcrt.dll", "shell32.dll", "rpcrt4.dll"}
    if base in common_ms_dlls:
        return True, f"DLL {base} is a known Microsoft system library"
    return False, ""


# ---------------------------------------------------------------------------
# Constructor
# ---------------------------------------------------------------------------

class MemoryAnomalyConstructor(Constructor):
    """Detects structural memory anomalies that indicate injection, sideloading
    or in-memory-only processes, regardless of binary name."""

    name = "MemoryAnomaly"
    mitre_tactic = "TA0005"  # Defense Evasion
    mitre_techniques = ["T1055", "T1055.001", "T1055.012", "T1574.002"]

    grouping_window_seconds = 1800  # 30 min
    group_by = ["host"]

    @property
    def triggers(self) -> list[TriggerRule]:
        return [
            TriggerRule("pe_header_in_private_memory", 60, _is_pe_in_private_memory),
            TriggerRule("unsigned_dll_in_writable_path", 50, _is_unsigned_dll_in_writable_path),
            TriggerRule("process_no_image_path", 55, _is_process_no_image_path),
            TriggerRule("sigma_process_injection_alert", 55, _is_sigma_injection_alert),
            TriggerRule("executable_in_writable_path", 35, _is_writable_path_execution),
        ]

    @property
    def supporting_signals(self) -> list[SignalRule]:
        return [
            SignalRule("co_occurs_with_lolbin", 12, _eval_co_occurs_with_lolbin),
            SignalRule("followed_by_network_connection", 10, _eval_followed_by_network_connection),
            SignalRule("co_occurs_with_credential_access", 15, _eval_co_occurs_with_credential_access),
        ]

    @property
    def counter_signals(self) -> list[CounterSignal]:
        return [
            CounterSignal("dll_in_system_path", 15, _eval_dll_in_system_path),
            CounterSignal("signed_microsoft_dll", 10, _eval_signed_microsoft_dll),
            CounterSignal("known_good_hash", 15, counter_known_good_hash),
            CounterSignal("system_legitimate_path", 20, counter_system_legitimate_path),
        ]

    def generate_summary(self, cluster: Cluster) -> None:
        host = cluster.trigger_event.host_name
        trig = cluster.trigger_name
        proc = cluster.trigger_event.process_name or "<no-image>"
        cluster.summary = (
            f"Memory anomaly on {host}: {trig} (proc={proc}). "
            f"Possible code injection / DLL sideloading / in-memory loader."
        )
