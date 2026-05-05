"""Beaconing Constructor.

Detects TA0011 (Command and Control) techniques.
Constructs behavioral clusters for C2 beaconing, DNS tunneling,
and periodic outbound communication patterns.

References:
  - CONSTRUCTORS.md § 5.6
  - MITRE: TA0011, T1071, T1090, T1571
"""

from __future__ import annotations

import statistics
from typing import Any

from nighteye.canonical.types import CanonicalEvent, CanonicalType
from nighteye.constructors.base import Cluster, Constructor, CounterSignal, SignalRule, TriggerRule
from nighteye.constructors.counter_evidence import counter_known_good_hash, counter_system_legitimate_path

__all__ = ["BeaconingConstructor"]

# ============================================================
# Trigger Evaluators
# ============================================================

def _is_periodic_outbound(event: CanonicalEvent) -> bool:
    """Check if event is a network connection that could be part of beaconing."""
    if event.canonical_type != CanonicalType.NETWORK_CONNECTION:
        return False
    # Must have remote IP and be outbound
    if not event.remote_ip or event.remote_ip in ("127.0.0.1", "::1"):
        return False
    return True

def _is_dga_dns(event: CanonicalEvent) -> bool:
    """Detect DGA-like DNS patterns."""
    if event.canonical_type != CanonicalType.ALERT:
        return False
    name = event.alert_name.lower()
    return "dga" in name or "dns tunnel" in name or "suspicious dns" in name

def _is_low_rep_destination(event: CanonicalEvent) -> bool:
    """Check if network connection goes to low-reputation destination."""
    if event.canonical_type != CanonicalType.ALERT:
        return False
    name = event.alert_name.lower()
    return "suspicious ip" in name or "malicious domain" in name or "c2" in name

def _is_cobalt_strike_pipe(event: CanonicalEvent) -> bool:
    """Detect Cobalt Strike named pipe patterns."""
    if event.canonical_type != CanonicalType.ALERT:
        return False
    name = event.alert_name.lower()
    return "cobalt strike" in name or "named pipe" in name

def _is_dns_tunnel_pattern(event: CanonicalEvent) -> bool:
    """Detect DNS tunneling via long subdomains."""
    if event.canonical_type != CanonicalType.ALERT:
        return False
    name = event.alert_name.lower()
    return "dns" in name and ("tunnel" in name or "exfil" in name)

def _is_user_agent_anomaly(event: CanonicalEvent) -> bool:
    """Detect anomalous HTTP user agents."""
    if event.canonical_type != CanonicalType.ALERT:
        return False
    name = event.alert_name.lower()
    return "user agent" in name or "user-agent" in name

def _is_non_standard_port_external(event: CanonicalEvent) -> bool:
    """Detect connections to high ports on external IPs."""
    if event.canonical_type != CanonicalType.NETWORK_CONNECTION:
        return False
    if not event.remote_port:
        return False
    # High ports (above 1024) to external
    return event.remote_port > 1024 and event.remote_ip and not _is_internal_ip(event.remote_ip)

def _is_ja3_malicious(event: CanonicalEvent) -> bool:
    """Detect known malicious JA3 TLS fingerprints."""
    if event.canonical_type != CanonicalType.ALERT:
        return False
    name = event.alert_name.lower()
    return "ja3" in name or "tls fingerprint" in name

# ============================================================
# Helpers
# ============================================================

def _is_internal_ip(ip: str) -> bool:
    """Check if IP is RFC1918 internal."""
    if not ip:
        return True
    if ip.startswith("10.") or ip.startswith("192.168."):
        return True
    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) >= 2:
            try:
                second = int(parts[1])
                if 16 <= second <= 31:
                    return True
            except ValueError:
                pass
    return ip.startswith("127.") or ip == "::1"

def _compute_jitter(timestamps: list[str]) -> float:
    """Compute coefficient of variation (stddev/mean) of intervals."""
    if len(timestamps) < 3:
        return 1.0  # High jitter = not beaconing

    # Parse timestamps and compute intervals in seconds
    from nighteye.ingest.ecs import normalize_timestamp
    from datetime import datetime

    parsed = []
    for ts in timestamps:
        norm = normalize_timestamp(ts)
        if norm:
            try:
                dt = datetime.fromisoformat(norm.replace("Z", "+00:00"))
                parsed.append(dt.timestamp())
            except (ValueError, TypeError):
                continue

    if len(parsed) < 3:
        return 1.0

    parsed.sort()
    intervals = [parsed[i+1] - parsed[i] for i in range(len(parsed)-1)]
    if not intervals:
        return 1.0

    mean_interval = statistics.mean(intervals)
    if mean_interval == 0:
        return 1.0

    try:
        stddev = statistics.stdev(intervals)
        return stddev / mean_interval
    except statistics.StatisticsError:
        return 1.0

# ============================================================
# Supporting Signal Evaluators
# ============================================================

def _eval_destination_unique_to_host(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if destination is unique to this host in the case."""
    # Would need cross-host correlation data; simplified here
    dest_ips = set()
    for evt in context:
        if evt.remote_ip and not _is_internal_ip(evt.remote_ip):
            dest_ips.add(evt.remote_ip)
    return len(dest_ips) == 1

def _eval_occurred_after_initial_access(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if beaconing started after an initial access signal."""
    for evt in context:
        if evt.canonical_type == CanonicalType.ALERT:
            name = evt.alert_name.lower()
            if "initial access" in name or "lateral movement" in name:
                return True
    return False

def _eval_persistence_present(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if persistence mechanisms exist on same host."""
    for evt in context:
        if evt.canonical_type in (CanonicalType.REGISTRY_MODIFICATION, CanonicalType.SERVICE_INSTALLATION):
            return True
    return False

def _eval_known_malicious_family(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if beacon interval matches known malware family."""
    for evt in context:
        if evt.canonical_type == CanonicalType.ALERT:
            name = evt.alert_name.lower()
            if "cobalt strike" in name or "metasploit" in name or "trickbot" in name:
                return True
    return False

# ============================================================
# Counter Signal Evaluators
# ============================================================

def _eval_destination_in_baseline(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if destination is in corporate baseline."""
    # Would query known good destinations from config
    return False, ""

def _eval_destination_is_updater(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if destination is known software updater."""
    trigger = cluster.trigger_event
    if trigger.remote_ip:
        known_updaters = ["windowsupdate.com", "update.microsoft.com", "officecdn.microsoft.com"]
        # Simplified: would do reverse DNS lookup in production
        return False, ""
    return False, ""

def _eval_legitimate_user_agent(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if user agent matches legitimate application."""
    return False, ""

# ============================================================
# Constructor
# ============================================================

class BeaconingConstructor(Constructor):
    name = "Beaconing"
    mitre_tactic = "TA0011"
    mitre_techniques = ["T1071.001", "T1071.004", "T1090", "T1095", "T1102", "T1132", "T1571", "T1572", "T1573"]

    grouping_window_seconds = 0  # Entire case - beaconing is temporal pattern
    group_by = ["source_host", "destination_ip_or_domain"]

    @property
    def triggers(self) -> list[TriggerRule]:
        return [
            TriggerRule("periodic_outbound_low_jitter", 20, _is_periodic_outbound),
            TriggerRule("dga_dns_pattern", 35, _is_dga_dns),
            TriggerRule("low_rep_destination", 25, _is_low_rep_destination),
            TriggerRule("cobalt_strike_pipe", 45, _is_cobalt_strike_pipe),
            TriggerRule("dns_tunnel_pattern", 35, _is_dns_tunnel_pattern),
            TriggerRule("user_agent_anomaly", 15, _is_user_agent_anomaly),
            TriggerRule("non_standard_port_external", 20, _is_non_standard_port_external),
            TriggerRule("ja3_known_malicious", 30, _is_ja3_malicious),
        ]

    @property
    def supporting_signals(self) -> list[SignalRule]:
        return [
            SignalRule("destination_unique_to_one_host", 10, _eval_destination_unique_to_host),
            SignalRule("occurred_after_initial_access", 12, _eval_occurred_after_initial_access),
            SignalRule("persistence_present_on_same_host", 12, _eval_persistence_present),
            SignalRule("beacon_interval_known_malicious_family", 14, _eval_known_malicious_family),
        ]

    @property
    def counter_signals(self) -> list[CounterSignal]:
        return [
            CounterSignal("destination_in_corporate_baseline", 15, _eval_destination_in_baseline),
            CounterSignal("destination_is_software_updater", 12, _eval_destination_is_updater),
            CounterSignal("user_agent_matches_legitimate_app", 10, _eval_legitimate_user_agent),
            CounterSignal("known_good_hash", 15, counter_known_good_hash),
            CounterSignal("system_legitimate_path", 20, counter_system_legitimate_path),
        ]

    def generate_summary(self, cluster: Cluster) -> None:
        host = cluster.trigger_event.host_name
        trigger = cluster.trigger_name
        dest = cluster.trigger_event.remote_ip or "unknown"
        cluster.summary = f"Beaconing/C2 detected on {host}: {trigger} to {dest}. Possible command and control channel."
