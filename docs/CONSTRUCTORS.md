# NightEye — Behavior Constructor Specifications

This document specifies all 12 behavior constructors that run at ingest
time over the canonical event index. Each constructor produces clusters
with permissive triggers, supporting/counter signals, and graded
confidence.

> **Critical principle:** the agent never reads raw EVTX, raw MFT, or raw
> registry hives. The agent reads clusters. Cluster correctness is
> therefore load-bearing. Permissive triggers ensure novel attacker
> variants surface; graded confidence + counter-evidence ensures noise
> doesn't drown signal.

---

## Table of contents

1. [Constructor framework](#1-constructor-framework)
2. [Output schema](#2-output-schema)
3. [Strength tiers and visibility](#3-strength-tiers-and-visibility)
4. [Counter-evidence pre-computation](#4-counter-evidence-pre-computation)
5. [Constructor specifications](#5-constructor-specifications)
   - [5.1 LateralMovementConstructor](#51-lateralmovementconstructor)
   - [5.2 PersistenceConstructor](#52-persistenceconstructor)
   - [5.3 CredentialAccessConstructor](#53-credentialaccessconstructor)
   - [5.4 RemoteExecutionConstructor](#54-remoteexecutionconstructor)
   - [5.5 DefenseEvasionConstructor](#55-defenseevasionconstructor)
   - [5.6 BeaconingConstructor](#56-beaconingconstructor)
   - [5.7 CollectionConstructor](#57-collectionconstructor)
   - [5.8 ExfiltrationConstructor](#58-exfiltrationconstructor)
   - [5.9 ImpactConstructor](#59-impactconstructor)
   - [5.10 LogClearingConstructor](#510-logclearingconstructor)
   - [5.11 TimestompConstructor](#511-timestompconstructor)
   - [5.12 ShadowDeletionConstructor](#512-shadowdeletionconstructor)
6. [Implementation notes](#6-implementation-notes)
7. [Build order](#7-build-order)

---

## 1. Constructor framework

Every constructor is a Python class implementing the same interface:

```python
class Constructor:
    name: str                      # e.g. "LateralMovement"
    cluster_type: str              # written to clusters.cluster_type
    mitre_tactic: str              # MITRE tactic ID
    technique_ids: list[str]       # MITRE technique IDs covered

    triggers: list[TriggerRule]    # ANY one fires the cluster
    supporting: list[SignalRule]   # additive contributions
    counter: list[SignalRule]      # subtractive contributions

    scoring: ScoringConfig

    def run(self, case_id, canonical_index) -> list[Cluster]:
        """
        Scan canonical events for triggers.
        Group hits by host + time window.
        For each group: score, attach supporting, attach counter.
        Emit one Cluster per group.
        """
```

### Trigger rule structure

```python
@dataclass
class TriggerRule:
    name: str                            # human-readable
    canonical_type: str                  # canonical event type
    field_filters: dict[str, Any]        # field=value or field=callable
    custom_check: Optional[Callable]     # for complex multi-event patterns
    weight: int = 30                     # base score on trigger fire
```

### Signal rule structure

```python
@dataclass
class SignalRule:
    name: str
    description: str
    check: Callable[[ClusterContext], bool]   # returns True if signal applies
    weight: int                                # signed; negative for counter
```

### Scoring configuration

```python
@dataclass
class ScoringConfig:
    base_on_trigger: int = 30
    cap: int = 95
    floor: int = 0
    # tier thresholds
    strong_threshold: int = 70
    moderate_threshold: int = 40
    weak_threshold: int = 20
    # below weak_threshold = NOISE, never surfaced
```

### Cluster grouping rules

After triggers fire, candidates are grouped into clusters by:

- Same `host` (always)
- Time window: configurable per constructor (default 5 minutes)
- Same `user` (where applicable, default true)
- Same `process tree root` (where applicable)

Multiple triggers within the same group produce one cluster, not many.
The cluster records all firing triggers.

---

## 2. Output schema

Each cluster row in SQLite (`clusters` table) and OpenSearch index
(`case-X-clusters`) carries:

```json
{
  "cluster_id": "cluster-shivang-LM-001",
  "case_id": "INC-2026-001",
  "cluster_type": "LateralMovement",
  "strength": "STRONG",
  "score": 78,
  "triggers_fired": [
    "network_logon_type3_from_internal_non_baseline",
    "service_install_within_60s_of_remote_auth"
  ],
  "supporting_signals": [
    "admin_share_write_within_60s",
    "cross_host_signal_repetition"
  ],
  "counter_signals": [],
  "contradicting_clusters": [],
  "member_canonical_ids": [
    "canon-DC01-20260429T142307-001",
    "canon-DC01-20260429T142312-002",
    "canon-DC01-20260429T142315-003"
  ],
  "primary_host": "DC01",
  "primary_user": "stark\\admin",
  "secondary_hosts": ["WKSTN-01"],
  "time_start": "2026-04-29T14:23:07Z",
  "time_end":   "2026-04-29T14:24:11Z",
  "technique_ids": ["T1021.002"],
  "mitre_tactic": "TA0008",
  "summary": "Lateral movement from WKSTN-01 to DC01: network logon (type 3) by stark\\admin, followed by SCM service install of unsigned binary, with admin share write 8s prior.",
  "created_at": "2026-04-29T14:24:30Z"
}
```

### Counter-evidence in detail

Counter-evidence is stored as a list of objects, not just signal names,
so the agent can read context without expanding canonical events:

```json
"counter_evidence_details": [
  {
    "signal": "service_binary_signed_microsoft",
    "applies": false,
    "evidence": "binary unsigned (no AuthentiCode signature found)"
  },
  {
    "signal": "source_host_baseline_matched_admin_workstation",
    "applies": false,
    "evidence": "WKSTN-01 not in admin baseline; user 'stark\\admin' last logon was 30 days ago"
  },
  {
    "signal": "within_documented_maintenance_window",
    "applies": false,
    "evidence": "no maintenance window configured"
  }
]
```

When `applies: true`, the signal subtracts from score. When `false`,
it's recorded for transparency (the agent sees that the constructor
checked legitimacy and didn't find it).

---

## 3. Strength tiers and visibility

| Score | Tier | Default agent visibility |
|---|---|---|
| 70-95 | STRONG | Always surfaced via `triage_clusters()` |
| 40-69 | MODERATE | Always surfaced via `triage_clusters()` |
| 20-39 | WEAK | Hidden by default; agent requests via `query_clusters(min_strength="weak")` |
| 0-19 | NOISE | Never auto-surfaced; available in audit only |

Rationale: a single trigger creates a low-confidence cluster (~30
score = WEAK). It's preserved (so novel single-vector attacks aren't
lost) but doesn't flood the agent. Agents investigating a rich target
host can pull WEAK clusters explicitly. Multiple triggers + supporting
signals push past 40 (MODERATE) and the cluster surfaces by default.

---

## 4. Counter-evidence pre-computation

For every cluster created, the constructor runs the counter checks
inline and attaches results. This is the **substrate for
self-correction without branching**.

The agent's `challenge_hypothesis` reads counter-evidence from the
cluster the hypothesis came from. No second-pass adversarial query.
No context explosion.

Counter checks are kept cheap (single OpenSearch query each, or simple
table lookup) so adding 4-6 per cluster type costs <500ms per cluster.

---

## 5. Constructor specifications

> Notation: `T1234` = MITRE ATT&CK technique. Each constructor docstring
> in code MUST cite its sources (Sigma rule IDs, DFIR Report URLs, MITRE
> pages).

---

### 5.1 LateralMovementConstructor

**MITRE tactic:** TA0008
**Techniques:** T1021.001 (RDP), T1021.002 (SMB Admin Shares),
T1021.003 (DCOM), T1021.006 (WinRM), T1210, T1534, T1550.002 (PtH),
T1563, T1570

**Time window:** 5 minutes
**Grouping:** by (source_host, destination_host)

#### Triggers (any one fires)

| Trigger | Canonical type | Filters |
|---|---|---|
| network_logon_type3_from_internal_non_baseline | AUTHENTICATION | logon_type=3, src_ip internal, src≠dst, user not machine account |
| rdp_logon_type10_from_non_baseline | AUTHENTICATION | logon_type=10, src not in baseline RDP sources |
| service_install_following_remote_auth | SERVICE_INSTALL | within 60s of preceding AUTHENTICATION on same host |
| admin_share_access_non_baseline | FILE_WRITE | share=ADMIN$/C$/IPC$, user not in baseline admins |
| sigma_lateral_movement_match | (any) | Hayabusa/Chainsaw rule with tag attack.lateral_movement fired |
| wmi_event_subscription_remote | WMI_SUBSCRIPTION | (any) |
| cobalt_strike_named_pipe | (any) | pipe name matches \msagent_*, \postex_*, \status_*, \MSSE-* |
| service_spawned_process_unusual | PROCESS_EXECUTION | parent_image=services.exe, image_path in user-writable location |
| psexec_pattern | SERVICE_INSTALL | binary path matches PsExec service patterns OR random-named svc binary in admin share |

#### Supporting signals (each adds +12)

| Signal | Description |
|---|---|
| admin_share_write_within_60s | Admin share write preceded service install |
| service_install_following_remote_auth_within_60s | Service install in same window as remote auth |
| cross_host_signal_repetition | Same primary user/binary appears on multiple hosts in case |
| destination_host_is_high_value_asset | DC, file server, mail server |
| off_hours_timestamp | Outside 09-17 local time |
| process_tree_originated_remote | Process tree root traces back to remote source |
| destination_account_is_privileged | User has admin/domain admin SID |

#### Counter signals (each subtracts -10)

| Signal | Check |
|---|---|
| source_host_baseline_matched_admin_workstation | Source IP in known admin workstation list |
| destination_account_is_documented_service_account | User in documented service account list |
| service_binary_signed_microsoft | Service binary has valid Microsoft AuthentiCode signature |
| within_documented_maintenance_window | Falls inside configured maintenance window |
| matched_gpo_push_pattern | Matches known GPO push timing/source pattern |
| logon_outcome_failure | event.outcome=failure (not actual movement) |

#### Sources

- MITRE T1021 family
- Sigma `category: lateral_movement`
- Microsoft 4624 LogonType reference
- The DFIR Report PsExec writeups
- Atomic Red Team T1021.002 atomics
- Cobalt Strike named pipe references

---

### 5.2 PersistenceConstructor

**MITRE tactic:** TA0003
**Techniques:** T1547.001 (Run), T1543.003 (Service), T1053.005
(Scheduled Task), T1546.003 (WMI), T1547.009 (Shortcut), T1574.001 (DLL
search order), T1546.007 (Netsh helper), T1546.008 (Accessibility),
T1136 (Create Account), T1574.011 (IFEO Debugger)

**Time window:** entire case (persistence is point-in-time)
**Grouping:** by host

#### Triggers (any one fires)

| Trigger | Canonical type | Filters |
|---|---|---|
| registry_run_key_added | REGISTRY_MODIFY | key matches Run/RunOnce/RunOnceEx, last_write recent |
| service_install_persistent | SERVICE_INSTALL | start_type in [auto, demand], binary not in baseline |
| scheduled_task_created | SCHEDULED_TASK_CREATE | (any) |
| wmi_persistent_subscription | WMI_SUBSCRIPTION | persistent flag |
| startup_folder_item_added | FILE_WRITE | path matches Startup folder |
| ifeo_debugger_set | REGISTRY_MODIFY | path matches IFEO\<image>\Debugger |
| appinit_dlls_modified | REGISTRY_MODIFY | AppInit_DLLs value non-empty |
| accessibility_binary_replaced | FILE_WRITE | sethc.exe / utilman.exe / osk.exe replaced |
| dll_search_order_hijack | FILE_WRITE | hijackable DLL name in unexpected location |
| sigma_persistence_match | (any) | Sigma tag attack.persistence |

#### Supporting signals

| Signal | +Weight |
|---|---|
| binary_unsigned | +12 |
| binary_path_user_writable | +12 |
| recent_addition | +10 (within case time window) |
| binary_not_in_baseline | +12 |
| binary_path_unusual | +10 (Temp, AppData, ProgramData) |
| service_runs_as_localsystem | +8 |

#### Counter signals

| Signal | -Weight |
|---|---|
| binary_signed_microsoft | -12 |
| binary_in_known_software_baseline | -12 |
| matched_msi_install_pattern | -10 |
| within_patch_install_window | -10 |
| key_path_known_legitimate | -8 |

#### Sources

- MITRE T1547, T1543, T1053, T1546, T1574
- Sigma `category: persistence`
- Sysinternals Autoruns documentation
- The DFIR Report persistence catalog

---

### 5.3 CredentialAccessConstructor

**MITRE tactic:** TA0006
**Techniques:** T1003 (and sub), T1110, T1555, T1556, T1558, T1212

**Time window:** 5 minutes
**Grouping:** by host + user

#### Triggers (any one fires)

| Trigger | Filters |
|---|---|
| lsass_access_dump_pattern | LSASS_ACCESS with GrantedAccess in {0x1010, 0x1410, 0x1438, 0x143A, 0x1FFFFF} |
| sigma_credential_access_match | Sigma tag attack.credential_access |
| kerberoasting_pattern | TICKET_REQUEST with EncryptionType=0x17 (RC4) for service accounts |
| dcsync_pattern | REPLICATION with replication GUID, source not DC machine account |
| ntds_dit_access | FILE_READ on \Windows\NTDS\NTDS.dit |
| sam_security_hive_copy | FILE_READ or FILE_WRITE on SAM/SECURITY/SYSTEM hive copies in unusual paths |
| browser_credential_file_access | FILE_READ on Login Data / key4.db / Cookies, by non-browser process |
| brute_force_4625_spike | AUTHENTICATION failures >10 in 60s for single account or single source |
| mimikatz_yara_hit | YARA scan match on memory or disk |
| nanodump_lsassy_yara_hit | YARA match for known dumping tools |

#### Supporting signals

| Signal | +Weight |
|---|---|
| dumping_tool_in_process_tree | +14 |
| privileged_user_targeted | +12 |
| memory_dump_file_created | +12 (suspicious .dmp, lsass.dmp, etc.) |
| occurred_after_lateral_movement | +10 |
| occurred_on_dc | +10 |
| followed_by_pass_the_hash | +12 |

#### Counter signals

| Signal | -Weight |
|---|---|
| accessing_process_is_defender | -15 (legitimate AV scanning LSASS) |
| accessing_process_is_sysmon | -15 |
| matched_known_av_or_edr_signature | -12 |
| audit_legitimate_use_window | -10 |

#### Sources

- MITRE T1003 + sub-techniques
- Sigma `category: credential_access`
- The DFIR Report credential dumping case studies
- Atomic Red Team T1003 atomics

---

### 5.4 RemoteExecutionConstructor

**MITRE tactic:** TA0002 + TA0008
**Techniques:** T1059.x, T1106, T1218, T1569, T1021

**Time window:** 5 minutes
**Grouping:** by host + process tree root

#### Triggers (any one fires)

| Trigger | Filters |
|---|---|
| encoded_powershell | PROCESS_EXECUTION cmdline matches -enc/-EncodedCommand with base64 >100 chars |
| lolbin_unusual_parent | PROCESS_EXECUTION image in LOLBAS list, parent not typical |
| office_spawning_shell | parent winword.exe/excel.exe/powerpnt.exe, child cmd.exe/powershell.exe |
| svchost_spawning_shell | parent svchost.exe, child cmd.exe/powershell.exe (rare) |
| services_spawning_unsigned | parent services.exe, child unsigned image |
| wmi_remote_exec | parent WmiPrvSE.exe, child cmd/powershell |
| rundll32_unusual_args | rundll32.exe with non-standard DLL function |
| mshta_unusual_url | mshta.exe loading remote URL |
| sigma_execution_match | Sigma tag attack.execution |
| script_block_obfuscation | EVTX 4104 ScriptBlockText matches obfuscation patterns |

#### Supporting signals

| Signal | +Weight |
|---|---|
| binary_unsigned | +10 |
| binary_in_temp_path | +12 |
| process_terminated_quickly | +8 (live-off-the-land cleanup) |
| network_connection_after_execution | +12 |
| occurred_after_initial_access_signal | +10 |

#### Counter signals

| Signal | -Weight |
|---|---|
| binary_signed_microsoft | -12 |
| within_known_admin_script_pattern | -10 |
| parent_is_documented_admin_tool | -10 |
| matched_known_software_install | -8 |

---

### 5.5 DefenseEvasionConstructor

**MITRE tactic:** TA0005
**Techniques:** T1027, T1055, T1140, T1218, T1562

**Time window:** 5 minutes
**Grouping:** by host

#### Triggers

| Trigger | Filters |
|---|---|
| obfuscated_powershell | encoded/compressed PS detected |
| process_injection_indicator | PROCESS_INJECTION canonical event (Sysmon 8/25, Vol3 malfind) |
| defender_disabled | EVTX 5001/5007 (Defender disabled or settings changed) |
| defender_exclusion_added | DEFENDER_EXCLUSION_ADDED canonical event |
| sigma_defense_evasion_match | Sigma tag attack.defense_evasion |
| unsigned_binary_in_signed_process_path | binary path mimics signed binary path |
| process_doppelganging_indicator | Vol3 malfind shows hollowed process |
| signed_binary_proxy_lolbin | LOLBin used in suspicious context |

#### Supporting signals

| Signal | +Weight |
|---|---|
| disabled_defender_then_executed | +14 |
| evasion_followed_by_persistence | +12 |
| occurred_during_anti_forensic_window | +10 |

#### Counter signals

| Signal | -Weight |
|---|---|
| matched_known_admin_powershell | -10 |
| within_av_update_window | -10 |
| matched_documented_software_pattern | -8 |

---

### 5.6 BeaconingConstructor

**MITRE tactic:** TA0011
**Techniques:** T1071.001 (Web), T1071.004 (DNS), T1090, T1095, T1102,
T1132, T1571, T1572, T1573

**Time window:** entire case (beacons are temporal patterns)
**Grouping:** by (source_host, destination_ip_or_domain)

#### Triggers

| Trigger | Filters |
|---|---|
| periodic_outbound_low_jitter | NETWORK_CONNECTION pairs with std-dev/mean <0.25 across >10 connections |
| dga_dns_pattern | DNS_QUERY with high entropy domain or many failed similar resolutions |
| low_rep_destination | NETWORK_CONNECTION to IP/domain in low-rep intel feed |
| cobalt_strike_pipe | named pipe matching CS patterns (also fires LM, both clusters created) |
| dns_tunnel_pattern | DNS_QUERY with long subdomains, base32/base64 labels |
| user_agent_anomaly | HTTP user-agent not in baseline |
| non_standard_port_external | NETWORK_CONNECTION to high port external, repeated |
| ja3_known_malicious | TLS fingerprint match in intel |

#### Supporting signals

| Signal | +Weight |
|---|---|
| destination_unique_to_one_host | +10 |
| occurred_after_initial_access | +12 |
| persistence_present_on_same_host | +12 |
| beacon_interval_known_malicious_family | +14 |

#### Counter signals

| Signal | -Weight |
|---|---|
| destination_in_corporate_baseline | -15 |
| destination_is_software_updater | -12 |
| user_agent_matches_legitimate_app | -10 |

---

### 5.7 CollectionConstructor

**MITRE tactic:** TA0009
**Techniques:** T1005, T1039, T1056, T1074, T1113, T1115, T1119, T1213

**Time window:** 30 minutes (collection is bursty)
**Grouping:** by host + user

#### Triggers

| Trigger | Filters |
|---|---|
| mass_file_enumeration | FILE_READ events >100 in 60s by same process |
| archive_creation_unusual_path | FILE_WRITE with .zip/.rar/.7z in non-typical paths |
| password_grep_pattern | PROCESS_EXECUTION cmdline matches findstr/Get-ChildItem -Recurse with password/credential patterns |
| document_recursive_enumeration | FILE_READ recursive with doc/xls/pdf extensions |
| screenshot_or_clipboard_yara | YARA hit for keylog/clipboard/screenshot libraries |
| outlook_pst_access_unusual | PST file accessed by non-outlook process |

#### Supporting signals

| Signal | +Weight |
|---|---|
| occurred_after_lateral_movement | +12 |
| files_from_high_value_paths | +10 (financial, HR, code repos) |
| encrypted_archive_creation | +12 (-p flag, -hp flag) |
| occurred_outside_business_hours | +8 |

#### Counter signals

| Signal | -Weight |
|---|---|
| matched_backup_software_pattern | -12 |
| within_indexing_service_pattern | -10 |
| user_documented_data_owner | -8 |

---

### 5.8 ExfiltrationConstructor

**MITRE tactic:** TA0010
**Techniques:** T1041, T1048, T1052, T1567, T1029

**Time window:** 30 minutes
**Grouping:** by host + destination

#### Triggers

| Trigger | Filters |
|---|---|
| large_outbound_to_external | NETWORK_CONNECTION orig_bytes > case-adaptive threshold to external |
| cloud_uploader_process | PROCESS_EXECUTION image in [rclone, MEGAcmd, dropbox, OneDrive] in unusual context |
| dns_tunnel_high_volume | DNS_QUERY count >500 to single domain in 60s |
| smtp_to_non_corporate | NETWORK_CONNECTION port 25/465/587 to non-corporate mail server |
| encrypted_archive_followed_by_upload | archive create → HTTPS to external in same 5min |

#### Supporting signals

| Signal | +Weight |
|---|---|
| occurred_after_collection_cluster | +14 |
| destination_first_seen_in_case | +10 |
| outside_business_hours | +8 |
| unusual_protocol_for_volume | +10 (e.g., DNS for MB-scale data) |

#### Counter signals

| Signal | -Weight |
|---|---|
| destination_corporate_cloud_baseline | -15 |
| matched_backup_destination | -12 |

---

### 5.9 ImpactConstructor

**MITRE tactic:** TA0040
**Techniques:** T1485, T1486, T1489, T1490, T1491, T1565

**Time window:** 30 minutes
**Grouping:** by host

#### Triggers

| Trigger | Filters |
|---|---|
| mass_file_modification | FILE_WRITE events >100/min |
| ransomware_extension_pattern | FILE_WRITE with extensions in known ransomware list |
| shadow_copy_deletion | SHADOW_DELETED canonical event (shared with anti-forensic) |
| backup_destruction | PROCESS_EXECUTION cmdline matches wbadmin/bcdedit destructive |
| ransom_note_pattern | FILE_WRITE with names like README*.txt, HOW_TO_DECRYPT*, _readme.txt across many dirs |
| mass_service_stop | EVTX 7036 stops for SQL/Exchange/backup/AV in clustered window |
| mass_account_lockout | AUTHENTICATION lockouts >10 accounts in 5min |

#### Supporting signals

| Signal | +Weight |
|---|---|
| occurred_after_credential_access | +12 |
| affected_dc_or_file_server | +14 |
| persistence_destruction_pattern | +10 |
| anti_forensic_co_occurrence | +12 |

#### Counter signals

| Signal | -Weight |
|---|---|
| matched_documented_decommission | -15 |
| within_av_quarantine_pattern | -12 |
| matched_known_software_uninstall | -10 |

---

### 5.10 LogClearingConstructor (anti-forensic)

**MITRE tactic:** TA0005
**Techniques:** T1070.001

**Time window:** instantaneous
**Grouping:** by host

**Side effect:** registers `evidence_disturbance` row spanning ±15
minutes around each detection. Hypotheses near these windows receive
automatic confidence penalty.

#### Triggers

| Trigger | Filters |
|---|---|
| evtx_1102_clear | LOG_CLEARED canonical event (EVTX 1102) |
| evtx_104_alt_clear | LOG_CLEARED via alternative mechanism (EVTX 104) |
| recordid_gap | EVTX RecordID sequence gap >50 within single channel |
| evtx_truncated | EVTX file size <10% of expected baseline for channel/host |

#### Supporting signals

| Signal | +Weight |
|---|---|
| cleared_by_non_admin | +14 |
| occurred_during_other_attack_signals | +12 |
| multiple_logs_cleared_same_window | +14 |

#### Counter signals

| Signal | -Weight |
|---|---|
| within_log_rotation_pattern | -15 |
| performed_by_documented_admin | -10 |

---

### 5.11 TimestompConstructor (anti-forensic)

**MITRE tactic:** TA0005
**Techniques:** T1070.006

**Time window:** instantaneous
**Grouping:** by host + file

**Side effect:** marks affected files with `evidence_disturbed=true` in
graph; cluster registers disturbance.

#### Triggers

| Trigger | Filters |
|---|---|
| si_fn_timestamp_mismatch | $MFT $STANDARD_INFORMATION timestamps differ from $FILE_NAME by >5 min |
| si_before_fn | $STANDARD_INFORMATION timestamps earlier than $FILE_NAME (impossible without manipulation) |
| rounded_second_timestamps | timestamps with .0000000 ticks (legitimate ones are usually millisecond-precise) |
| backdated_file | created_ts before OS install date |

#### Supporting signals

| Signal | +Weight |
|---|---|
| affected_file_in_persistence_path | +14 |
| affected_file_unsigned | +10 |
| affected_file_in_system32 | +12 |
| occurred_with_other_attack_signals | +10 |

#### Counter signals

| Signal | -Weight |
|---|---|
| matched_known_installer_behavior | -12 |
| within_file_restore_window | -10 |

---

### 5.12 ShadowDeletionConstructor (anti-forensic)

**MITRE tactic:** TA0040 + TA0005
**Techniques:** T1490

**Time window:** instantaneous
**Grouping:** by host

**Side effect:** registers disturbance ±30 minutes (deletion is
preparatory).

#### Triggers

| Trigger | Filters |
|---|---|
| vssadmin_delete_shadows | PROCESS_EXECUTION cmdline matches "vssadmin delete shadows" |
| wmic_shadowcopy_delete | PROCESS_EXECUTION matches wmic shadowcopy delete |
| diskshadow_delete | PROCESS_EXECUTION matches diskshadow delete |
| evtx_524 | EVTX 524 (volume shadow copy deleted) |
| powershell_remove_wmiobject_shadow | EVTX 4104 ScriptBlock matches Get-WmiObject Win32_ShadowCopy followed by Delete |

#### Supporting signals

| Signal | +Weight |
|---|---|
| executed_by_non_admin | +14 |
| followed_by_mass_file_modification | +14 |
| occurred_with_backup_destruction | +12 |

#### Counter signals

| Signal | -Weight |
|---|---|
| matched_documented_disk_cleanup | -12 |
| within_backup_software_window | -10 |

---

## Additional anti-forensic detectors (for v1 if time permits)

The following are detectors but not full clusters in v1; they register
disturbances without surfacing as separate clusters. v2 may promote them
to full constructors.

- **USN journal gaps** (T1070): `$UsnJrnl` sequence breaks
- **Defender exclusion additions** (T1562.001): tracked via
  `DEFENDER_EXCLUSION_ADDED` canonical events; folded into
  DefenseEvasionConstructor
- **Command history clearing** (T1070.003): folded into
  DefenseEvasionConstructor

---

## 6. Implementation notes

### Skeleton template

```python
from nighteye.constructors.base import Constructor, Cluster, TriggerRule, SignalRule
from nighteye.opensearch import canonical_search
from nighteye.graph import write_entity, write_edge

class LateralMovementConstructor(Constructor):
    name = "LateralMovement"
    cluster_type = "LateralMovement"
    mitre_tactic = "TA0008"
    technique_ids = ["T1021.001", "T1021.002", "T1021.003", "T1021.006",
                     "T1210", "T1534", "T1550.002", "T1563", "T1570"]

    triggers = [
        TriggerRule(
            name="network_logon_type3_from_internal_non_baseline",
            canonical_type="AUTHENTICATION",
            field_filters={"details.logon_type": 3},
            custom_check=lambda evt: (
                is_internal_ip(evt["source"]["ip"])
                and evt["source"]["ip"] != evt["host"]["name_to_ip"]
                and not is_machine_account(evt["user"]["name"])
            )
        ),
        # ... more triggers
    ]

    supporting = [
        SignalRule(
            name="admin_share_write_within_60s",
            description="Admin share write preceded service install",
            check=lambda ctx: ctx.has_canonical_within(
                "FILE_WRITE", filters={"file.path": is_admin_share},
                seconds=60
            ),
            weight=12
        ),
        # ... more
    ]

    counter = [
        SignalRule(
            name="service_binary_signed_microsoft",
            description="Service binary has valid Microsoft signature",
            check=lambda ctx: any(
                e.get("signing_status") == "signed_microsoft"
                for e in ctx.member_events
                if e["canonical_type"] == "SERVICE_INSTALL"
            ),
            weight=-12
        ),
        # ... more
    ]

    scoring = ScoringConfig(base_on_trigger=30, cap=95)

    grouping_window_seconds = 300
    group_by = ["source_host", "destination_host"]

    async def run(self, case_id, canonical_index):
        candidates = await self._scan_triggers(case_id, canonical_index)
        groups = self._group_candidates(candidates)
        clusters = []
        for group in groups:
            cluster = await self._build_cluster(group, canonical_index)
            await self._attach_counter_evidence(cluster, canonical_index)
            await self._detect_contradictions(cluster, canonical_index)
            cluster.score = self._score_cluster(cluster)
            cluster.strength = self._tier(cluster.score)
            clusters.append(cluster)
        return clusters
```

### CI test fixtures

The `data/synthetic-test-case/` directory contains seeded patterns:

- **lateral_movement_canonical.json** — seeded events matching all
  required LateralMovement triggers
- **legitimate_admin_canonical.json** — seeded events that should
  NOT fire (or should fire but with low score after counter-evidence)
- **persistence_canonical.json** — etc.

Each constructor has a `tests/test_<constructor>.py` that:
1. Loads its seeded fixture
2. Runs the constructor
3. Asserts expected clusters fire with expected strength
4. Asserts no spurious clusters fire on legitimate fixtures

Constructors cannot be merged without passing tests.

---

## 7. Build order

| Day | Constructor | Notes |
|---|---|---|
| D9 | Constructor framework + LateralMovementConstructor | Canonical example, full implementation, full tests |
| D10 | PersistenceConstructor | Heavy registry/MFT use, validates those parsers |
| D10 | CredentialAccessConstructor | LSASS / Kerberoast / DCSync coverage |
| D11 | RemoteExecutionConstructor | Process tree analysis |
| D11 | DefenseEvasionConstructor | Includes Defender exclusion + cmd history detectors |
| D11 | BeaconingConstructor | Network analysis, jitter computation |
| D12 | CollectionConstructor + ExfiltrationConstructor + ImpactConstructor | Lower-priority TTP coverage |
| D12 | LogClearingConstructor + TimestompConstructor + ShadowDeletionConstructor | Anti-forensic with disturbance registration |

Each constructor: design doc → fixture → implementation → tests →
integration with cluster table writer.

If schedule slips: ImpactConstructor + ExfiltrationConstructor +
TimestompConstructor are lower priority.
