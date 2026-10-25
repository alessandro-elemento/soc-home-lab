# SOC Home Lab: Detection & Incident Response Portfolio

This repository documents a self-built home security lab used to simulate real-world
attacker techniques (mapped to MITRE ATT&CK), investigate them using the same tools a
SOC analyst would use on the job, and write up the findings as genuine incident reports.

The goal was not just to "run a tool and screenshot the output". Every report is
discovery-first, meaning the artefact is found rather than looked up by a name or location
already known in advance, but there are two approaches:

- **Baseline diff** (the four persistence and privilege escalation reports): capture a
  system baseline, execute a simulated technique, capture a second baseline, and find the
  anomaly by **diffing the two**.
- **Telemetry first** (the Sysmon and Splunk report): collect logs continuously, run the
  technique, then investigate from the logs alone, as a SOC would when nobody took a
  snapshot beforehand.

## Lab Environment

Two isolated VirtualBox VMs, fully documented in [`lab-setup/lab-overview.md`](lab-setup/lab-overview.md):

- **Ubuntu-Victim**: Ubuntu Server 26.04.1 LTS (ARM64)
- **Windows11-Victim**: Windows 11 Home (ARM64, build 10.0.26200)

Attacker techniques were simulated using [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam)
(Atomic Red Team), and investigated using Wireshark, System Informer (Process Hacker),
Splunk Enterprise, Sysmon, AWS CloudWatch Logs, and native OS tooling (PowerShell, `reg`,
`schtasks`, `find`, `systemctl`).

## Incident Reports

| Technique | Tactic | Platform | Tools Used | Report |
|---|---|---|---|---|
| T1548.001 | Privilege Escalation / Defense Evasion | Linux | PowerShell, `find`, `file` | [SetUID Privilege Escalation](incident-reports/linux/T1548.001-setuid-privilege-escalation.md) |
| T1053.006 | Persistence | Linux | `systemctl`, PowerShell | [systemd Timer Persistence](incident-reports/linux/T1053.006-systemd-timer-persistence.md) |
| N/A | Discovery / Analysis | Linux | Wireshark | [HTTP Plaintext Traffic Analysis](incident-reports/linux/http-plaintext-traffic-analysis.md) |
| T1547.001 | Persistence | Windows | PowerShell, `reg` | [Registry Run Key Persistence](incident-reports/windows/T1547.001-registry-run-key-persistence.md) |
| T1053.005 | Persistence | Windows | PowerShell, `schtasks` | [Scheduled Task Persistence](incident-reports/windows/T1053.005-scheduled-task-persistence.md) |
| T1110.001 | Credential Access | Windows | Splunk Enterprise, Event Viewer | [Failed Logon Brute-Force Detection](incident-reports/windows/failed-logon-detection-splunk.md) |
| T1110.001 | Credential Access | Windows | AWS CloudWatch (Logs, Logs Insights, alarm), SNS, AWS CLI, PowerShell | [Failed Logon Detection on AWS CloudWatch](incident-reports/windows/failed-logon-detection-cloudwatch.md) |
| T1136.001, T1547.001 | Persistence | Windows | Sysmon, Splunk Enterprise, Windows Security log | [Persistence Detection from Telemetry with Sysmon and Splunk](incident-reports/windows/sysmon-splunk-persistence-detection.md) |

## Methodology

### Baseline-diff flow

The Linux and Windows persistence and privilege escalation reports (T1548.001,
T1053.006, T1547.001, T1053.005) follow this flow:

1. **Baseline**: Capture the relevant system state (registry keys, SetUID files,
   scheduled tasks, event logs) *before* anything happens.
2. **Simulate**: Execute the Atomic Red Team test for the target technique.
3. **Discover**: Capture the same system state *after*, and diff the two baselines to
   surface what changed, without relying on already knowing the artifact's name.
4. **Analyse**: Evaluate the surfaced artifact on its own technical merits (location,
   ownership, permissions, referenced binary existence) to justify why it's suspicious.
5. **Eradicate**: Remove the artifact using the same manual commands a real analyst
   would use against a real attacker (`reg delete`, `sudo rm`, `schtasks /delete`), not
   the Atomic Red Team framework's own `-Cleanup` flag, since a genuine adversary's
   artifact wouldn't ship with a built-in removal tool.
6. **Verify**: Confirm removal and that the system has returned to its baseline state.

### Telemetry-first flow

The [Sysmon and Splunk report](incident-reports/windows/sysmon-splunk-persistence-detection.md)
works the other way round, because a SOC mostly starts from logs and alerts:

1. **Collect**: Deploy Sysmon and send its events, with the Windows Security log, to
   Splunk before anything happens.
2. **Simulate**: Execute the Atomic Red Team test.
3. **Investigate**: Start from a clue, search the telemetry, and pivot between log sources
   (the Security log says what and who, Sysmon says how) to build a timeline.
4. **Map**: Tie the finding to MITRE ATT&CK last.
5. **Detect**: Turn the finding into a saved search or alert.
6. **Clean up**: Remove the artefacts with Atomic Red Team's own `-Cleanup` flag and
   verify. This is a deliberate difference from the baseline-diff reports: the focus here
   was the detection, not the manual eradication.

The failed-logon reports (Splunk and CloudWatch) and the Wireshark report analyse logs or
traffic rather than a planted artefact, so they follow their own steps, described in each
report.

## Skills Demonstrated

- Windows and Linux persistence mechanism analysis (Registry Run keys, Scheduled Tasks,
  systemd timers)
- Linux privilege escalation analysis (SetUID/SetGID abuse)
- Baseline-diff investigative methodology (as opposed to signature/IOC lookup)
- SIEM log correlation and alert tuning in Splunk (Event ID 4625, `stats`/`where`
  threshold logic, real-time alerting, throttling/suppression)
- Windows Security Event Log analysis (Logon Type, Source Network Address, failure codes,
  account-management events)
- Sysmon deployment on ARM64 Windows and detection from telemetry: process-chain
  investigation, pivoting between Sysmon and Security logs, noise filtering, and a
  scheduled Splunk alert for local account creation
- Small-scale AWS experience: IAM user with a least-privilege policy and root MFA,
  shipping Windows security events to CloudWatch Logs with the AWS CLI on a schedule,
  querying them with Logs Insights, and alerting with a CloudWatch metric filter, alarm
  and SNS email notification
- Network traffic analysis with Wireshark (HTTP stream reconstruction)
- Manual, real-world eradication and verification steps (registry, scheduled tasks,
  filesystem)
- Multi-VM lab administration on Apple Silicon (ARM64-specific tooling constraints)
- Basic Python scripting for log analysis (standard-library CSV parsing, threshold-based
  detection logic independent of Splunk) and PowerShell scripting for log forwarding;
  see [`scripts/`](scripts/)
- Version control with Git/GitHub (repository structure, commit history, remote push)

## Limitations

- Techniques were simulated using Atomic Red Team's built-in test payloads, which
  are intentionally simplified stand-ins for real malicious behaviour.
- The environment is a fully isolated, self-generated lab; there is no real
  adversary, and no production data or network was involved.
- The AWS work is a small, single-host exercise (one log group, a scheduled script rather
  than a purpose-built agent, alert latency of minutes), not a production logging
  pipeline.

## Repository Structure

```
soc-home-lab/
├── README.md
├── lab-setup/
│   └── lab-overview.md
├── incident-reports/
│   ├── linux/
│   │   ├── T1548.001-setuid-privilege-escalation.md
│   │   ├── T1053.006-systemd-timer-persistence.md
│   │   └── http-plaintext-traffic-analysis.md
│   └── windows/
│       ├── T1547.001-registry-run-key-persistence.md
│       ├── T1053.005-scheduled-task-persistence.md
│       ├── failed-logon-detection-splunk.md
│       ├── failed-logon-detection-cloudwatch.md
│       └── sysmon-splunk-persistence-detection.md
├── detections/
│   ├── failed-logon-threshold.spl
│   ├── failed-logon-threshold.logsinsights
│   ├── local-account-created.spl
│   └── registry-run-key-sysmon.spl
├── scripts/
│   ├── analyze_failed_logons.py
│   ├── sample-4625-events.csv
│   └── ship-4625-to-cloudwatch.ps1
└── screenshots/
```
