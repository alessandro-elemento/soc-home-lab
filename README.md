# SOC Home Lab: Detection & Incident Response Portfolio

This repository documents a self-built home security lab used to simulate real-world
attacker techniques (mapped to MITRE ATT&CK), investigate them using the same tools a
SOC analyst would use on the job, and write up the findings as genuine incident reports.

The goal was not just to "run a tool and screenshot the output", every report below
follows a discovery-first methodology: capture a system baseline, execute a simulated
technique, capture a second baseline, and find the anomaly by **diffing the two** rather
than searching for an artifact whose name or location was already known in advance.

## Lab Environment

Two isolated VirtualBox VMs, fully documented in [`lab-setup/lab-overview.md`](lab-setup/lab-overview.md):

- **Ubuntu-Victim**: Ubuntu Server 26.04.1 LTS (ARM64)
- **Windows11-Victim**: Windows 11 Home (ARM64, build 10.0.26200)

Attacker techniques were simulated using [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam)
(Atomic Red Team), and investigated using Wireshark, System Informer (Process Hacker),
Splunk Enterprise, and native OS tooling (PowerShell, `reg`, `schtasks`, `find`, `systemctl`).

## Incident Reports

| Technique | Tactic | Platform | Tools Used | Report |
|---|---|---|---|---|
| T1548.001 | Privilege Escalation / Defense Evasion | Linux | PowerShell, `find`, `file` | [SetUID Privilege Escalation](incident-reports/linux/T1548.001-setuid-privilege-escalation.md) |
| T1053.006 | Persistence | Linux | `systemctl`, PowerShell | [systemd Timer Persistence](incident-reports/linux/T1053.006-systemd-timer-persistence.md) |
| — | Discovery / Analysis | Linux | Wireshark | [HTTP Plaintext Traffic Analysis](incident-reports/linux/http-plaintext-traffic-analysis.md) |
| T1547.001 | Persistence | Windows | PowerShell, `reg` | [Registry Run Key Persistence](incident-reports/windows/T1547.001-registry-run-key-persistence.md) |
| T1053.005 | Persistence | Windows | PowerShell, `schtasks` | [Scheduled Task Persistence](incident-reports/windows/T1053.005-scheduled-task-persistence.md) |
| T1110.001 | Credential Access | Windows | Splunk Enterprise, Event Viewer | [Failed Logon Brute-Force Detection](incident-reports/windows/failed-logon-detection-splunk.md) |

## Methodology

Every report follows the same investigative flow:

1. **Baseline**: Capture the relevant system state (registry keys, SetUID files,
   scheduled tasks, event logs) *before* anything happens.
2. **Simulate**: Execute the Atomic Red Team test for the target technique.
3. **Discover**: Capture the same system state *after*, and diff the two baselines to
   surface what changed, without relying on already knowing the artifact's name.
4. **Analyze**: Evaluate the surfaced artifact on its own technical merits (location,
   ownership, permissions, referenced binary existence) to justify why it's suspicious.
5. **Eradicate**: Remove the artifact using the same manual commands a real analyst
   would use against a real attacker (`reg delete`, `sudo rm`, `schtasks /delete`) —
   never the Atomic Red Team framework's own `-Cleanup` flag, since a genuine adversary's
   artifact wouldn't ship with a built-in removal tool.
6. **Verify**: Confirm removal and that the system has returned to its baseline state.

## Skills Demonstrated

- Windows and Linux persistence mechanism analysis (Registry Run keys, Scheduled Tasks,
  systemd timers)
- Linux privilege escalation analysis (SetUID/SetGID abuse)
- Baseline-diff investigative methodology (as opposed to signature/IOC lookup)
- SIEM log correlation and alert tuning in Splunk (Event ID 4625, `stats`/`where`
  threshold logic, real-time alerting, throttling/suppression)
- Windows Security Event Log analysis (Logon Type, Source Network Address, failure codes)
- Network traffic analysis with Wireshark (HTTP stream reconstruction)
- Manual, real-world eradication and verification steps (registry, scheduled tasks,
  filesystem)
- Multi-VM lab administration on Apple Silicon (ARM64-specific tooling constraints)

## Limitations

- Techniques were simulated using Atomic Red Team's built-in test payloads, which
  are intentionally simplified stand-ins for real malicious behavior.
- The environment is a fully isolated, self-generated lab — there is no real
  adversary, and no production data or network was involved.
  
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
│       └── failed-logon-detection-splunk.md
├── detections/
│   └── failed-logon-threshold.spl
└── screenshots/
```
