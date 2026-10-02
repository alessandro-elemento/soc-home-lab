# Lab Overview

## Hardware / Host

- Apple Silicon Mac, VirtualBox for virtualization.
- Apple Silicon does **not** support running x86_64 Windows guests in VirtualBox, only
  ARM64 Windows or ARM64 Linux guests are supported. This directly shaped the VM choices
  below (Windows 11 **Home ARM64**, not the more commonly documented x64 build).

## Virtual Machines

### Ubuntu-Victim

- **OS:** Ubuntu Server 26.04.1 LTS (ARM64), codename "resolute"
- **Networking:** isolated VirtualBox internal/host-only network, no exposure to the
  host LAN beyond what's required for package installation
- **Tools installed:**
  - PowerShell (ARM64 tarball build -> the standard install script does not support
    ARM64, so the `.tar.gz` release was downloaded and extracted manually)
  - Invoke-AtomicRedTeam (PowerShell module) + Atomics folder, cloned to
    `/home/kal/AtomicRedTeam`
  - Wireshark
  - Native tools used for investigation: `find`, `systemctl`, `file`, `ls`

### Windows11-Victim

- **OS:** Windows 11 Home (ARM64, build 10.0.26200)
- **Networking:** isolated VirtualBox internal/host-only network
- **Tools installed:**
  - PowerShell 7 (ARM64 build)
  - Invoke-AtomicRedTeam + Atomics folder, at `C:\AtomicRedTeam`
  - System Informer (Process Hacker successor)
  - Splunk Enterprise 10.4.3 (build 4174a2deda5d): installed here rather than on the
    Linux VM because there is no ARM64 Linux build of Splunk
  - Windows Defender folder exclusion added for `C:\AtomicRedTeam` (Defender otherwise
    quarantines Atomic Red Team's test definition files)

## Snapshot Strategy

Each VM has a clean baseline snapshot taken immediately after tool installation. Before
running a new Atomic Red Team test, the lab is reset to this snapshot (or cleaned up
between tests) so that each investigation starts from a known-good state and baseline
captures are meaningful.

## ARM64-Specific Challenges & Workarounds Encountered

- VirtualBox on Apple Silicon cannot run x64 Windows guests: ARM64 Windows 11
  Home was used instead.
- The standard PowerShell install script does not support ARM64; the ARM64 tarball/zip
  release had to be downloaded and extracted manually on both VMs.
- There is no ARM64 Linux build of Splunk, so Splunk Enterprise was installed on the
  Windows VM instead of the Linux VM, and log collection was scoped to the Windows
  Security and System event logs.
- Running `Invoke-AtomicTest` as root on Linux via `sudo` resolves `~` to `/root`, not
  the invoking user's home directory -> the `-PathToAtomicsFolder` flag had to be passed
  explicitly on every elevated run to avoid a "path does not exist" error.

## Windows Defender Note

Real-time protection was disabled at one point during testing (to allow a process
injection technique to execute without being blocked) and was left off for the
remainder of the lab sessions covered in this repository, since it has no bearing on
the content of the reports below -> none of the finalised techniques here rely on
Defender being active or inactive.
