# Guardian

> **Resident intruder guard for a single-person home PC** — plus network-bridge
> removal and registry ACL hardening (Troll functions), in one small exe.

---

## Overview

The assumption for a single-person home PC is simple: nobody should be logging
into or controlling this machine from somewhere else. Guardian watches for
remote access in near-real-time and, by design, acts on it **automatically** —
it disconnects the remote session, kills the remote-control program, stops the
remote-access service, and firewalls the source IP.

Because you sit physically at the PC, auto-eviction is safe for you: you keep
your own keyboard and screen no matter what it blocks.

Guardian also folds in the **Troll** functions: on startup it removes any
network bridge and restores sane registry permissions on the `Network` control
key (backing up the existing permissions first).

**Everything is automatic.** There are no configuration switches. The only
argument is `uninstall`.

---

## Project Structure

| File | Description |
|------|-------------|
| `Program.cs` | Entry point, logging, self-install/uninstall, embedded-tool extraction, Troll cleanup |
| `Guard.cs` | Intruder-guard detectors, responses, allow/deny lists, monitor loop |
| `Notify.cs` | Event-log + tray-balloon notifications |
| `Guardian.csproj` | .NET Framework 4.8 project; embeds the two tools as resources |
| `app.manifest` | Requests administrator elevation |
| `SetACL.exe` | Third-party registry-permission tool (embedded into the exe at build) |
| `devcon.exe` | Microsoft device-management tool (embedded into the exe at build) |

> `SetACL.exe` and `devcon.exe` must stay in the folder: the build embeds them
> into `Guardian.exe` each time you compile. They are not shipped separately.

The build produces a single **`Guardian.exe`** (~700 KB). .NET Framework 4.8
ships with Windows 10/11, so no runtime needs to be installed. Guardian runs
windowless — status and errors go to `C:\ProgramData\Guardian\guardian.log`.

---

## Build

```powershell
dotnet build .\Guardian.csproj -c Release
# Output: bin\Release\net48\Guardian.exe (single file)
```

---

## Usage

### Run it (fully automatic)
```powershell
# Run as Administrator (the exe also self-elevates via its manifest)
.\Guardian.exe
```

Guardian will:
1. Copy itself to `C:\Windows\Setup\Scripts\Bin\`
2. Create a scheduled task that runs at every boot under SYSTEM (auto-restarts on failure)
3. Run the Troll cleanup (unbridge + registry ACL restore)
4. Monitor continuously and evict any remote access it finds

### Uninstall
```powershell
# Remove the scheduled task and stop any running monitors
.\Guardian.exe uninstall
```

Firewall rules named `Guardian block <ip>` are left in place; remove them in
Windows Defender Firewall if you want.

---

## What it detects and does

| Detection | Response (automatic) |
|-----------|----------------------|
| Active Remote Desktop (RDP) session | Disconnect the session (`tsdiscon`) |
| Known remote-control tool running (TeamViewer, AnyDesk, VNC, RustDesk, etc.) | Kill the process |
| Remote-access service running | Stop the service |
| Remote logon (Security event 4624, logon type 10) from a non-loopback IP | Block the source IP in the firewall **and** disable the intruder's local account |

Detection is near-real-time: Guardian subscribes to new logon events and also
polls every 20 seconds.

**Account disabling is safe for you:** Guardian never disables the account
signed in at the physical console (you), and never touches machine/service
accounts (`SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`, or names ending in `$`).
Only a *remote* intruder's local account gets disabled. Domain accounts can't be
disabled by the local `net user` command and are left alone.

Only loopback (`127.0.0.1`, `::1`) is treated as trusted — even LAN remote
access is unexpected on a single-person home PC.

---

## Honest limits

Guardian catches commodity remote access — a forgotten AnyDesk, an RDP login
from a strange IP, a screen-share service left running. It is **not** an
antivirus/EDR and cannot reliably evict kernel-level malware or a rootkit. Keep
a real antivirus alongside it; treat Guardian as a tripwire.

---

## Legal disclaimer

This project is intended for authorized defensive, administrative, research, or
educational use only.

- Use only on systems you own or have explicit permission to protect.
- Running security, hardening, monitoring, or response tooling can impact
  stability and may disrupt legitimate software (including remote-access tools
  you use on purpose).
- Validate in a test environment before production use.
- Provided "AS IS", without warranties of any kind. The authors are not liable
  for any damages, data loss, downtime, or lockout resulting from its use.
- You are solely responsible for lawful operation and compliance in your
  jurisdiction.

---

<p align="center">
  <sub>Built with care by <strong>Gorstak</strong></sub>
</p>
