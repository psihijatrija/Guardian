// Guardian intruder guard: detectors, responses, allow/deny lists, monitor loop.
// Ported from Guardian.ps1.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Net;
using System.ServiceProcess;
using System.Threading;

namespace Guardian
{
    internal static partial class Program
    {
        // Source IPs that are never treated as intruders (single-person home PC:
        // even LAN remote access is unexpected, so only loopback is allowed).
        private static readonly string[] AllowIpRanges = { "127.0.0.1", "::1" };

        // Remote-control tools you use on purpose (process-name fragments). Empty:
        // a home PC normally runs none of these.
        private static readonly string[] AllowPrograms = new string[0];

        // Deny-list of known remote-control / screen-share tools (name fragments).
        private static readonly string[] DenyPrograms =
        {
            "teamviewer","anydesk","vnc","tightvnc","ultravnc","realvnc","logmein",
            "gotomypc","remotepc","ammyy","supremo","dwagent","dwservice","splashtop",
            "rustdesk","parsec","screenconnect","connectwise","dwrcs","radmin",
            "aeroadmin","remoteutilities","showmypc","litemanager","getscreen"
        };

        // Remote-access service display-name fragments.
        private static readonly string[] DenyServiceNames =
        {
            "vnc","teamviewer","anydesk","rustdesk","logmein","splashtop",
            "screenconnect","dwservice","ammyy","radmin","atera","getscreen",
            "remote utilities"
        };

        private sealed class Threat
        {
            public string Kind;       // RdpSession, RemoteToolProcess, RemoteService, RemoteLogon
            public string Detail;
            public string Account;
            public string SourceIp;
            public Process Process;
            public ServiceController Service;
            public string SessionId;
        }

        // --- Monitor loop -----------------------------------------------------------

        private static void MonitorLoop()
        {
            Log("INFO", "Guardian starting. Mode=Aggressive. Data=" + DataDir);
            Log("INFO", "Fully automatic: detected remote access will be evicted " +
                "(sessions dropped, tools killed, services stopped, source IPs blocked).");

            EventLogWatcher watcher = StartLiveLogonWatcher();

            try
            {
                while (true)
                {
                    Pass();
                    Thread.Sleep((PollSeconds < 5 ? 5 : PollSeconds) * 1000);
                }
            }
            finally
            {
                if (watcher != null) { watcher.Enabled = false; watcher.Dispose(); }
                Log("INFO", "Guardian stopped.");
            }
        }

        private static EventLogWatcher StartLiveLogonWatcher()
        {
            try
            {
                var query = new EventLogQuery("Security", PathType.LogName,
                    "*[System[(EventID=4624)]]");
                var watcher = new EventLogWatcher(query);
                watcher.EventRecordWritten += (s, e) =>
                {
                    try
                    {
                        if (e.EventRecord == null) return;
                        string msg = e.EventRecord.FormatDescription() ?? string.Empty;
                        if (!msg.Contains("Logon Type:\t10") && !LogonTypeIs10(msg)) return;

                        string src = Extract(msg, "Source Network Address:");
                        string acct = Extract(msg, "Account Name:");
                        if (IsLoopbackOrEmpty(src)) return;

                        ResolveThreat(new Threat
                        {
                            Kind = "RemoteLogon",
                            Detail = "LIVE remote logon as '" + acct + "' from " + src,
                            Account = acct,
                            SourceIp = src
                        });
                    }
                    catch { }
                };
                watcher.Enabled = true;
                Log("INFO", "Live logon watcher active (Security 4624).");
                return watcher;
            }
            catch (Exception ex)
            {
                Log("WARN", "Could not start live logon watcher; polling only: " + ex.Message);
                return null;
            }
        }

        private static void Pass()
        {
            var threats = new List<Threat>();
            threats.AddRange(GetRemoteSessionThreats());
            threats.AddRange(GetRemoteToolThreats());
            threats.AddRange(GetRemoteServiceThreats());
            threats.AddRange(GetRemoteLogonThreats(DateTime.Now.AddMinutes(-2)));

            foreach (Threat t in threats)
            {
                try { ResolveThreat(t); }
                catch (Exception ex) { Log("ERROR", "Error handling threat: " + ex.Message); }
            }
        }

        // --- Detectors --------------------------------------------------------------

        private static IEnumerable<Threat> GetRemoteSessionThreats()
        {
            var list = new List<Threat>();
            try
            {
                string raw = CaptureProcess("qwinsta.exe", "");
                foreach (string line in raw.Split('\n').Skip(1))
                {
                    if (line.IndexOf("rdp-tcp#", StringComparison.OrdinalIgnoreCase) >= 0 &&
                        line.IndexOf("Active", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        string sid = null;
                        var m = System.Text.RegularExpressions.Regex.Match(line, @"\s(\d+)\s+Active");
                        if (m.Success) sid = m.Groups[1].Value;
                        list.Add(new Threat
                        {
                            Kind = "RdpSession",
                            Detail = ("Active Remote Desktop session (" + line.Trim() + ")"),
                            SessionId = sid
                        });
                    }
                }
            }
            catch { }
            return list;
        }

        private static IEnumerable<Threat> GetRemoteToolThreats()
        {
            var list = new List<Threat>();
            try
            {
                foreach (Process proc in Process.GetProcesses())
                {
                    if (IsProgramDenied(proc.ProcessName))
                    {
                        list.Add(new Threat
                        {
                            Kind = "RemoteToolProcess",
                            Detail = "Remote-control program running: " + proc.ProcessName,
                            Process = proc
                        });
                    }
                }
            }
            catch { }
            return list;
        }

        private static IEnumerable<Threat> GetRemoteServiceThreats()
        {
            var list = new List<Threat>();
            try
            {
                foreach (ServiceController sc in ServiceController.GetServices())
                {
                    if (sc.Status != ServiceControllerStatus.Running) continue;
                    string display = (sc.DisplayName ?? string.Empty).ToLowerInvariant();
                    if (DenyServiceNames.Any(frag => display.Contains(frag)))
                    {
                        list.Add(new Threat
                        {
                            Kind = "RemoteService",
                            Detail = "Remote-access service running: " + sc.DisplayName,
                            Service = sc
                        });
                    }
                }
            }
            catch { }
            return list;
        }

        private static IEnumerable<Threat> GetRemoteLogonThreats(DateTime since)
        {
            var list = new List<Threat>();
            try
            {
                string q = "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= " +
                    ((long)(DateTime.UtcNow - since.ToUniversalTime()).TotalMilliseconds) + "]]]";
                var query = new EventLogQuery("Security", PathType.LogName, q);
                using (var reader = new EventLogReader(query))
                {
                    EventRecord rec;
                    while ((rec = reader.ReadEvent()) != null)
                    {
                        using (rec)
                        {
                            string msg = rec.FormatDescription() ?? string.Empty;
                            if (!LogonTypeIs10(msg)) continue;
                            string src = Extract(msg, "Source Network Address:");
                            string acct = Extract(msg, "Account Name:");
                            if (IsLoopbackOrEmpty(src)) continue;
                            list.Add(new Threat
                            {
                                Kind = "RemoteLogon",
                                Detail = "Remote logon as '" + acct + "' from " + src +
                                    " at " + rec.TimeCreated,
                                Account = acct,
                                SourceIp = src
                            });
                        }
                    }
                }
            }
            catch { }
            return list;
        }

        // --- Classify + respond -----------------------------------------------------

        private static void ResolveThreat(Threat t)
        {
            // Allowlist checks.
            if (t.Kind == "RemoteToolProcess" && t.Process != null &&
                IsProgramAllowed(t.Process.ProcessName))
            {
                Log("INFO", "ALLOWED (program on allowlist): " + t.Detail);
                return;
            }
            if (t.Kind == "RemoteLogon" && IsIpAllowed(t.SourceIp))
            {
                Log("INFO", "ALLOWED (source IP on allowlist): " + t.Detail);
                return;
            }

            Log("DETECT", t.Detail);
            SendNotice("Guardian: possible intrusion detected", t.Detail, NoticeKind.Warning);

            // Guardian is always aggressive: evict on sight.
            switch (t.Kind)
            {
                case "RemoteToolProcess": KillProcess(t.Process, t.Detail); break;
                case "RemoteLogon":
                    FirewallBlockIp(t.SourceIp, t.Detail);
                    DisableAccount(t.Account, t.Detail);
                    break;
                case "RdpSession":
                    if (!string.IsNullOrEmpty(t.SessionId)) DisconnectRdp(t.SessionId, t.Detail);
                    break;
                case "RemoteService": StopService(t.Service, t.Detail); break;
            }
        }

        // --- Responses --------------------------------------------------------------

        private static void DisconnectRdp(string sessionId, string reason)
        {
            try
            {
                RunProcess("tsdiscon.exe", sessionId, waitForExit: true, ignoreExit: true);
                Log("ACTION", "Disconnected RDP session " + sessionId + ". Reason: " + reason);
                SendNotice("Guardian: remote session disconnected", reason, NoticeKind.Error);
            }
            catch (Exception ex)
            {
                Log("ERROR", "Failed to disconnect RDP session " + sessionId + ": " + ex.Message);
            }
        }

        private static void StopService(ServiceController sc, string reason)
        {
            try
            {
                if (sc.Status == ServiceControllerStatus.Running)
                {
                    sc.Stop();
                    sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(15));
                }
                Log("ACTION", "Stopped service '" + sc.ServiceName + "'. Reason: " + reason);
                SendNotice("Guardian: remote-access service stopped",
                    sc.DisplayName + " -- " + reason, NoticeKind.Error);
            }
            catch (Exception ex)
            {
                Log("ERROR", "Failed to stop service '" + sc.ServiceName + "': " + ex.Message);
            }
        }

        private static void KillProcess(Process proc, string reason)
        {
            try
            {
                string name = proc.ProcessName;
                int pid = proc.Id;
                proc.Kill();
                Log("ACTION", "Killed process '" + name + "' (PID " + pid + "). Reason: " + reason);
                SendNotice("Guardian: remote-control program stopped",
                    name + " -- " + reason, NoticeKind.Error);
            }
            catch (Exception ex)
            {
                Log("ERROR", "Failed to kill process: " + ex.Message);
            }
        }

        private static void FirewallBlockIp(string ip, string reason)
        {
            if (string.IsNullOrWhiteSpace(ip) || ip == "-" || ip == "unknown") return;
            string ruleName = "Guardian block " + ip;
            try
            {
                // Add only if a rule with this name doesn't already exist.
                string existing = CaptureProcess("netsh",
                    "advfirewall firewall show rule name=\"" + ruleName + "\"");
                if (existing.IndexOf(ruleName, StringComparison.OrdinalIgnoreCase) >= 0) return;

                RunProcess("netsh",
                    "advfirewall firewall add rule name=\"" + ruleName + "\" " +
                    "dir=in action=block remoteip=" + ip,
                    waitForExit: true, ignoreExit: true);
                Log("ACTION", "Firewall now blocks inbound from " + ip + ". Reason: " + reason);
                SendNotice("Guardian: source IP blocked", ip + " -- " + reason, NoticeKind.Error);
            }
            catch (Exception ex)
            {
                Log("ERROR", "Failed to add firewall block for " + ip + ": " + ex.Message);
            }
        }

        private static void DisableAccount(string account, string reason)
        {
            if (string.IsNullOrWhiteSpace(account) || account == "-" ||
                account.Equals("unknown", StringComparison.OrdinalIgnoreCase))
                return;

            // Never disable the account signed in at the console -- that is YOU.
            string console = GetConsoleUser();
            if (!string.IsNullOrEmpty(console) &&
                account.Equals(console, StringComparison.OrdinalIgnoreCase))
            {
                Log("WARN", "Refusing to disable '" + account +
                    "': it is the console (signed-in) user.");
                return;
            }

            // Also skip machine/service accounts (names ending in '$' or well-known ones).
            if (account.EndsWith("$") ||
                account.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) ||
                account.Equals("LOCAL SERVICE", StringComparison.OrdinalIgnoreCase) ||
                account.Equals("NETWORK SERVICE", StringComparison.OrdinalIgnoreCase))
            {
                Log("WARN", "Refusing to disable system/service account '" + account + "'.");
                return;
            }

            try
            {
                // net user <name> /active:no disables a local account.
                int code = RunProcess("net.exe",
                    "user \"" + account + "\" /active:no", waitForExit: true, ignoreExit: true);
                if (code == 0)
                {
                    Log("ACTION", "Disabled local account '" + account + "'. Reason: " + reason);
                    SendNotice("Guardian: account disabled",
                        account + " -- " + reason, NoticeKind.Error);
                }
                else
                {
                    Log("WARN", "Could not disable account '" + account +
                        "' (net user exit " + code + "); it may be a domain or non-local account.");
                }
            }
            catch (Exception ex)
            {
                Log("ERROR", "Could not disable account '" + account + "': " + ex.Message);
            }
        }

        private static string GetConsoleUser()
        {
            // The account signed in at the physical console -- the one we must never lock out.
            try
            {
                // Win32_ComputerSystem.UserName returns DOMAIN\user for the console session.
                using (var searcher = new System.Management.ManagementObjectSearcher(
                    "SELECT UserName FROM Win32_ComputerSystem"))
                {
                    foreach (System.Management.ManagementObject mo in searcher.Get())
                    {
                        string full = mo["UserName"] as string;
                        if (!string.IsNullOrEmpty(full))
                        {
                            int slash = full.LastIndexOf('\\');
                            return slash >= 0 ? full.Substring(slash + 1) : full;
                        }
                    }
                }
            }
            catch { }
            // Fallback to the environment user (less reliable when running as SYSTEM).
            return Environment.UserName;
        }

        // --- Allow/deny + parsing helpers -------------------------------------------

        private static bool IsProgramDenied(string procName)
        {
            string n = (procName ?? string.Empty).ToLowerInvariant();
            return DenyPrograms.Any(p => n.Contains(p));
        }

        private static bool IsProgramAllowed(string procName)
        {
            string n = (procName ?? string.Empty).ToLowerInvariant();
            return AllowPrograms.Any(p => !string.IsNullOrEmpty(p) && n.Contains(p.ToLowerInvariant()));
        }

        private static bool IsIpAllowed(string ip)
        {
            return AllowIpRanges.Any(r => IpInRange(ip, r));
        }

        private static bool IsLoopbackOrEmpty(string src)
        {
            return string.IsNullOrWhiteSpace(src) || src == "-" ||
                   src == "127.0.0.1" || src == "::1";
        }

        private static bool LogonTypeIs10(string msg)
        {
            var m = System.Text.RegularExpressions.Regex.Match(msg, @"Logon Type:\s+(\d+)");
            return m.Success && m.Groups[1].Value == "10";
        }

        private static string Extract(string msg, string label)
        {
            var m = System.Text.RegularExpressions.Regex.Match(
                msg, System.Text.RegularExpressions.Regex.Escape(label) + @"\s+(\S+)");
            return m.Success ? m.Groups[1].Value : "unknown";
        }

        private static bool IpInRange(string ip, string range)
        {
            if (string.IsNullOrWhiteSpace(ip) || string.IsNullOrWhiteSpace(range)) return false;
            if (ip == range) return true;
            try
            {
                if (!range.Contains("/"))
                    return IPAddress.Parse(ip).Equals(IPAddress.Parse(range));

                string[] parts = range.Split('/');
                IPAddress netAddr = IPAddress.Parse(parts[0]);
                int prefix = int.Parse(parts[1]);
                IPAddress ipAddr = IPAddress.Parse(ip);
                if (ipAddr.AddressFamily != netAddr.AddressFamily) return false;

                byte[] ipBytes = ipAddr.GetAddressBytes();
                byte[] netBytes = netAddr.GetAddressBytes();
                int bits = prefix;
                for (int i = 0; i < ipBytes.Length && bits > 0; i++)
                {
                    int take = Math.Min(8, bits);
                    byte mask = (byte)((0xFF << (8 - take)) & 0xFF);
                    if ((ipBytes[i] & mask) != (netBytes[i] & mask)) return false;
                    bits -= 8;
                }
                return true;
            }
            catch { return false; }
        }
    }
}
