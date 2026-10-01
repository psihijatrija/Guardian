// Guardian.exe by Gorstak
// A resident intruder guard for a single-person home PC, merged with Troll's
// network-bridge removal + registry ACL cleanup. Single windowless .NET 4.8 exe.
//
// Ported from Guardian.ps1 (intruder guard) + Troll (bridge/registry cleanup).
//
// Behavior:
//   Guardian.exe            -> fully automatic: self-install as a SYSTEM boot
//                              scheduled task, run Troll cleanup, then monitor
//                              aggressively (evict remote access on sight).
//   Guardian.exe uninstall  -> remove the scheduled task and stop monitors.

using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;

namespace Guardian
{
    internal static partial class Program
    {
        internal const string TaskName = "Guardian";
        private const string RegistryKey =
            @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network";

        // Guardian is fully automatic and always aggressive by design.
        internal const int PollSeconds = 20;

        // Extracted helper tools (Troll functions) live here for the process lifetime.
        private static string _toolDir;
        private static string _setAcl;
        private static string _devcon;

        // Persistent log so a windowless run is diagnosable.
        internal static readonly string DataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Guardian");
        internal static readonly string LogFile = Path.Combine(DataDir, "guardian.log");

        [STAThread]
        private static int Main(string[] args)
        {
            try
            {
                string command = args.Length > 0 ? args[0].ToLowerInvariant() : string.Empty;

                // The only switch: uninstall. Needs no extracted tools.
                if (command == "uninstall")
                {
                    Uninstall();
                    return 0;
                }

                EnsureDataDir();
                EnsureEventSource();
                ExtractEmbeddedTools();

                // Fully automatic path.
                RegisterSystemBootTask();
                RunNetworkCleanup();     // Troll: registry ACLs + unbridge
                MonitorLoop();           // Guardian: resident intruder guard
                return 0;
            }
            catch (Exception ex)
            {
                Log("ERROR", "Fatal: " + ex.Message);
                return 1;
            }
        }

        private static void EnsureDataDir()
        {
            try { Directory.CreateDirectory(DataDir); } catch { }
        }

        // --- Embedded tool extraction (Troll) ---------------------------------------

        private static void ExtractEmbeddedTools()
        {
            _toolDir = Path.Combine(Path.GetTempPath(),
                "Guardian_" + Process.GetCurrentProcess().Id);
            Directory.CreateDirectory(_toolDir);

            _setAcl = ExtractResource("Guardian.SetACL.exe", "SetACL.exe");
            _devcon = ExtractResource("Guardian.devcon.exe", "devcon.exe");
        }

        private static string ExtractResource(string resourceName, string fileName)
        {
            string outPath = Path.Combine(_toolDir, fileName);
            Assembly asm = Assembly.GetExecutingAssembly();
            using (Stream src = asm.GetManifestResourceStream(resourceName))
            {
                if (src == null)
                    throw new InvalidOperationException("Embedded resource missing: " + resourceName);
                using (FileStream dst = File.Create(outPath))
                {
                    src.CopyTo(dst);
                }
            }
            return outPath;
        }

        // --- Persistence: scheduled task at boot under SYSTEM -----------------------

        private static void RegisterSystemBootTask()
        {
            string targetFolder = @"C:\Windows\Setup\Scripts\Bin";
            string exeSource = Process.GetCurrentProcess().MainModule.FileName;
            string targetPath = Path.Combine(targetFolder, Path.GetFileName(exeSource));

            try
            {
                Directory.CreateDirectory(targetFolder);

                if (!string.Equals(exeSource, targetPath, StringComparison.OrdinalIgnoreCase))
                {
                    File.Copy(exeSource, targetPath, true);
                    Log("INFO", "Copied executable to: " + targetPath);
                }

                RunProcess("schtasks.exe",
                    "/Delete /TN \"" + TaskName + "\" /F", waitForExit: true, ignoreExit: true);

                // Run at startup, as SYSTEM, highest privileges, restart on failure.
                string createArgs =
                    "/Create /TN \"" + TaskName + "\" " +
                    "/TR \"\\\"" + targetPath + "\\\"\" " +
                    "/SC ONSTART /RU SYSTEM /RL HIGHEST /F";

                int code = RunProcess("schtasks.exe", createArgs, waitForExit: true);
                Log("INFO", code == 0
                    ? "Scheduled task '" + TaskName + "' created (runs at boot as SYSTEM)."
                    : "Failed to register task (exit " + code + ").");
            }
            catch (Exception ex)
            {
                Log("ERROR", "Persistence setup failed: " + ex.Message);
            }
        }

        private static void Uninstall()
        {
            EnsureDataDir();
            Log("INFO", "Uninstall requested: removing scheduled task and stopping monitors.");

            int code = RunProcess("schtasks.exe",
                "/Delete /TN \"" + TaskName + "\" /F", waitForExit: true, ignoreExit: true);
            Log("INFO", code == 0
                ? "Scheduled task '" + TaskName + "' removed (or was not present)."
                : "schtasks delete returned exit " + code + ".");

            int self = Process.GetCurrentProcess().Id;
            string selfName = Process.GetCurrentProcess().ProcessName;
            foreach (Process p in Process.GetProcessesByName(selfName))
            {
                if (p.Id == self) continue;
                try { p.Kill(); Log("INFO", "Stopped Guardian process PID " + p.Id + "."); }
                catch (Exception ex) { Log("ERROR", "Could not stop PID " + p.Id + ": " + ex.Message); }
                finally { p.Dispose(); }
            }
            Log("INFO", "Uninstall complete. (Any 'Guardian block ...' firewall rules remain; remove them manually if desired.)");
        }

        // --- Troll: registry ACL cleanup + unbridge ---------------------------------

        private static void RunNetworkCleanup()
        {
            string backup = Path.Combine(_toolDir, "network_permissions_backup.txt");
            Log("INFO", "Network cleanup starting (registry ACLs + unbridge).");

            if (SetAcl("-on \"" + RegistryKey + "\" -ot reg -actn list -lst \"f:sddl;w:dacl\" -bckp \"" + backup + "\"") != 0)
            {
                Log("WARN", "Registry permission backup failed. Aborting cleanup.");
                return;
            }

            SetAcl("-on \"" + RegistryKey + "\" -ot reg -actn trustee -trst \"n1:Everyone;ta:remtrst;w:dacl\"");
            SetAcl("-on \"" + RegistryKey + "\" -ot reg -actn ace -ace \"n:Administrators;p:full\" -rec cont_obj");
            SetAcl("-on \"" + RegistryKey + "\" -ot reg -actn ace -ace \"n:SYSTEM;p:full\" -rec cont_obj");
            SetAcl("-on \"" + RegistryKey + "\" -ot reg -actn ace -ace \"n:Users;p:read\" -rec cont_obj");
            SetAcl("-on \"" + RegistryKey + "\" -ot reg -actn ace -ace \"n:CREATOR OWNER;p:full;i:so,sc\" -rec cont_obj");
            SetAcl("-on \"" + RegistryKey + "\" -ot reg -actn setowner -ownr \"n:Administrators\" -rec cont_obj");
            SetAcl("-on \"" + RegistryKey + "\" -ot reg -actn setprot -op \"dacl:np;sacl:np\"");

            Log("INFO", "Unbridging network adapters.");
            CaptureProcess("netsh", "bridge uninstall");

            Log("INFO", "Network cleanup complete.");
        }

        private static int SetAcl(string args)
        {
            return RunProcess(_setAcl, args, waitForExit: true, ignoreExit: true);
        }

        // --- Process helpers --------------------------------------------------------

        internal static int RunProcess(string exe, string args, bool waitForExit, bool ignoreExit = false)
        {
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                Arguments = args,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using (Process p = Process.Start(psi))
            {
                if (!waitForExit) return 0;
                p.WaitForExit();
                return ignoreExit ? 0 : p.ExitCode;
            }
        }

        internal static string CaptureProcess(string exe, string args)
        {
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                Arguments = args,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using (Process p = Process.Start(psi))
            {
                string stdout = p.StandardOutput.ReadToEnd();
                string stderr = p.StandardError.ReadToEnd();
                p.WaitForExit();
                return stdout + stderr;
            }
        }

        // --- Logging + notifications ------------------------------------------------

        internal static void Log(string level, string message)
        {
            string line = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") +
                " [" + level + "] " + message;
            try
            {
                Directory.CreateDirectory(DataDir);
                File.AppendAllText(LogFile, line + Environment.NewLine);
            }
            catch { /* logging is best-effort */ }
        }
    }
}
