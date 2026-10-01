// Guardian notifications: Windows event log + tray balloon (toast).

using System;
using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;

namespace Guardian
{
    internal static partial class Program
    {
        private const string EventSource = "Guardian";
        private const int EventId = 7001;

        private static void EnsureEventSource()
        {
            try
            {
                if (!EventLog.SourceExists(EventSource))
                    EventLog.CreateEventSource(EventSource, "Application");
            }
            catch { /* requires admin; best-effort */ }
        }

        internal enum NoticeKind { Info, Warning, Error }

        internal static void SendNotice(string title, string message, NoticeKind kind)
        {
            // Event log entry.
            try
            {
                EventLogEntryType etype;
                switch (kind)
                {
                    case NoticeKind.Error: etype = EventLogEntryType.Error; break;
                    case NoticeKind.Warning: etype = EventLogEntryType.Warning; break;
                    default: etype = EventLogEntryType.Information; break;
                }
                EventLog.WriteEntry(EventSource, title + "\n" + message, etype, EventId);
            }
            catch { }

            // Tray balloon. NotifyIcon needs a message pump; show briefly then dispose.
            try
            {
                ToolTipIcon tip;
                switch (kind)
                {
                    case NoticeKind.Error: tip = ToolTipIcon.Error; break;
                    case NoticeKind.Warning: tip = ToolTipIcon.Warning; break;
                    default: tip = ToolTipIcon.Info; break;
                }

                using (var ni = new NotifyIcon())
                {
                    ni.Icon = SystemIcons.Shield;
                    ni.Visible = true;
                    ni.ShowBalloonTip(8000, title, message, tip);
                    // Pump briefly so the balloon actually appears.
                    Application.DoEvents();
                    System.Threading.Thread.Sleep(250);
                    ni.Visible = false;
                }
            }
            catch { /* no interactive desktop when running as SYSTEM; log still captures it */ }
        }
    }
}
