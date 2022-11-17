using System;
using System.Collections.Generic;
using WonkaVision.lib.extra.Interop;

namespace WonkaVision.lib.Analysis
{
    public class SessionDetections
    {
        public string MachineName { get; set; }

        public LUID LoginID { get; set; }

        public string Username { get; set; }

        public Dictionary<string, DetectionIOA> SessionIOAs { get; set; }

        public uint Score { get; set; }

        public List<TicketDetections> Tickets { get; set; }

        public SessionDetections()
        {
            Score = 0;
            SessionIOAs = Analysis.SessionIOAs.GetSessionIOAs();
            Tickets = new List<TicketDetections>();
        }
    }
}
