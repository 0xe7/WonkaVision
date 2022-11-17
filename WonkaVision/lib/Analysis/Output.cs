using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace WonkaVision.lib.Analysis
{
    public class Output
    {
        public static int SessionEventId = 9988;

        public static int TicketEventId = 9989;

        public static void DisplayConsoleOutput(List<SessionDetections> sessionDetections)
        {
            foreach(var sd in sessionDetections)
            {
                // check session detections
                uint sessionScore = 0;
                string IOAOut = String.Empty;
                string Reasons = String.Empty;
                EventLogEntryType logType = EventLogEntryType.Information;
                foreach (string detection in sd.SessionIOAs.Keys)
                {
                    if (sd.SessionIOAs[detection].Score > 0)
                    {
                        sessionScore += sd.SessionIOAs[detection].Score;
                        IOAOut += String.Format("\t{0}: {1}\n", detection, sd.SessionIOAs[detection].Value);
                        Reasons += String.Format("{0} ", sd.SessionIOAs[detection].Reason);
                    }
                }
                if (sessionScore > 0)
                {
                    EventLog.WriteEntry("WonkaVision Session", String.Format("Possible compromised session\nTotal Score: {0}\nSession: {1}\nMachine Name: {2}\nUsername: {3}\n\nIOAs:\n\n{4}\n\nIOA Reasons: {5}", (int)sessionScore, sd.LoginID.ToString(), sd.MachineName, sd.Username, IOAOut, Reasons), logType, SessionEventId);
                }

                // check each ticket
                foreach (var td in sd.Tickets)
                {
                    if (td.FinalScore > 0)
                    {
                        // only output information on tickets that have scored above 0
                        Helpers.WriteConsole($"Machine: {sd.MachineName}; SessionUser: {sd.Username}; LogonID: {sd.LoginID}; TicketUser: {td.Username}; Service: {td.ServiceName}");
                        Helpers.WriteConsole($"\tSessionScore: {sessionScore}; TicketScore: {td.FinalScore + sd.Score}; MimikatzScore: {td.MimikatzScore}; ImpacketScore: {td.ImpacketScore}; RubeusScore: {td.RubeusScore}\r\n");

                        // write out IOAs
                        IOAOut = String.Empty;
                        Reasons = String.Empty;
                        foreach (string detection in td.Unencrypted.Keys)
                        {
                            if (td.Unencrypted[detection].Score > 0)
                            {
                                IOAOut += String.Format("\t{0}: {1}\n", detection, td.Unencrypted[detection].Value);
                                Reasons += String.Format("{0} ", td.Unencrypted[detection].Reason);
                            }
                        }

                        if (td.EncryptedPopulated)
                        {
                            foreach (string detection in td.Encrypted.Keys)
                            {
                                if (td.Encrypted[detection].Score > 0)
                                {
                                    IOAOut += String.Format("\t{0}: {1}\n", detection, td.Encrypted[detection].Value);
                                    Reasons += String.Format("{0} ", td.Encrypted[detection].Reason);
                                }
                            }
                        }

                        IOAOut += String.Format("\n\nTool Scores:\n\tMimikatz Score: {0}\n\tImpacket Score: {1}\n\tRubeus Score: {2}\n\tCobalt Strike Score: {3}\n", td.MimikatzScore, td.ImpacketScore, td.RubeusScore, td.CobaltStrikeScore);

                        EventLog.WriteEntry("WonkaVision Ticket", String.Format("Possible forged ticket\nTotal Score: {0}\nSession: {1}\nMachine Name: {2}\nUser: {3}\nService Principal Name: {4}\n\nIOAs:\n\n{5}\n\nIOA Reasons: {6}", (int)td.FinalScore, sd.LoginID.ToString(), sd.MachineName, td.Username, td.ServiceName, IOAOut, Reasons), logType, TicketEventId);
                    }
                }
            }
        }
    }
}
