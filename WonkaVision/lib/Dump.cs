using System;
using System.Collections.Generic;
using System.Text;
using System.Net;
using Newtonsoft.Json;
using WonkaVision.lib.extra.Interop;
using System.IO;

namespace WonkaVision.lib
{
    public class Dump
    {
        public class JsonOutFile
        {
            public string PublicKey;
            public string IV;
            public string Data;
        }

        public static void DumpSessionCreds(string dumpDir, string strPublicKey, LUID targetLuid = new LUID(), string targetService = null, string targetUser = null, string targetServer = null)
        {
            // displays a given .kirbi (KRB_CRED) object, with display options

            //  sessionCreds            -   list of one or more SESSION_CRED objects
            //  displayFormat           -   the TicketDisplayFormat to display the tickets in ("Triage" table, traditional "Klist", or "Full" for full ticket extraction)
            //  displayTGT              -   shortened display for monitor/harvesting
            //  displayB64ticket        -   display a base64 encoded version of the ticket
            //  extractKerberoastHash   -   extract out the rc4_hmac "kerberoastable" hash, if possible

            // extract out the tickets (w/ full data) with the specified targeting options
            List<LSA.SESSION_CRED> sessionCreds = LSA.EnumerateTickets(true, targetLuid, targetService, targetUser, targetServer, true);

            // skip any sessions without tickets
            List<LSA.SESSION_CRED> outCreds = new List<LSA.SESSION_CRED>();
            foreach (var sessionCred in sessionCreds)
            {
                if (sessionCred.Tickets.Count > 0)
                {
                    outCreds.Add(sessionCred);
                }
            }

            if (!String.IsNullOrEmpty(dumpDir))
            {

                // serialise as JSON and encrypt using the publickey
                string serializedCreds = JsonConvert.SerializeObject(outCreds);
                Tuple<byte[], byte[]> t = Crypto.CreateKeys();
                byte[] myPublicKey = t.Item1;
                byte[] myPrivateKey = t.Item2;
                byte[] publicKey;
                if (File.Exists(strPublicKey))
                {
                    try
                    {
                        publicKey = File.ReadAllBytes(strPublicKey);
                    }
                    catch (Exception ex)
                    {
                        Helpers.WriteConsole($"[X] Unable to read public key file: {ex.Message}");
                        return;
                    }
                }
                else
                {
                    try
                    {
                        publicKey = Convert.FromBase64String(strPublicKey);
                    }
                    catch (Exception ex)
                    {
                        Helpers.WriteConsole($"[X] Unable to convert public key from base64 encoded string: {ex.Message}");
                        return;
                    }
                }
                t = Crypto.EncryptData(myPrivateKey, publicKey, Encoding.UTF8.GetBytes(serializedCreds));
                JsonOutFile outdata = new JsonOutFile();
                outdata.IV = Convert.ToBase64String(t.Item1);
                outdata.Data = Convert.ToBase64String(t.Item2);
                outdata.PublicKey = Convert.ToBase64String(myPublicKey);
                string serializedOutdata = JsonConvert.SerializeObject(outdata);

                // determine filename
                string hostName = Dns.GetHostName();
                DateTime fileTime = DateTime.Now;
                string outfile = String.Format("{0}\\{1}.{2}.json", dumpDir, hostName, fileTime.ToString("yyyy_MM_dd_HH_mm_ss"));
                Helpers.WriteConsole($"[*] Writing LSA dump to {outfile}");

                // Write encrypted data
                Helpers.WriteBytesToFile(outfile, Encoding.UTF8.GetBytes(serializedOutdata), false);
            }
            else
            {
                foreach (var sessionCred in outCreds)
                {
                    Console.WriteLine("  UserName                 : {0}", sessionCred.LogonSession.Username);
                    Console.WriteLine("  Domain                   : {0}", sessionCred.LogonSession.LogonDomain);
                    Console.WriteLine("  LogonId                  : {0}", sessionCred.LogonSession.LogonID);
                    Console.WriteLine("  UserSID                  : {0}", sessionCred.LogonSession.Sid);
                    Console.WriteLine("  AuthenticationPackage    : {0}", sessionCred.LogonSession.AuthenticationPackage);
                    Console.WriteLine("  LogonType                : {0}", sessionCred.LogonSession.LogonType);
                    Console.WriteLine("  LogonTime                : {0}", sessionCred.LogonSession.LogonTime);
                    Console.WriteLine("  LogonServer              : {0}", sessionCred.LogonSession.LogonServer);
                    Console.WriteLine("  LogonServerDNSDomain     : {0}", sessionCred.LogonSession.DnsDomainName);
                    Console.WriteLine("  UserPrincipalName        : {0}\r\n", sessionCred.LogonSession.Upn);

                    for (int j = 0; j < sessionCred.Tickets.Count; j++)
                    {
                        var ticket = sessionCred.Tickets[j];
                        Console.WriteLine("    [{0:x}] - 0x{1:x} - {2}", j, (int)ticket.EncryptionType, (Interop.KERB_ETYPE)ticket.EncryptionType);
                        Console.WriteLine("      Start/End/MaxRenew: {0} ; {1} ; {2}", ticket.StartTime, ticket.EndTime, ticket.RenewTime);
                        Console.WriteLine("      Server Name       : {0} @ {1}", ticket.ServerName, ticket.ServerRealm);
                        Console.WriteLine("      Client Name       : {0} @ {1}", ticket.ClientName, ticket.ClientRealm);
                        Console.WriteLine("      Flags             : {0} ({1:x})\r\n", ticket.TicketFlags, (UInt32)ticket.TicketFlags);
                    }
                }
            }

        }
    }
}
