using System;
using System.Linq;
using System.Globalization;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.IO;
using System.Text;
using Newtonsoft.Json;
using WonkaVision.Kerberos;
using WonkaVision.Kerberos.PAC;
using WonkaVision.lib.krb;
using WonkaVision.lib.Analysis;

namespace WonkaVision.lib
{
    public class Analyze
    {
        private static string CredentialUser = null;
        private static string CredentialDomain = null;
        private static string CredentialPassword = null;

        public static void AnalyzeDumps(string dumpDir, string strPrivateKey = null, bool dcsync = true, string credUser = null, string credPass = null, string credDomain = null, string outdir = null)
        {
            DirectoryInfo rootDir = new DirectoryInfo(dumpDir);
            FileInfo[] dumps = rootDir.GetFiles("*.json", SearchOption.AllDirectories);
            List<SessionDetections> sessionDetections = new List<SessionDetections>();

            CredentialUser = credUser;
            CredentialDomain = credDomain;
            CredentialPassword = credPass;

            Helpers.WriteConsole($"[*] Trying to deserialize json files in {dumpDir}");

            foreach (var dump in dumps)
            {
                string jsonText = null;
                try
                {
                    jsonText = Encoding.UTF8.GetString(File.ReadAllBytes(dump.FullName));
                }
                catch
                {
                    Helpers.WriteConsole($"[!] Unable to read file: {dump.FullName}, skipping...");
                    continue;
                }
                if (!String.IsNullOrEmpty(jsonText))
                {
                    byte[] iV;
                    byte[] publicKey;
                    byte[] encryptedData;

                    byte[] privateKey;
                    if (File.Exists(strPrivateKey))
                    {
                        try
                        {
                            privateKey = File.ReadAllBytes(strPrivateKey);
                        }
                        catch (Exception ex)
                        {
                            Helpers.WriteConsole($"[X] Unable to read private key file: {ex.Message}");
                            return;
                        }
                    }
                    else
                    {
                        try
                        {
                            privateKey = Convert.FromBase64String(strPrivateKey);
                        }
                        catch (Exception ex)
                        {
                            Helpers.WriteConsole($"[X] Unable to convert private key from base64 encoded string: {ex.Message}");
                            return;
                        }
                    }

                    try
                    {
                        Dump.JsonOutFile dumpFileJson = JsonConvert.DeserializeObject<Dump.JsonOutFile>(jsonText);
                        iV = Convert.FromBase64String(dumpFileJson.IV);
                        publicKey = Convert.FromBase64String(dumpFileJson.PublicKey);
                        encryptedData = Convert.FromBase64String(dumpFileJson.Data);
                    }
                    catch
                    {
                        Helpers.WriteConsole($"[!] Unable to deserialize json file {dump.FullName}, skipping...");
                        continue;
                    }
                    string plaintextData;
                    try
                    {
                        Helpers.WriteConsole($"[*] Decrypting {dump.FullName}");
                        plaintextData = Encoding.UTF8.GetString(Crypto.DecryptData(privateKey, publicKey, iV, encryptedData));
                    }
                    catch
                    {
                        Helpers.WriteConsole($"[!] Unable to decrypt data within file {dump.FullName}, skipping...");
                        continue;
                    }

                    List<LSA.SESSION_CRED> deserializedCreds;
                    try
                    {
                        deserializedCreds = JsonConvert.DeserializeObject<List<LSA.SESSION_CRED>>(plaintextData);
                    }
                    catch
                    {
                        Helpers.WriteConsole($"[!] Unable to deserialize decrypted data from file {dump.FullName}, skipping...");
                        continue;
                    }
                    foreach (var sessionCred in deserializedCreds)
                    {
                        if (sessionCred.Tickets.Count > 0)
                        {
                            SessionDetections sd = new SessionDetections();

                            Helpers.WriteConsole($"[*] Analyzing {sessionCred.Tickets.Count} tickets for session on {dump.Name.Split('.')[0]} with session ID {sessionCred.LogonSession.LogonID} and username {sessionCred.LogonSession.Username}");

                            // loop through each ticket in the session
                            for (int j = 0; j < sessionCred.Tickets.Count; j++)
                            {
                                var ticket = sessionCred.Tickets[j];
                                if (ticket.KrbCred != null)
                                {
                                    TicketDetections td = AnalyzeTicket(new KRB_CRED(ticket.KrbCred), sessionCred.LogonSession.Username, dcsync, ticket);
                                    if (td != null)
                                        sd.Tickets.Add(td);
                                }
                                else
                                {
                                    if (Program.Verbose)
                                        Helpers.WriteConsole($"[!] Unable to read ticket for user {ticket.ClientName} on domain {ticket.ClientRealm} for service {ticket.ServerName}, skipping...");
                                    continue;
                                }
                            }

                            if (sd.Tickets.Count > 0)
                            {
                                sd = AnalyzeSession(sd, dump.Name.Split('.')[0], sessionCred);

                                sessionDetections.Add(sd);
                            }
                        }
                    }

                    Helpers.WriteConsole("[*] Finished analyzing sessions, outputting findings.\r\n");

                    Output.DisplayConsoleOutput(sessionDetections);
                }
            }
        }

        public static SessionDetections AnalyzeSession(SessionDetections sd, string machineName, LSA.SESSION_CRED sessionCred)
        {
            /*Console.WriteLine("  UserName                 : {0}", sessionCred.LogonSession.Username);
            Console.WriteLine("  Domain                   : {0}", sessionCred.LogonSession.LogonDomain);
            Console.WriteLine("  LogonId                  : {0}", sessionCred.LogonSession.LogonID);
            Console.WriteLine("  UserSID                  : {0}", sessionCred.LogonSession.Sid);
            Console.WriteLine("  AuthenticationPackage    : {0}", sessionCred.LogonSession.AuthenticationPackage);
            Console.WriteLine("  LogonType                : {0}", sessionCred.LogonSession.LogonType);
            Console.WriteLine("  LogonTime                : {0}", sessionCred.LogonSession.LogonTime);
            Console.WriteLine("  LogonServer              : {0}", sessionCred.LogonSession.LogonServer);
            Console.WriteLine("  LogonServerDNSDomain     : {0}", sessionCred.LogonSession.DnsDomainName);
            Console.WriteLine("  UserPrincipalName        : {0}\r\n", sessionCred.LogonSession.Upn);*/

            // set some values
            sd.MachineName = machineName;
            sd.LoginID = sessionCred.LogonSession.LogonID;
            sd.Username = sessionCred.LogonSession.Username;

            // from Jared Atkinson (@jaredcatkinson) script: https://gist.github.com/jaredcatkinson/c95fd1e4e76a4b9b966861f64782f5a9
            sd.SessionIOAs["AuthenticationPackage"].Value = sessionCred.LogonSession.AuthenticationPackage;
            if (!sessionCred.LogonSession.AuthenticationPackage.Equals("Kerberos") && (((UInt64)sessionCred.LogonSession.LogonID.HighPart << 32) + sessionCred.LogonSession.LogonID.LowPart) != 999 && (((UInt64)sessionCred.LogonSession.LogonID.HighPart << 32) + sessionCred.LogonSession.LogonID.LowPart) != 996)
            {
                sd.SessionIOAs["AuthenticationPackage"].Score += 3;
                sd.SessionIOAs["AuthenticationPackage"].Reason += "Non Kerberos Authentication Package - Potential lateral movement. ";
            }
            else if (!sessionCred.LogonSession.AuthenticationPackage.Equals("Negotiate") && ((((UInt64)sessionCred.LogonSession.LogonID.HighPart << 32) + sessionCred.LogonSession.LogonID.LowPart) == 999 || (((UInt64)sessionCred.LogonSession.LogonID.HighPart << 32) + sessionCred.LogonSession.LogonID.LowPart) == 996))
            {
                sd.SessionIOAs["AuthenticationPackage"].Score += 2;
                sd.SessionIOAs["AuthenticationPackage"].Reason += String.Format("Non Negotiate Authentication Package for session {0} - Potential lateral movement. ", ((UInt64)sessionCred.LogonSession.LogonID.HighPart << 32) + sessionCred.LogonSession.LogonID.LowPart);
            }

            // look for initial TGT in session and username mismatch
            bool usernameMismatch = false;
            bool hasTGT = false;
            foreach (TicketDetections td in sd.Tickets)
            {
                if (td.IsTGT)
                    hasTGT = true;

                if (sd.Username != td.Username)
                {
                    usernameMismatch = true;
                    sd.SessionIOAs["UsernameMismatch"].Value = td.Username;
                }
            }
            if (!hasTGT && sd.Tickets.Count > 0 && !sd.Username.EndsWith("$"))
            {
                sd.SessionIOAs["LacksTGT"].Value = sd.Tickets.Select(t => t.ServiceName).Aggregate((cur, next) => cur + ", " + next);
                sd.SessionIOAs["LacksTGT"].Score += 3;
                sd.SessionIOAs["LacksTGT"].Reason += "The session lacks an initial TGT - Potential lateral movement. ";
            }
            if (usernameMismatch)
            {
                sd.SessionIOAs["UsernameMismatch"].Value = sd.Username;
                sd.SessionIOAs["UsernameMismatch"].Score += 3;
                sd.SessionIOAs["UsernameMismatch"].Reason += $"Session username {sd.Username} is different to at least 1 ticket ({sd.SessionIOAs["UsernameMismatch"].Value}). ";
            }

            return sd;
        }

        public static TicketDetections AnalyzeTicket(KRB_CRED cred, string sessionUsername, bool dcsync = true, LSA.KRB_TICKET ticket = null)
        {
            // displays a given .kirbi (KRB_CRED) object, with display options

            //  cred                    -   the KRB_CRED object to display
            //  indentLevel             -   level of indent, default of 2
            //  displayTGT              -   shortened display for monitor/harvesting
            //  displayB64ticket        -   display a base64 encoded version of the ticket
            //  extractKerberoastHash   -   extract out the rc4_hmac "kerberoastable" hash, if possible
            //  nowrap                  -   don't wrap base64 ticket output
            var userName = string.Join("@", cred.enc_part.ticket_info[0].pname.name_string.ToArray());
            var sname = string.Join("/", cred.enc_part.ticket_info[0].sname.name_string.ToArray());
            var keyType = String.Format("{0}", (Interop.KERB_ETYPE)cred.enc_part.ticket_info[0].key.keytype);
            string serviceName = sname.Split('/')[0];
            string serviceDomain = cred.enc_part.ticket_info[0].srealm.ToUpper();
            string principalDomain = cred.enc_part.ticket_info[0].prealm.ToUpper();
            Interop.TicketFlags flags = cred.enc_part.ticket_info[0].flags;
            string serviceDC = "";
            string principalDC = "";
            string principalForestRoot = "";
            string configOU = "";
            string netbiosName = "";
            byte[] serviceKey = null;
            byte[] asrepKey = null;
            byte[] krbKey = null;
            Dictionary<string, Dictionary<string, Object>> domainPolicy = null;
            List<Dictionary<string, Object>> adObjects = null;
            System.Net.NetworkCredential ldapCred = null;

            TicketDetections td = new TicketDetections();
            td.ServiceName = sname;
            td.Username = userName;

            // determine if initial TGT
            if (serviceDomain.Equals(principalDomain) && flags.HasFlag(Interop.TicketFlags.initial))
                td.IsTGT = true;

            //Console.WriteLine($"[*] Analyzing ticket for {userName}@{principalDomain} to {sname}@{serviceDomain}, KdcCalled: {ticket.KdcCalled}");

            // get DC for the service domain
            DirectoryContext directoryContext;
            if (String.IsNullOrWhiteSpace(CredentialUser) || String.IsNullOrWhiteSpace(CredentialDomain) || String.IsNullOrWhiteSpace(CredentialPassword))
                directoryContext = new DirectoryContext(DirectoryContextType.Domain, serviceDomain);
            else
                directoryContext = new DirectoryContext(DirectoryContextType.Domain, serviceDomain, $"{CredentialDomain}\\{CredentialUser}", CredentialPassword);

            try
            {
                using (var dc = DomainController.FindOne(directoryContext))
                {
                    serviceDC = dc.Name;
                }
            }
            catch
            {
                Helpers.WriteConsole($"[X] Unable to contact domain controller for domain {serviceDomain}, skipping...\r\n");
                return null;
            }

            //get DC for the principal domain
            if (serviceDomain.ToUpper().Equals(principalDomain.ToUpper()))
                principalDC = serviceDC;
            else
            {
                if (String.IsNullOrWhiteSpace(CredentialUser) || String.IsNullOrWhiteSpace(CredentialDomain) || String.IsNullOrWhiteSpace(CredentialPassword))
                    directoryContext = new DirectoryContext(DirectoryContextType.Domain, principalDomain);
                else
                    directoryContext = new DirectoryContext(DirectoryContextType.Domain, principalDomain, $"{CredentialDomain}\\{CredentialUser}", CredentialPassword);

                using (var dc = DomainController.FindOne(directoryContext))
                    principalDC = dc.Name;

            }
            if (String.IsNullOrWhiteSpace(CredentialUser) || String.IsNullOrWhiteSpace(CredentialDomain) || String.IsNullOrWhiteSpace(CredentialPassword))
                directoryContext = new DirectoryContext(DirectoryContextType.DirectoryServer, principalDC);
            else
                directoryContext = new DirectoryContext(DirectoryContextType.DirectoryServer, principalDC, $"{CredentialDomain}\\{CredentialUser}", CredentialPassword);

            using (var forest = Forest.GetForest(directoryContext))
            {
                principalForestRoot = forest.RootDomain.Name;
                configOU = String.Format("CN=Configuration,DC={0}", principalForestRoot.Replace(".", ",DC="));
            }
            if (!String.IsNullOrWhiteSpace(CredentialUser) && !String.IsNullOrWhiteSpace(CredentialDomain) && !String.IsNullOrWhiteSpace(CredentialPassword))
                ldapCred = new System.Net.NetworkCredential(CredentialUser, CredentialPassword, CredentialDomain);

            // dcsync service keys
            if (dcsync)
            {
                if (sname.Split('/').Length > 2)
                    sname = String.Format("{0}/{1}", sname.Split('/')[0], sname.Split('/')[1]);

                Dictionary<int, string> keys = null;
                if (Globals.AccountKeys.ContainsKey(serviceDomain))
                {
                    string serviceUser = Globals.GetMappedUsername(sname);
                    if (serviceUser != null && Globals.AccountKeys[serviceDomain].ContainsKey(serviceUser))
                        keys = Globals.AccountKeys[serviceDomain][serviceUser];
                }

                DCSync dcsyncObj = null;
                if (keys == null)
                {
                    dcsyncObj = new DCSync();
                    keys = dcsyncObj.Execute(sname, serviceDomain, serviceDC, CredentialUser, CredentialPassword, CredentialDomain);
                    if (keys == null)
                    {
                        Helpers.WriteConsole($"[!] Unable to dcsync service keys for {sname}@{serviceDomain}.");
                    }
                }
                if (keys != null)
                {
                    serviceKey = Helpers.StringToByteArray(keys[cred.tickets[0].enc_part.etype]);
                }

                // TODO: Get trust key if referral

                // if not a local TGT, get the krbtgt key too
                if (serviceKey != null && (!sname.Split('/')[0].Equals("krbtgt") || !sname.Split('/')[1].ToUpper().Equals(serviceDomain.ToUpper())))
                {
                    string krbName = $"krbtgt@{serviceDomain.ToLower()}";
                    if (!Globals.AccountKeys[serviceDomain].ContainsKey(krbName))
                    {
                        keys = dcsyncObj.Execute($"krbtgt/{serviceDomain}", serviceDomain, serviceDC, CredentialUser, CredentialPassword, CredentialDomain);
                    }
                    else
                    {
                        keys = Globals.AccountKeys[serviceDomain][krbName];
                    }


                    if (keys != null)
                    {
                        // for now always assume AES256 for kdc signature
                        krbKey = Helpers.StringToByteArray(keys[18]);
                    }
                }
            }

            // get domain policy
            if (Globals.DomainPolicy.ContainsKey(principalDomain))
                domainPolicy = Globals.DomainPolicy[principalDomain];
            else
            {
                adObjects = LDAP.GetLdapQuery(ldapCred, "", principalDC, principalDomain, "(name={31B2F340-016D-11D2-945F-00C04FB984F9})");
                if (adObjects == null)
                {
                    Helpers.WriteConsole("[!] Warning: Unable to get policy information using LDAP!");
                }
                else
                {
                    foreach (var o in adObjects)
                    {
                        if (o.ContainsKey("gpcfilesyspath"))
                        {
                            if (Program.Verbose)
                                Helpers.WriteConsole($"[*] Retrieving Domain policy file for {principalDomain}");
                            string gptTmplPath = String.Format("{0}\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf", (string)o["gpcfilesyspath"]);
                            gptTmplPath = gptTmplPath.Replace(String.Format("\\\\{0}\\", principalDomain.ToLower()), String.Format("\\\\{0}\\", principalDC));
                            string tmplUser = null;
                            if (!String.IsNullOrWhiteSpace(CredentialUser) && !String.IsNullOrWhiteSpace(CredentialDomain) && !String.IsNullOrWhiteSpace(CredentialPassword))
                                tmplUser = $"{CredentialDomain}\\{CredentialUser}";
                            domainPolicy = Policy.GetGptTmplContent(gptTmplPath, tmplUser, CredentialPassword);
                            if (domainPolicy == null)
                            {
                                Helpers.WriteConsole("[!] Warning: Unable to get domain policy information, unable to check PasswordCanChange and PasswordMustChange PAC fields or correct endtime and renew-till ticket lifetimes.");
                                continue;
                            }
                            Globals.DomainPolicy.Add(principalDomain, domainPolicy);
                        }
                    }
                }
            }

            if (!Globals.AccountInformation.ContainsKey(principalDomain))
                Globals.AccountInformation.Add(principalDomain, new Dictionary<string, Dictionary<string, Object>>());

            Dictionary<string, Object> adUser = null;
            List<int> groupIds = new List<int>();

            if (Globals.AccountInformation[principalDomain].ContainsKey(userName))
            {
                adUser = Globals.AccountInformation[principalDomain][userName];
                if (adUser != null && adUser.ContainsKey("groupids"))
                {
                    groupIds = (List<int>)adUser["groupids"];
                }
            }

            if (adUser == null)
            {
                // get ticket user information
                if (Program.Verbose)
                    Helpers.WriteConsole($"[*] Searching LDAP for user: {userName}");

                adObjects = LDAP.GetLdapQuery(ldapCred, "", principalDC, principalDomain, String.Format("(samaccountname={0})", userName));

                if (adObjects == null)
                {
                    Helpers.WriteConsole("[!] Warning: Unable to get principal information using LDAP!");
                    Globals.AccountInformation[principalDomain][userName] = null;
                }
                else
                {
                    adUser = adObjects[0];
                }
            }

            // get ticket group information
            if (adUser != null && !adUser.ContainsKey("groupids"))
            {
                string objectSid = (string)adUser["objectsid"];
                string domainSid = objectSid.Substring(0, objectSid.LastIndexOf('-'));

                // Get correct groups for user and domain GPO
                string filter = "";
                if (adUser.ContainsKey("memberof"))
                {
                    foreach (string groupDN in (string[])adUser["memberof"])
                    {
                        filter += String.Format("(distinguishedname={0})", groupDN);
                    }
                }

                if (Program.Verbose)
                    Helpers.WriteConsole("[*] Searching LDAP for group information");

                filter += String.Format("(objectsid={0}-{1})", domainSid, adUser["primarygroupid"]);
                filter = String.Format("(|{0})", filter);

                adObjects = LDAP.GetLdapQuery(ldapCred, "", principalDC, principalDomain, filter);
                if (adObjects == null)
                {
                    Helpers.WriteConsole("[!] Warning: Unable to get group information using LDAP!");
                }
                else
                {
                    foreach (var o in adObjects)
                    {
                        string groupSid = (string)o["objectsid"];
                        if (groupSid.StartsWith(domainSid))
                        {
                            int groupId = Int32.Parse(groupSid.Substring(groupSid.LastIndexOf('-') + 1));
                            groupIds.Add(groupId);
                        }
                    }
                    adUser["groupids"] = groupIds;
                }
                Globals.AccountInformation[principalDomain][userName] = adUser;
            }

            // get proper NetBios name
            if (Globals.NetbiosName.ContainsKey(principalDomain))
                netbiosName = Globals.NetbiosName[principalDomain];
            else
            {
                if (Program.Verbose)
                    Helpers.WriteConsole($"[*] Searching for netbios name in LDAP using configuration container: {configOU}");
                adObjects = LDAP.GetLdapQuery(ldapCred, configOU, principalDC, principalDomain, String.Format("(&(netbiosname=*)(dnsroot={0}))", principalDomain));
                if (adObjects == null)
                {
                    Helpers.WriteConsole("[!] Warning: Unable to get netbios name information using LDAP!");
                }
                else
                {
                    netbiosName = (string)adObjects[0]["netbiosname"];
                    Globals.NetbiosName.Add(principalDomain, netbiosName);
                }
            }

            // do unencrypted analysis
            td.Unencrypted = AnalyzeUnencrypted(cred, domainPolicy, adUser, sessionUsername, serviceKey == null, ticket, td.IsTGT);

            if (serviceKey != null)
            {
                EncTicketPart decryptedEncTicket = null;
                try
                {
                    decryptedEncTicket = cred.tickets[0].Decrypt(serviceKey, asrepKey);
                }
                catch
                {
                    Helpers.WriteConsole($"[!] Unable to decrypt the EncTicketPart using key: {Helpers.ByteArrayToString(serviceKey)}");
                }

                if (krbKey == null && (serviceName.Equals("krbtgt")) && (serviceDomain.ToUpper().Equals(sname.Split('/')[1].ToUpper())))
                {
                    krbKey = serviceKey;
                }

                if (decryptedEncTicket != null)
                {
                    // do encrypted analysis
                    td.Encrypted = AnalyzeEncrypted(decryptedEncTicket, serviceKey, krbKey, adUser, sname, netbiosName);
                    td.EncryptedPopulated = true;
                }
            }

            td = CalculateFinalScore(td);

            return td;
        }

        public static Dictionary<string, DetectionIOA> AnalyzeUnencrypted(KRB_CRED cred, Dictionary<string, Dictionary<string, Object>> domainPolicy, Dictionary<string, Object> adUser, string sessionUsername, bool checkTicketSize = false, LSA.KRB_TICKET ticket = null, bool IsInitialTGT = false)
        {
            Dictionary<string, DetectionIOA> ud = UnencryptedDetections.GetUnencrypted();

            // do unencrypted analysis

            // make sure the ticket user and session username match
            if (!String.IsNullOrWhiteSpace(sessionUsername))
            {
                ud["SessionUser"].Value = sessionUsername;
                if (!sessionUsername.Equals(cred.enc_part.ticket_info[0].pname.name_string[0]))
                {
                    ud["SessionUser"].Score += 3;
                    ud["SessionUser"].Reason += $"The session username ({sessionUsername}) and ticket username ({cred.enc_part.ticket_info[0].pname.name_string[0]}) differ. Potential lateral movement (pass-the-ticket). ";
                }
            }

            // Kdc Called
            ud["KDCCalled"].Value = ticket.KdcCalled;
            if (String.IsNullOrWhiteSpace(ud["KDCCalled"].Value) && !cred.enc_part.ticket_info[0].pname.name_string[0].EndsWith("$"))
            {
                ud["KDCCalled"].Score += 3;
                ud["KDCCalled"].Reason += $"KdcCalled information empty but expected value. Potential lateral movement. ";
            }


            // check ticket user
            ud["TicketUser"].Value = string.Join("@", cred.enc_part.ticket_info[0].pname.name_string.ToArray());
            if (adUser == null)
            {
                // invalid user
                ud["TicketUser"].Score += 3;
                ud["TicketUser"].Reason += "The ticket user was not found in LDAP suggesting that the user is not valid.";
            }

            // check endtime and renew-till
            int maxTicketAge = Int32.Parse((string)domainPolicy["KerberosPolicy"]["MaxTicketAge"]);
            int maxRenewAge = Int32.Parse((string)domainPolicy["KerberosPolicy"]["MaxRenewAge"]);
            int maxServiceAge = Int32.Parse((string)domainPolicy["KerberosPolicy"]["MaxServiceAge"]);
            DateTime startTime = cred.enc_part.ticket_info[0].starttime;
            DateTime endTime = cred.enc_part.ticket_info[0].endtime;
            ud["TicketEndTime"].Value = endTime.ToLocalTime().ToString(CultureInfo.CurrentCulture);
            DateTime renewTill = cred.enc_part.ticket_info[0].renew_till;
            ud["TicketRenewTill"].Value = renewTill.ToLocalTime().ToString(CultureInfo.CurrentCulture);
            // get logoff time
            DateTime logoffTime = DateTime.MaxValue;
            if (adUser != null && adUser.ContainsKey("logonhours"))
                logoffTime = ((LogonHours)adUser["logonhours"]).GetLogoffTime(startTime);
            if (adUser != null && ((List<int>)adUser["groupids"]).Contains(525))
            {
                // deal with members of the protected users group
                if (!TimeMatch(endTime, startTime.AddMinutes(240)))
                {
                    ud["TicketEndTime"].Score += 3;
                    ud["TicketEndTime"].Reason += $"User in Protected Users but ticket lifetime not 240 minutes. Ticket Starttime: {startTime.ToLocalTime().ToString(CultureInfo.CurrentCulture)}. ";
                }
                if (!TimeMatch(renewTill, startTime.AddMinutes(240)))
                {
                    ud["TicketRenewTill"].Score += 3;
                    ud["TicketRenewTill"].Reason += $"User in Protected Users but ticket renew time not 240 minutes. Ticket Starttime: {startTime.ToLocalTime().ToString(CultureInfo.CurrentCulture)}. ";
                }
            }
            else
            {
                // TODO: may need to rethink this, check for disallowed block of time
                // check times against domain policy and logoff time
                if (logoffTime == startTime)
                {
                    ud["TicketEndTime"].Score = 3;
                    ud["TicketEndTime"].Reason = $"Account configuration prohibits logon at {startTime.ToLocalTime().ToString(CultureInfo.CurrentCulture)}. ";
                }
                else
                {
                    if (logoffTime != DateTime.MaxValue && logoffTime < startTime.AddHours(maxTicketAge) && !logoffTime.Equals(endTime))
                    {
                        ud["TicketEndTime"].Score = 3;
                        ud["TicketEndTime"].Reason = $"Ticket lifetime does not match the account logoff time of {logoffTime.ToLocalTime().ToString(CultureInfo.CurrentCulture)}. ";
                    }
                    else if (IsInitialTGT && !TimeMatch(endTime, startTime.AddHours(maxTicketAge)))
                    {
                        ud["TicketEndTime"].Score = 3;
                        ud["TicketEndTime"].Reason = $"Ticket lifetime does not match the domain policy of {maxTicketAge} hours. Ticket Starttime: {startTime.ToLocalTime().ToString(CultureInfo.CurrentCulture)}. Expected Endtime {startTime.AddHours(maxTicketAge).ToLocalTime().ToString(CultureInfo.CurrentCulture)}. ";
                    }
                    else if (!IsInitialTGT && !TimeMatch(endTime, startTime.AddMinutes(maxServiceAge)))
                    {
                        ud["TicketEndTime"].Score = 3;
                        ud["TicketEndTime"].Reason = $"Ticket lifetime does not match the domain policy of {maxServiceAge} minutes. Ticket Starttime: {startTime.ToLocalTime().ToString(CultureInfo.CurrentCulture)}. Expected Endtime {startTime.AddMinutes(maxServiceAge).ToLocalTime().ToString(CultureInfo.CurrentCulture)}. ";
                    }
                    if (logoffTime != DateTime.MaxValue && logoffTime < startTime.AddDays(maxRenewAge) && !logoffTime.Equals(renewTill))
                    {
                        ud["TicketRenewTill"].Score = 3;
                        ud["TicketRenewTill"].Reason = $"Ticket renew time does not match the account logoff time of {logoffTime.ToLocalTime().ToString(CultureInfo.CurrentCulture)}. ";
                    }
                    else if (!TimeMatch(renewTill, startTime.AddDays(maxRenewAge)))
                    {
                        ud["TicketRenewTill"].Score = 3;
                        ud["TicketRenewTill"].Reason = $"Ticket renew time does not match the domain policy of {maxRenewAge} days. Ticket Starttime: {startTime.ToLocalTime().ToString(CultureInfo.CurrentCulture)}. Expected Renewtime: {startTime.AddDays(maxRenewAge).ToLocalTime().ToString(CultureInfo.CurrentCulture)}. ";
                    }
                }
            }

            // check for mimikatz and impacket defaults
            if (startTime.AddYears(10).AddDays(-2).Equals(endTime) && startTime.AddYears(10).AddDays(-2).Equals(renewTill))
            {
                ud["TicketEndTime"].MimiScore = 1;
                ud["TicketRenewTill"].MimiScore = 1;
                ud["TicketEndTime"].ImpacketScore = 1;
                ud["TicketRenewTill"].ImpacketScore = 1;
                ud["TicketEndTime"].Reason += "Using default impacket and mimikatz value. ";
                ud["TicketRenewTill"].Reason += "Using default impacket and mimikatz value. ";
            }
            else if (endTime.Equals(renewTill))
            {
                ud["TicketEndTime"].ImpacketScore = 1;
                ud["TicketRenewTill"].ImpacketScore = 1;
                ud["TicketEndTime"].Reason += "Using the same values for endtime and renew-till and the user is not in the Protected Users group, a sign of impacket. ";
                ud["TicketRenewTill"].Reason += "Using the same values for endtime and renew-till and the user is not in the Protected Users group, a sign of impacket. ";
            }

            // check Rubeus defaults
            if ((maxTicketAge != 10) && startTime.AddHours(10).Equals(endTime))
            {
                ud["TicketEndTime"].RubeusScore = 1;
                ud["TicketEndTime"].Reason += "Using default Rubeus value. ";
            }
            if ((maxRenewAge != 7) && startTime.AddDays(7).Equals(renewTill))
            {
                ud["TicketRenewTill"].RubeusScore = 1;
                ud["TicketRenewTill"].Reason += "Using default Rubeus value. ";
            }

            // check for Cobalt Strike default endtime
            if ((maxTicketAge != 8) && startTime.AddHours(8).Equals(endTime))
            {
                ud["TicketEndTime"].CobaltStrikeScore += 1;
                ud["TicketEndTime"].Reason += "Using default for Cobalt Strike's 'Golden Ticket' feature. ";
            }

            // check domains within the ticket
            string userRealm = cred.enc_part.ticket_info[0].prealm;
            ud["UserRealm"].Value = userRealm;
            string serviceRealm = cred.enc_part.ticket_info[0].srealm;
            ud["ServiceRealm"].Value = serviceRealm;
            if (!userRealm.Equals(userRealm.ToUpper()))
            {
                ud["UserRealm"].Score = 3;
                ud["UserRealm"].Reason = "Domain name is not uppercase. ";
                if (userRealm.Equals(userRealm.ToLower()))
                {
                    ud["UserRealm"].MimiScore = 1;
                    ud["UserRealm"].Reason += "Lowercase domain name (mimikatz default). ";
                }
            }
            if (!serviceRealm.Equals(serviceRealm.ToUpper()))
            {
                ud["ServiceRealm"].Score = 3;
                ud["ServiceRealm"].Reason = "Domain name is not uppercase. ";
                if (serviceRealm.Equals(serviceRealm.ToLower()))
                {
                    ud["ServiceRealm"].MimiScore = 1;
                    ud["ServiceRealm"].Reason += "Lowercase domain name (mimikatz default). ";
                }
            }

            // check encryption types
            Interop.LdapSupportedEncryptionTypes? supportedEtypes = null;
            Interop.KERB_ETYPE encType = (Interop.KERB_ETYPE)cred.tickets[0].enc_part.etype;
            ud["EncryptionType"].Value = String.Format("{0}", (uint)encType);
            string serviceName = string.Join("/", cred.enc_part.ticket_info[0].sname.name_string.ToArray());
            ud["ServiceName"].Value = serviceName;
            if (serviceName.Split('/')[0].Equals("krbtgt") && serviceName.Split('/')[1].ToUpper().Equals(serviceRealm.ToUpper()) && !encType.Equals(Interop.KERB_ETYPE.aes256_cts_hmac_sha1))
            {
                // local TGT's should always be AES256 encrypted
                ud["EncryptionType"].Score = 3;
                ud["EncryptionType"].MimiScore = 1;
                ud["EncryptionType"].ImpacketScore = 1;
                ud["EncryptionType"].RubeusScore = 1;
                ud["EncryptionType"].Reason = String.Format("Ticket encryption type is {0}. ", encType);
            }
            Dictionary<string, Object> serviceObject = null;
            if (!serviceName.Split('/')[0].Equals("krbtgt"))
            {
                // we should check the account supported encryption types for ST's
                string serviceUser = Globals.GetMappedUsername(serviceName);
                if (serviceUser != null)
                {
                    string sRealm = serviceRealm.ToUpper();
                    if (Globals.AccountInformation.ContainsKey(serviceRealm.ToUpper()) && Globals.AccountInformation[sRealm].ContainsKey(serviceUser))
                        serviceObject = Globals.AccountInformation[sRealm][serviceUser];

                    if (serviceObject != null && serviceObject.ContainsKey("msds-supportedencryptiontypes"))
                    {
                        supportedEtypes = (Interop.LdapSupportedEncryptionTypes)((int)serviceObject["msds-supportedencryptiontypes"]);
                        if (!encType.Equals(Interop.KERB_ETYPE.aes256_cts_hmac_sha1) && ((Interop.LdapSupportedEncryptionTypes)supportedEtypes).HasFlag(Interop.LdapSupportedEncryptionTypes.AES256))
                        {
                            ud["EncryptionType"].Score = 3;
                            ud["EncryptionType"].MimiScore = 1;
                            ud["EncryptionType"].ImpacketScore = 1;
                            ud["EncryptionType"].RubeusScore = 1;
                            ud["EncryptionType"].Reason = "Service account supports AES256 but the ticket encryption type is not AES256. ";
                        }
                    }
                }
            }

            // check flags (further testing for service tickets and referrals required!)
            // check them here because flags are different depending on service account UAC flags
            Interop.TicketFlags ticketFlags = cred.enc_part.ticket_info[0].flags;
            ud["TicketFlags"].Value = ticketFlags.ToString();
            if (!ticketFlags.HasFlag(Interop.TicketFlags.name_canonicalize))
            {
                ud["TicketFlags"].Score = 3;
                ud["TicketFlags"].MimiScore = 1;
                ud["TicketFlags"].ImpacketScore = 1;
                ud["TicketFlags"].RubeusScore = 1;
                ud["TicketFlags"].Reason = "Did not contain the 'name-canonicalize' flag. ";
            }
            if (ticketFlags.HasFlag(Interop.TicketFlags.proxiable))
            {
                ud["TicketFlags"].Score += 2;
                ud["TicketFlags"].ImpacketScore += 1;
                ud["TicketFlags"].Reason += "Contains 'proxiable' flag (impacket default). ";
            }
            if (serviceObject != null)
            {
                // only here if we're not dealing with any type of TGT
                Interop.LDAPUserAccountControl serviceUAC = (Interop.LDAPUserAccountControl)serviceObject["useraccountcontrol"];
                if (((serviceUAC & Interop.LDAPUserAccountControl.TRUSTED_FOR_DELEGATION) != 0) && !ticketFlags.HasFlag(Interop.TicketFlags.ok_as_delegate))
                {
                    ud["TicketFlags"].Score += 3;
                    ud["TicketFlags"].MimiScore += 1;
                    ud["TicketFlags"].ImpacketScore += 1;
                    ud["TicketFlags"].RubeusScore += 1;
                    ud["TicketFlags"].Reason += "Service account is TrustedForDelegation but 'ok-as-delegate' ticket flag not present. ";
                }
            }


            // check service name
            /*if (serviceName.Split('/')[0].Equals("krbtgt") && !serviceName.Split('/')[1].Equals(serviceRealm.ToLower()))
            {
                // genuine TGT's seem to have the domain lowercased in the SPN
                ud["ServiceName"].Score = 1;
                ud["ServiceName"].Reason = String.Format("Domain name in SPN is not lowercased: {0}. Could suggest impacket was used. ", serviceName.Split('/')[1]);
                ud["ServiceName"].ImpacketScore = 1;
            }*/

            // check key type - TODO Revisit avoiding false positives
            /*Interop.KERB_ETYPE keyType = (Interop.KERB_ETYPE)cred.enc_part.ticket_info[0].key.keytype;
            ud["KeyType"].Value = String.Format("{0}", keyType);
            if (adUser != null && adUser.ContainsKey("msds-supportedencryptiontypes"))
            {
                supportedEtypes = (Interop.LdapSupportedEncryptionTypes)((int)adUser["msds-supportedencryptiontypes"]);
                if (!keyType.Equals(Interop.KERB_ETYPE.aes256_cts_hmac_sha1) && ((Interop.LdapSupportedEncryptionTypes)supportedEtypes).HasFlag(Interop.LdapSupportedEncryptionTypes.AES256) && !(((string)adUser["samaccountname"]).EndsWith("$")))
                {
                    ud["KeyType"].Score = 2;
                    ud["KeyType"].Reason = "Account supports AES256 but the session key type is not AES256. ";
                }
            }*/

            // get the size of the EncTicketPart and check against 920 bytes for now
            // TODO: forge ticket and check against expected size?
            ud["EncryptedSize"].Value = String.Format("{0}", (uint)cred.tickets[0].enc_part.cipher.Length);
            if (checkTicketSize && cred.tickets[0].enc_part.cipher.Length < 920)
            {
                ud["EncryptedSize"].Score = 3;
                ud["EncryptedSize"].Reason = "Encrypted size too small for genuine ticket. ";
                ud["EncryptedSize"].ImpacketScore = 1;
                ud["EncryptedSize"].MimiScore = 1;
            }
            else
            {
                ud["EncryptedSize"].Checked = false;
            }

            return ud;
        }

        public static Dictionary<string, DetectionIOA> AnalyzeEncrypted(EncTicketPart decryptedEncTicket, byte[] serviceKey, byte[] krbKey, Dictionary<string, Object> adUser, string serviceName, string netbiosName)
        {
            Dictionary<string, DetectionIOA> ed = EncryptedDetections.GetEncrypted();

            bool isTGT = (serviceName.Split('/')[0].Equals("krbtgt") && serviceName.Split('/')[1].ToUpper().Equals(decryptedEncTicket.crealm.ToUpper())) || serviceName.ToUpper().Equals("kadmin/changepw");

            PACTYPE pt = decryptedEncTicket.GetPac(null);
            if (pt == null)
            {
                Helpers.WriteConsole("[X] Unable to get the PAC");
            }
            else
            {
                // grab domain policy
                Dictionary<string, Dictionary<string, Object>> domainPolicy = null;
                if (Globals.DomainPolicy.ContainsKey(decryptedEncTicket.crealm.ToUpper()))
                    domainPolicy = Globals.DomainPolicy[decryptedEncTicket.crealm.ToUpper()];

                // First deal with the checksums
                var validated = decryptedEncTicket.ValidatePac(serviceKey, krbKey);
                var checksums = decryptedEncTicket.GetChecksums();
                ed["ServerChecksum"].Value = Helpers.ByteArrayToString(checksums.Item1);
                ed["KDCChecksum"].Value = Helpers.ByteArrayToString(checksums.Item2);
                if (checksums.Item3 != null)
                {
                    ed["TicketChecksum"].Value = Helpers.ByteArrayToString(checksums.Item3);
                    // check if the ticket checksum was created using the service key
                    Interop.KERB_CHECKSUM_ALGORITHM? tktChecksumType = decryptedEncTicket.GetChecksumType(PacInfoBufferType.TicketChecksum);
                    if (tktChecksumType != null)
                    {
                        byte[] ticketChecksum = decryptedEncTicket.CalculateTicketChecksum(serviceKey, (Interop.KERB_CHECKSUM_ALGORITHM)tktChecksumType);
                        if (ed["TicketChecksum"].Value.Equals(Helpers.ByteArrayToString(ticketChecksum)))
                        {
                            ed["TicketChecksum"].Score += 3;
                            ed["TicketChecksum"].Reason = "Ticket checksum signed with the service key, very likely a Silver Ticket! ";
                        }
                    }
                }
                else
                    ed["TicketChecksum"].Value = "N/A";

                // if we're looking at a local TGT or kadmin/changepw ticket, no TicketChecksum will exist
                if (isTGT)
                    if (!ed["TicketChecksum"].Value.Equals("N/A"))
                    {
                        ed["TicketChecksum"].Score += 3;
                        ed["TicketChecksum"].Reason = "Ticket checksum exists on a local TGT, likely a Sapphire Ticket! ";
                    }
                    else
                        ed["TicketChecksum"].Checked = false;
                // else for now assume the TicketChecksum is supported and check for it
                else if (ed["TicketChecksum"].Value.Equals("N/A"))
                {
                    ed["TicketChecksum"].Score += 3;
                    ed["TicketChecksum"].Reason = "Ticket checksum does not exist for a service ticket, possibly a Silver Ticket! ";
                    ed["TicketChecksum"].MimiScore += 1;
                    ed["TicketChecksum"].ImpacketScore += 1;
                }

                if (!validated.Item1)
                {
                    ed["ServerChecksum"].Score = 2;
                    ed["ServerChecksum"].Reason = "Invalid ServerChecksum. Something weird has happened! Can decrypt the ticket but the ServerChecksum is incorrect, well worth investigating. ";
                }
                if (!validated.Item2)
                {
                    ed["KDCChecksum"].Score = 3;
                    ed["KDCChecksum"].Reason = "Invalid KDCChecksum. ";
                    if (!isTGT)
                    {
                        // check if KDCChecksum is signed with the service key
                        Interop.KERB_CHECKSUM_ALGORITHM? kdcChecksumType = decryptedEncTicket.GetChecksumType(PacInfoBufferType.KDCChecksum);
                        if (kdcChecksumType != null)
                        {
                            byte[] kdcChecksum = Crypto.KerberosChecksum(serviceKey, checksums.Item1, (Interop.KERB_CHECKSUM_ALGORITHM)kdcChecksumType);
                            if (ed["KDCChecksum"].Value.Equals(Helpers.ByteArrayToString(kdcChecksum)))
                            {
                                ed["KDCChecksum"].Score += 3;
                                ed["KDCChecksum"].Reason += "KDCChecksum created with the service key, very likely a Silver Ticket. ";
                            }
                            else
                            {
                                ed["KDCChecksum"].Reason += "Possibly a Silver Ticket. ";
                            }
                        }
                        else
                        {
                            ed["KDCChecksum"].Reason += "Possibly a Silver Ticket. ";
                        }
                    }
                    else
                        ed["KDCChecksum"].Reason += "Something weird has happened! Can decrypt the TGT but the KdcChecksum is incorrect, well worth investigating. ";
                }

                // check the other buffers
                bool upnDnsBuffer = false;
                bool requestorBuffer = false;
                bool attributesBuffer = false;
                bool extendedUpnDns = false;
                int userUAC = GenerateUserUAC((Interop.LDAPUserAccountControl)adUser["useraccountcontrol"]);
                foreach (var pacInfoBuffer in pt.PacInfoBuffers)
                {
                    // do KERB_VALIDATION_INFO checks
                    if (pacInfoBuffer is LogonInfo li)
                    {
                        // check fields that require LDAP results for the user here
                        if (adUser != null)
                        {
                            // check LogoffTime
                            DateTime logoffTime = DateTime.MaxValue;
                            try
                            {
                                logoffTime = DateTime.FromFileTimeUtc((long)li.KerbValidationInfo.LogoffTime.LowDateTime | ((long)li.KerbValidationInfo.LogoffTime.HighDateTime << 32));
                            }
                            catch { }
                            ed["LogoffTime"].Value = logoffTime.ToLocalTime().ToString(CultureInfo.CurrentCulture);
                            // get real logoff time
                            DateTime realLogoffTime = DateTime.MaxValue;
                            if (adUser.ContainsKey("logonhours"))
                                realLogoffTime = ((LogonHours)adUser["logonhours"]).GetLogoffTime(decryptedEncTicket.starttime);
                            // compare times
                            if (realLogoffTime != DateTime.MaxValue && logoffTime != realLogoffTime)
                            {
                                ed["LogoffTime"].Score = 3;
                                ed["LogoffTime"].Reason = String.Format("Logoff Time does not match the expected value of {0}. ", realLogoffTime.ToLocalTime().ToString(CultureInfo.CurrentCulture));
                                ed["LogoffTime"].ImpacketScore = 1;
                                ed["LogoffTime"].MimiScore = 1;
                                ed["LogoffTime"].RubeusScore = 1;
                            }

                            // check pwdlastset
                            DateTime pwdLastSet = DateTime.MaxValue;
                            try
                            {
                                pwdLastSet = DateTime.FromFileTimeUtc((long)li.KerbValidationInfo.PasswordLastSet.LowDateTime | ((long)li.KerbValidationInfo.PasswordLastSet.HighDateTime << 32));
                            }
                            catch { }
                            ed["PasswordLastSet"].Value = pwdLastSet.ToLocalTime().ToString(CultureInfo.CurrentCulture);
                            if (adUser.ContainsKey("pwdlastset") && (DateTime)adUser["pwdlastset"] != DateTime.MinValue && !((((DateTime)adUser["pwdlastset"]).AddSeconds(1) >= pwdLastSet) && (((DateTime)adUser["pwdlastset"]).AddSeconds(-1) <= pwdLastSet)))
                            {
                                ed["PasswordLastSet"].Score = 2;
                                ed["PasswordLastSet"].Reason = String.Format("Password Last Set does not match the expected value of {0}. ", ((DateTime)adUser["pwdlastset"]).ToLocalTime().ToString(CultureInfo.CurrentCulture));
                                ed["PasswordLastSet"].ImpacketScore = 1;
                                ed["PasswordLastSet"].MimiScore = 1;
                            }

                            // check Password Can Change and Password Must Change, only possible if domain policy has been retrieved
                            DateTime pwdCanChange = DateTime.MaxValue;
                            DateTime pwdMustChange = DateTime.MaxValue;
                            try
                            {
                                pwdCanChange = DateTime.FromFileTimeUtc((long)li.KerbValidationInfo.PasswordCanChange.LowDateTime | ((long)li.KerbValidationInfo.PasswordCanChange.HighDateTime << 32));
                            }
                            catch { }
                            try
                            {
                                pwdMustChange = DateTime.FromFileTimeUtc((long)li.KerbValidationInfo.PasswordMustChange.LowDateTime | ((long)li.KerbValidationInfo.PasswordMustChange.HighDateTime << 32));
                            }
                            catch { }
                            ed["PasswordCanChange"].Value = pwdCanChange.ToLocalTime().ToString(CultureInfo.CurrentCulture);
                            ed["PasswordMustChange"].Value = pwdMustChange.ToLocalTime().ToString(CultureInfo.CurrentCulture);
                            DateTime startTime = decryptedEncTicket.starttime;
                            // check if pwdCanChange == starttime, impacket default
                            if (pwdCanChange.Equals(startTime))
                            {
                                ed["PasswordCanChange"].Score += 3;
                                ed["PasswordCanChange"].Reason += $"PasswordCanChange field the same as StartTime of the ticket (impacket default): {pwdCanChange}. ";
                                ed["PasswordCanChange"].ImpacketScore += 2;
                            }
                            if (domainPolicy != null && adUser.ContainsKey("pwdlastset"))
                            {
                                int minPassAge = 0;
                                if (domainPolicy["SystemAccess"].ContainsKey("MinimumPasswordAge"))
                                    minPassAge = Int32.Parse((string)domainPolicy["SystemAccess"]["MinimumPasswordAge"]);

                                int maxPassAge = 0;
                                if (domainPolicy["SystemAccess"].ContainsKey("MaximumPasswordAge"))
                                    maxPassAge = Int32.Parse((string)domainPolicy["SystemAccess"]["MaximumPasswordAge"]);

                                if (minPassAge > 0)
                                {
                                    if (!pwdCanChange.Equals(((DateTime)adUser["pwdlastset"]).AddDays(minPassAge)))
                                    {
                                        ed["PasswordCanChange"].Score += 3;
                                        ed["PasswordCanChange"].Reason += $"Expected PasswordCanChange to be '{((DateTime)adUser["pwdlastset"]).AddDays(minPassAge).ToLocalTime().ToString(CultureInfo.CurrentCulture)}' but got '{ed["PasswordCanChange"].Value}'. ";
                                        ed["PasswordCanChange"].MimiScore += 1;
                                        ed["PasswordCanChange"].ImpacketScore += 1;
                                    }
                                }
                                // exclude computers for now
                                if (maxPassAge > 0 && !((Interop.LDAPUserAccountControl)adUser["useraccountcontrol"]).HasFlag(Interop.LDAPUserAccountControl.DONT_EXPIRE_PASSWORD) && !((Interop.LDAPUserAccountControl)adUser["useraccountcontrol"]).HasFlag(Interop.LDAPUserAccountControl.WORKSTATION_TRUST_ACCOUNT))
                                {
                                    if (!pwdMustChange.Equals(((DateTime)adUser["pwdlastset"]).AddDays(maxPassAge)))
                                    {
                                        ed["PasswordMustChange"].Score += 3;
                                        ed["PasswordMustChange"].Reason += $"Expected PasswordMustChange to be '{((DateTime)adUser["pwdlastset"]).AddDays(maxPassAge).ToLocalTime().ToString(CultureInfo.CurrentCulture)}' but got '{ed["PasswordMustChange"].Value}'. ";
                                        ed["PasswordMustChange"].MimiScore += 1;
                                        ed["PasswordMustChange"].ImpacketScore += 1;
                                    }
                                }
                            }

                            // skip effective name, do full name
                            ed["FullName"].Value = li.KerbValidationInfo.FullName.ToString();
                            if (adUser.ContainsKey("displayname"))
                            {
                                if (!((string)adUser["displayname"]).Equals(ed["FullName"].Value))
                                {
                                    ed["FullName"].Score += 1;
                                    ed["FullName"].Reason += $"Expected full name to be '{(string)adUser["displayname"]}' but got '{ed["FullName"].Value}'. ";
                                    ed["FullName"].MimiScore += 1;
                                    ed["FullName"].ImpacketScore += 1;
                                }
                            }
                            else if (!String.IsNullOrWhiteSpace(ed["FullName"].Value))
                            {
                                ed["FullName"].Score += 2;
                                ed["FullName"].Reason += $"Expected full name to be empty but got '{ed["FullName"].Value}'. ";
                                ed["FullName"].MimiScore += 1;
                                ed["FullName"].ImpacketScore += 1;
                            }

                            // logon script
                            ed["LogonScript"].Value = li.KerbValidationInfo.LogonScript.ToString();
                            if (adUser.ContainsKey("scriptpath"))
                            {
                                if (!((string)adUser["scriptpath"]).Equals(ed["LogonScript"].Value))
                                {
                                    ed["LogonScript"].Score += 1;
                                    ed["LogonScript"].Reason += $"Expected logon script to be '{(string)adUser["scriptpath"]}' but got '{ed["LogonScript"].Value}'. ";
                                    ed["LogonScript"].MimiScore += 1;
                                    ed["LogonScript"].ImpacketScore += 1;
                                }
                            }
                            else if (!String.IsNullOrWhiteSpace(ed["LogonScript"].Value))
                            {
                                ed["LogonScript"].Score += 2;
                                ed["LogonScript"].Reason += $"Expected logon script to be empty but got '{ed["LogonScript"].Value}'. ";
                                ed["LogonScript"].MimiScore += 1;
                                ed["LogonScript"].ImpacketScore += 1;
                            }

                            // profile path
                            ed["ProfilePath"].Value = li.KerbValidationInfo.ProfilePath.ToString();
                            if (adUser.ContainsKey("profilepath"))
                            {
                                if (!((string)adUser["profilepath"]).Equals(ed["ProfilePath"].Value))
                                {
                                    ed["ProfilePath"].Score += 1;
                                    ed["ProfilePath"].Reason += $"Expected profile path to be '{(string)adUser["profilepath"]}' but got '{ed["ProfilePath"].Value}'. ";
                                    ed["ProfilePath"].MimiScore += 1;
                                    ed["ProfilePath"].ImpacketScore += 1;
                                }
                            }
                            else if (!String.IsNullOrWhiteSpace(ed["ProfilePath"].Value))
                            {
                                ed["ProfilePath"].Score += 2;
                                ed["ProfilePath"].Reason += $"Expected profile path to be empty but got '{ed["ProfilePath"].Value}'. ";
                                ed["ProfilePath"].MimiScore += 1;
                                ed["ProfilePath"].ImpacketScore += 1;
                            }

                            // home directory
                            ed["HomeDirectory"].Value = li.KerbValidationInfo.HomeDirectory.ToString();
                            if (adUser.ContainsKey("homedirectory"))
                            {
                                if (!((string)adUser["homedirectory"]).Equals(ed["HomeDirectory"].Value))
                                {
                                    ed["HomeDirectory"].Score += 1;
                                    ed["HomeDirectory"].Reason += $"Expected home directory to be '{(string)adUser["homedirectory"]}' but got '{ed["HomeDirectory"].Value}'. ";
                                    ed["HomeDirectory"].MimiScore += 1;
                                    ed["HomeDirectory"].ImpacketScore += 1;
                                }
                            }
                            else if (!String.IsNullOrWhiteSpace(ed["HomeDirectory"].Value))
                            {
                                ed["HomeDirectory"].Score += 2;
                                ed["HomeDirectory"].Reason += $"Expected home directory to be empty but got '{ed["HomeDirectory"].Value}'. ";
                                ed["HomeDirectory"].MimiScore += 1;
                                ed["HomeDirectory"].ImpacketScore += 1;
                            }

                            // home drive
                            ed["HomeDirectoryDrive"].Value = li.KerbValidationInfo.HomeDirectoryDrive.ToString();
                            if (adUser.ContainsKey("homedrive"))
                            {
                                if (!((string)adUser["homedrive"]).Equals(ed["HomeDirectoryDrive"].Value))
                                {
                                    ed["HomeDirectoryDrive"].Score += 1;
                                    ed["HomeDirectoryDrive"].Reason += $"Expected logon script to be '{(string)adUser["homedrive"]}' but got '{ed["HomeDirectoryDrive"].Value}'. ";
                                    ed["HomeDirectoryDrive"].MimiScore += 1;
                                    ed["HomeDirectoryDrive"].ImpacketScore += 1;
                                }
                            }
                            else if (!String.IsNullOrWhiteSpace(ed["HomeDirectoryDrive"].Value))
                            {
                                ed["HomeDirectoryDrive"].Score += 2;
                                ed["HomeDirectoryDrive"].Reason += $"Expected logon script to be empty but got '{ed["HomeDirectoryDrive"].Value}'. ";
                                ed["HomeDirectoryDrive"].MimiScore += 1;
                                ed["HomeDirectoryDrive"].ImpacketScore += 1;
                            }

                            // Logon Count
                            ed["LogonCount"].Value = $"{li.KerbValidationInfo.LogonCount}";
                            /*if (adUser.ContainsKey("logoncount"))
                            {
                                if (((int)adUser["logoncount"] - LogonCountDifference) > (int)li.KerbValidationInfo.LogonCount || (int)li.KerbValidationInfo.LogonCount > (int)adUser["logoncount"])
                                {
                                    ed["LogonCount"].Score += 1;
                                    ed["LogonCount"].Reason += $"Expected logon count to be {adUser["logoncount"]} but got {ed["LogonCount"].Value}. ";
                                    ed["LogonCount"].MimiScore += 1;
                                    ed["LogonCount"].ImpacketScore += 1;
                                    if (li.KerbValidationInfo.LogonCount.Equals(500))
                                    {
                                        ed["LogonCount"].Score += 2;
                                        ed["LogonCount"].Reason += $"Using default impacket value. ";
                                        ed["LogonCount"].ImpacketScore += 1;
                                    }
                                    else if (li.KerbValidationInfo.LogonCount.Equals(0))
                                    {
                                        ed["LogonCount"].Score += 2;
                                        ed["LogonCount"].Reason += $"Using default mimikatz value. ";
                                        ed["LogonCount"].MimiScore += 1;
                                    }
                                }
                            }*/
                            if (!String.IsNullOrWhiteSpace(ed["LogonCount"].Value))
                            {
                                if (li.KerbValidationInfo.LogonCount.Equals(500) && (adUser.ContainsKey("logoncount") && (int)adUser["logoncount"] != 500))
                                {
                                    ed["LogonCount"].Score += 2;
                                    ed["LogonCount"].Reason += $"Using default impacket value. ";
                                    ed["LogonCount"].ImpacketScore += 1;
                                }
                            }

                            // BadPasswordCount
                            ed["BadPasswordCount"].Value = $"{li.KerbValidationInfo.BadPasswordCount}";
                            if (adUser.ContainsKey("badpwdcount"))
                            {
                                if ((int)adUser["badpwdcount"] != li.KerbValidationInfo.BadPasswordCount)
                                {
                                    ed["BadPasswordCount"].Score += 1;
                                    ed["BadPasswordCount"].Reason += $"Expected bad password count to be {adUser["badpwdcount"]} but got {ed["BadPasswordCount"].Value}. ";
                                    ed["BadPasswordCount"].MimiScore += 1;
                                    ed["BadPasswordCount"].ImpacketScore += 1;
                                }
                            }

                            // UserId
                            string userSid = (string)adUser["objectsid"];
                            int uid = Int32.Parse(userSid.Substring(userSid.LastIndexOf('-') + 1));
                            ed["UserID"].Value = $"{li.KerbValidationInfo.UserId}";
                            if (uid != li.KerbValidationInfo.UserId)
                            {
                                ed["UserID"].Score += 2;
                                ed["UserID"].Reason += $"Expected user ID to be {uid} but got {ed["UserID"].Value}. ";
                                ed["UserID"].MimiScore += 1;
                                ed["UserID"].ImpacketScore += 1;

                                if (li.KerbValidationInfo.UserId == 500)
                                {
                                    ed["UserID"].Reason += $"mimikatz and impacket default. ";
                                    ed["UserID"].MimiScore += 1;
                                    ed["UserID"].ImpacketScore += 1;
                                }
                            }

                            // primary group ID
                            ed["PrimaryGID"].Value = $"{li.KerbValidationInfo.PrimaryGroupId}";
                            if ((int)adUser["primarygroupid"] != li.KerbValidationInfo.PrimaryGroupId)
                            {
                                ed["PrimaryGID"].Score += 2;
                                ed["PrimaryGID"].Reason += $"Expected primary group ID to be {adUser["primarygroupid"]} but got {ed["PrimaryGID"].Value}. ";
                                ed["PrimaryGID"].MimiScore += 1;
                                ed["PrimaryGID"].ImpacketScore += 1;

                                if (li.KerbValidationInfo.PrimaryGroupId == 513)
                                {
                                    ed["PrimaryGID"].Reason += $"mimikatz and impacket default. ";
                                    ed["PrimaryGID"].MimiScore += 1;
                                    ed["PrimaryGID"].ImpacketScore += 1;
                                }
                            }

                            // groups
                            ed["GroupCount"].Value = li.KerbValidationInfo.GroupCount.ToString();
                            if (li.KerbValidationInfo.GroupCount > 0)
                                ed["GroupIds"].Value = li.KerbValidationInfo.GroupIds?.GetValue().Select(g => g.RelativeId.ToString()).Aggregate((cur, next) => cur + "," + next);
                            if (li.KerbValidationInfo.GroupCount > 0)
                            {
                                int invalidGroups = 0;
                                // check user groups
                                foreach (var groupId in li.KerbValidationInfo.GroupIds.GetValue())
                                {
                                    if (!((List<int>)adUser["groupids"]).Contains(groupId.RelativeId))
                                    {
                                        invalidGroups += 1;
                                    }
                                }
                                if (invalidGroups > 0)
                                {
                                    ed["GroupIds"].Score += 3;
                                    ed["GroupIds"].Reason += $"Invalid groups within PAC, should be: {((List<int>)adUser["groupids"]).Select(g => g.ToString()).Aggregate((cur, next) => cur + "," + next)}. ";
                                    ed["GroupIds"].MimiScore += 1;
                                    ed["GroupIds"].ImpacketScore += 1;
                                }
                                if (((List<int>)adUser["groupids"]).Count != 5 && li.KerbValidationInfo.GroupCount == 5)
                                {
                                    ed["GroupCount"].Score += 5;
                                    ed["GroupCount"].Reason += "Default impacket and mimikatz number of groups (5). ";
                                    ed["GroupCount"].MimiScore += 1;
                                    ed["GroupCount"].ImpacketScore += 1;
                                }

                            }
                            else if (((List<int>)adUser["groupids"]).Count > 0)
                            {
                                // check GroupIds field in PAC
                                int groupCount = 0;
                                int invalidGroups = 0;
                                foreach (var groupId in li.KerbValidationInfo.GroupIds?.GetValue().Select(g => g.RelativeId))
                                {
                                    groupCount += 1;
                                    if (!((List<int>)adUser["groupids"]).Contains(groupId))
                                    {
                                        invalidGroups += 1;
                                    }
                                }
                                if (groupCount > 0)
                                {
                                    ed["GroupCount"].Score += 1;
                                    ed["GroupCount"].Reason += $"Mismatch between GroupCount ({ed["GroupCount"].Value}) and number of RIDs within GroupIds field ({groupCount}). ";

                                }
                                if (invalidGroups > 0 || !((List<int>)adUser["groupids"]).Count.Equals(groupCount))
                                {
                                    ed["GroupIds"].Score += 3;
                                    ed["GroupIds"].Reason += $"Invalid groups within PAC, should be: {((List<int>)adUser["groupids"]).Select(g => g.ToString()).Aggregate((cur, next) => cur + "," + next)}. ";
                                    ed["GroupIds"].MimiScore += 1;
                                    ed["GroupIds"].ImpacketScore += 1;
                                }
                            }
                        }

                        // UserFlags

                        // NetBIOSName
                        if (!String.IsNullOrWhiteSpace(netbiosName))
                        {
                            ed["NetBIOSName"].Value = li.KerbValidationInfo.LogonDomainName.ToString();
                            if (!netbiosName.Equals(li.KerbValidationInfo.LogonDomainName.ToString()))
                            {
                                ed["NetBIOSName"].Score += 3;
                                ed["NetBIOSName"].Reason += $"NetBIOS name not the expected value of {netbiosName}. ";
                                ed["NetBIOSName"].ImpacketScore += 1;
                                ed["NetBIOSName"].MimiScore += 1;

                                if (decryptedEncTicket.crealm.ToUpper().Equals(li.KerbValidationInfo.LogonDomainName.ToString()))
                                {
                                    ed["NetBIOSName"].Reason += $"impacket default. ";
                                    ed["NetBIOSName"].ImpacketScore += 2;
                                }
                                else if (decryptedEncTicket.crealm.ToUpper().Split('.')[0].Equals(li.KerbValidationInfo.LogonDomainName.ToString()))
                                {
                                    ed["NetBIOSName"].Reason += $"mimikatz default. ";
                                    ed["NetBIOSName"].MimiScore += 2;
                                }
                            }
                        }

                        // LogonServer
                        ed["LogonServer"].Value = li.KerbValidationInfo.LogonServer.ToString();
                        if (String.IsNullOrWhiteSpace(li.KerbValidationInfo.LogonServer.ToString()))
                        {
                            ed["LogonServer"].Score = 3;
                            ed["LogonServer"].Reason = "Logon Server field empty. ";
                            ed["LogonServer"].ImpacketScore = 1;
                            ed["LogonServer"].MimiScore = 1;
                        }
                        else
                        {
                            // check if a valid DC name
                            bool found = false;
                            DirectoryContext directoryContext;
                            if (String.IsNullOrWhiteSpace(CredentialUser) || String.IsNullOrWhiteSpace(CredentialDomain) || String.IsNullOrWhiteSpace(CredentialPassword))
                                directoryContext = new DirectoryContext(DirectoryContextType.Domain, decryptedEncTicket.crealm);
                            else
                                directoryContext = new DirectoryContext(DirectoryContextType.Domain, decryptedEncTicket.crealm, $"{CredentialDomain}\\{CredentialUser}", CredentialPassword);
                            foreach (DomainController domainController in DomainController.FindAll(directoryContext))
                            {
                                string dcName = domainController.Name.Split('.')[0];
                                if (ed["LogonServer"].Value.ToUpper().Equals(dcName.ToUpper()))
                                    found = true;
                            }

                            if (!found)
                            {
                                ed["LogonServer"].Score = 2;
                                ed["LogonServer"].Reason = "Logon Server field contains invalid DC name. ";
                            }
                        }

                        // UAC
                        ed["UAC"].Value = $"{li.KerbValidationInfo.UserAccountControl}";
                        if (li.KerbValidationInfo.UserAccountControl != userUAC)
                        {
                            ed["UAC"].Score += 2;
                            ed["UAC"].Reason += $"UAC field not expected value of {userUAC}. ";
                            ed["UAC"].ImpacketScore += 1;
                            ed["UAC"].MimiScore += 1;
                            if (li.KerbValidationInfo.UserAccountControl == 528)
                            {
                                ed["UAC"].Reason += $"mimikatz and impacket default. ";
                                ed["UAC"].ImpacketScore += 1;
                                ed["UAC"].MimiScore += 1;
                            }
                        }

                        // check the SID history
                        if (li.KerbValidationInfo.SidCount > 0)
                            ed["ExtraSIDs"].Value = $"{li.KerbValidationInfo.ExtraSids.GetValue().Select(s => s.Sid.ToString()).Aggregate((cur, next) => cur + "," + next)}";
                        int sidHistoryCount = 0;
                        List<string> sidHistory = new List<string>();
                        if (adUser.ContainsKey("sidhistory"))
                        {
                            sidHistory = (List<string>)adUser["sidhistory"];
                            sidHistoryCount = sidHistory.Count;
                        }
                        if (li.KerbValidationInfo.SidCount > 0)
                        {
                            foreach (var sid in li.KerbValidationInfo.ExtraSids.GetValue())
                            {
                                if (!sidHistory.Contains(sid.Sid.ToString()) && !sid.Sid.ToString().Equals("S-1-5-9") && !sid.Sid.ToString().Equals("S-1-18-1"))
                                {
                                    ed["ExtraSIDs"].Score += 3;
                                    ed["ExtraSIDs"].Reason += $"Contains invalid SID {sid.Sid}. ";
                                }
                            }
                        }

                        // resource groups?
                    }
                    else if (pacInfoBuffer is UpnDns upnDns)
                    {
                        upnDnsBuffer = true;
                        if (upnDns.Flags.HasFlag(Interop.UpnDnsFlags.EXTENDED))
                        {
                            extendedUpnDns = true;
                        }
                    }
                    else if (pacInfoBuffer is Requestor requestor)
                    {
                        requestorBuffer = true;
                    }
                    else if (pacInfoBuffer is Attributes attr)
                    {
                        attributesBuffer = true;
                    }
                }

                // if UpnDns buffer not found
                if (!upnDnsBuffer)
                {
                    ed["UpnDNSBuffer"].Value = "None";
                    ed["UpnDNSBuffer"].Score += 3;
                    ed["UpnDNSBuffer"].Reason += "UpnDNS PAC_INFO_BUFFER does not exist. ";
                    ed["UpnDNSBuffer"].ImpacketScore += 1;
                    ed["UpnDNSBuffer"].MimiScore += 1;
                }
                else if (!extendedUpnDns)
                {
                    ed["UpnDNSBuffer"].Value = "Not Extended";
                    ed["UpnDNSBuffer"].Score += 2;
                    ed["UpnDNSBuffer"].Reason += "UpnDNS PAC_INFO_BUFFER does not contain the EXTENDED flag. ";
                    ed["UpnDNSBuffer"].ImpacketScore += 1;
                    ed["UpnDNSBuffer"].MimiScore += 1;
                    ed["UpnDNSBuffer"].RubeusScore += 1;
                }
                if (isTGT && !requestorBuffer)
                {
                    ed["RequestorBuffer"].Value = "None";
                    ed["RequestorBuffer"].Score += 3;
                    ed["RequestorBuffer"].Reason += "Requestor PAC_INFO_BUFFER does not exist. ";
                    ed["RequestorBuffer"].ImpacketScore += 1;
                    ed["RequestorBuffer"].MimiScore += 1;
                }
                if (isTGT && !attributesBuffer)
                {
                    ed["AttributesBuffer"].Value = "None";
                    ed["AttributesBuffer"].Score += 3;
                    ed["AttributesBuffer"].Reason += "Attributes PAC_INFO_BUFFER does not exist. ";
                    ed["AttributesBuffer"].ImpacketScore += 1;
                    ed["AttributesBuffer"].MimiScore += 1;
                }
            }

            return ed;
        }

        private static TicketDetections CalculateFinalScore(TicketDetections td)
        {
            foreach (var detection in td.Unencrypted.Keys)
            {
                if (td.Unencrypted[detection].Checked)
                {
                    td.FinalScore += td.Unencrypted[detection].Score;
                    td.MimikatzScore += td.Unencrypted[detection].MimiScore;
                    td.ImpacketScore += td.Unencrypted[detection].ImpacketScore;
                    td.RubeusScore += td.Unencrypted[detection].RubeusScore;
                    td.CobaltStrikeScore += td.Unencrypted[detection].CobaltStrikeScore;
                }
            }
            if (td.EncryptedPopulated)
            {
                foreach (var detection in td.Encrypted.Keys)
                {
                    if (td.Encrypted[detection].Checked)
                    {
                        td.FinalScore += td.Encrypted[detection].Score;
                        td.MimikatzScore += td.Encrypted[detection].MimiScore;
                        td.ImpacketScore += td.Encrypted[detection].ImpacketScore;
                        td.RubeusScore += td.Encrypted[detection].RubeusScore;
                        td.CobaltStrikeScore += td.Encrypted[detection].CobaltStrikeScore;
                    }
                }
            }

            return td;
        }

        // needed as genuine tickets can sometimes be minutes out of what you'd expect, so to avoid false positives check either side + or - TimeDifference seconds
        private static bool TimeMatch(DateTime timeToCheck, DateTime expectedTime)
        {
            return timeToCheck <= expectedTime;
        }

        // generate proper UAC attr
        private static int GenerateUserUAC(Interop.LDAPUserAccountControl userUAC)
        {
            var kvi = Ndr._KERB_VALIDATION_INFO.CreateDefault();
            kvi.UserAccountControl = 0;

            if ((userUAC & Interop.LDAPUserAccountControl.ACCOUNTDISABLE) != 0)
            {
                kvi.UserAccountControl |= (int)Interop.PacUserAccountControl.ACCOUNTDISABLE;
            }
            if ((userUAC & Interop.LDAPUserAccountControl.HOMEDIR_REQUIRED) != 0)
            {
                kvi.UserAccountControl |= (int)Interop.PacUserAccountControl.HOMEDIR_REQUIRED;
            }

            if ((userUAC & Interop.LDAPUserAccountControl.PASSWD_NOTREQD) != 0)
            {
                kvi.UserAccountControl |= (int)Interop.PacUserAccountControl.PASSWD_NOTREQD;
            }
            if ((userUAC & Interop.LDAPUserAccountControl.TEMP_DUPLICATE_ACCOUNT) != 0)
            {
                kvi.UserAccountControl |= (int)Interop.PacUserAccountControl.TEMP_DUPLICATE_ACCOUNT;
            }
            if ((userUAC & Interop.LDAPUserAccountControl.NORMAL_ACCOUNT) != 0)
            {
                kvi.UserAccountControl |= (int)Interop.PacUserAccountControl.NORMAL_ACCOUNT;
            }
            if ((userUAC & Interop.LDAPUserAccountControl.MNS_LOGON_ACCOUNT) != 0)
            {
                kvi.UserAccountControl |= (int)Interop.PacUserAccountControl.MNS_LOGON_ACCOUNT;
            }
            if ((userUAC & Interop.LDAPUserAccountControl.INTERDOMAIN_TRUST_ACCOUNT) != 0)
            {
                kvi.UserAccountControl |= (int)Interop.PacUserAccountControl.INTERDOMAIN_TRUST_ACCOUNT;
            }
            if ((userUAC & Interop.LDAPUserAccountControl.WORKSTATION_TRUST_ACCOUNT) != 0)
            {
                kvi.UserAccountControl |= (int)Interop.PacUserAccountControl.WORKSTATION_TRUST_ACCOUNT;
            }
            if ((userUAC & Interop.LDAPUserAccountControl.SERVER_TRUST_ACCOUNT) != 0)
            {
                kvi.UserAccountControl |= (int)Interop.PacUserAccountControl.SERVER_TRUST_ACCOUNT;
            }
            if ((userUAC & Interop.LDAPUserAccountControl.DONT_EXPIRE_PASSWORD) != 0)
            {
                kvi.UserAccountControl |= (int)Interop.PacUserAccountControl.DONT_EXPIRE_PASSWORD;
            }
            if ((userUAC & Interop.LDAPUserAccountControl.LOCKOUT) != 0)
            {
                kvi.UserAccountControl |= (int)Interop.PacUserAccountControl.ACCOUNT_AUTO_LOCKED;
            }
            if ((userUAC & Interop.LDAPUserAccountControl.ENCRYPTED_TEXT_PWD_ALLOWED) != 0)
            {
                kvi.UserAccountControl |= (int)Interop.PacUserAccountControl.ENCRYPTED_TEXT_PASSWORD_ALLOWED;
            }
            if ((userUAC & Interop.LDAPUserAccountControl.SMARTCARD_REQUIRED) != 0)
            {
                kvi.UserAccountControl |= (int)Interop.PacUserAccountControl.SMARTCARD_REQUIRED;
            }
            if ((userUAC & Interop.LDAPUserAccountControl.TRUSTED_FOR_DELEGATION) != 0)
            {
                kvi.UserAccountControl |= (int)Interop.PacUserAccountControl.TRUSTED_FOR_DELEGATION;
            }
            if ((userUAC & Interop.LDAPUserAccountControl.NOT_DELEGATED) != 0)
            {
                kvi.UserAccountControl |= (int)Interop.PacUserAccountControl.NOT_DELEGATED;
            }
            if ((userUAC & Interop.LDAPUserAccountControl.USE_DES_KEY_ONLY) != 0)
            {
                kvi.UserAccountControl |= (int)Interop.PacUserAccountControl.USE_DES_KEY_ONLY;
            }
            if ((userUAC & Interop.LDAPUserAccountControl.DONT_REQ_PREAUTH) != 0)
            {
                kvi.UserAccountControl |= (int)Interop.PacUserAccountControl.DONT_REQ_PREAUTH;
            }
            if ((userUAC & Interop.LDAPUserAccountControl.PASSWORD_EXPIRED) != 0)
            {
                kvi.UserAccountControl |= (int)Interop.PacUserAccountControl.PASSWORD_EXPIRED;
            }
            if ((userUAC & Interop.LDAPUserAccountControl.TRUSTED_TO_AUTH_FOR_DELEGATION) != 0)
            {
                kvi.UserAccountControl |= (int)Interop.PacUserAccountControl.TRUSTED_TO_AUTH_FOR_DELEGATION;
            }
            if ((userUAC & Interop.LDAPUserAccountControl.NO_AUTH_DATA_REQUIRED) != 0)
            {
                kvi.UserAccountControl |= (int)Interop.PacUserAccountControl.NO_AUTH_DATA_REQUIRED;
            }
            if ((userUAC & Interop.LDAPUserAccountControl.PARTIAL_SECRETS_ACCOUNT) != 0)
            {
                kvi.UserAccountControl |= (int)Interop.PacUserAccountControl.PARTIAL_SECRETS_ACCOUNT;
            }

            return kvi.UserAccountControl;
        }
    }
}
