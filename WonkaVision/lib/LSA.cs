using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.ComponentModel;
using System.Text.RegularExpressions;
using WonkaVision.lib.krb;
using WonkaVision.lib.extra.Interop;
using System.IO;

namespace WonkaVision.lib
{
    public class LSA
    {
        public class SESSION_CRED
        {
            // contains information on a logon session and any associated credentials
            //  used/returned by ExtractTickets

            public LogonSessionData LogonSession;

            public List<KRB_TICKET> Tickets;
        }

        public class KRB_TICKET
        {
            // contains cache info (i.e. KERB_TICKET_CACHE_INFO_EX) and the full .kirbi
            public string ClientName;
            public string ClientRealm;
            public string ServerName;
            public string ServerRealm;
            public DateTime StartTime;
            public DateTime EndTime;
            public DateTime RenewTime;
            public Int32 EncryptionType;
            public Interop.TicketFlags TicketFlags;
            public Interop.KERB_ETYPE SessionKeyType;
            public UInt32 BranchId;
            public Interop.LsaCacheFlags CacheFlags;
            public string KdcCalled;
            public byte[] KrbCred;
        }

        public static IntPtr LsaRegisterLogonProcessHelper()
        {
            // helper that establishes a connection to the LSA server and verifies that the caller is a logon application
            //  used for Kerberos ticket enumeration for ALL users

            var logonProcessName = "User32LogonProcess";
            Interop.LSA_STRING_IN LSAString;
            IntPtr lsaHandle = IntPtr.Zero;
            ulong securityMode = 0;

            LSAString.Length = (ushort)logonProcessName.Length;
            LSAString.MaximumLength = (ushort)(logonProcessName.Length + 1);
            LSAString.Buffer = logonProcessName;

            var ret = Interop.LsaRegisterLogonProcess(ref LSAString, out lsaHandle, out securityMode);

            return lsaHandle;
        }

        public static IntPtr GetLsaHandle()
        {
            // returns a handle to LSA
            //  uses LsaConnectUntrusted() if not in high integrity
            //  uses LsaRegisterLogonProcessHelper() if in high integrity

            IntPtr lsaHandle;

            if (!Helpers.IsHighIntegrity())
            {
                int retCode = Interop.LsaConnectUntrusted(out lsaHandle);
            }
            else
            {
                lsaHandle = LsaRegisterLogonProcessHelper();

                // if the original call fails then it is likely we don't have SeTcbPrivilege
                // to get SeTcbPrivilege we can Impersonate a NT AUTHORITY\SYSTEM Token
                if (lsaHandle == IntPtr.Zero)
                {
                    var currentName = WindowsIdentity.GetCurrent().Name;

                    if (Helpers.IsSystem())
                    {
                        // if we're already SYSTEM, we have the proper privilegess to get a Handle to LSA with LsaRegisterLogonProcessHelper
                        lsaHandle = LsaRegisterLogonProcessHelper();
                    }
                    else
                    {
                        // elevated but not system, so gotta GetSystem() first
                        if (!Helpers.GetSystem())
                        {
                            throw new Exception("Could not elevate to system");
                        }
                        // should now have the proper privileges to get a Handle to LSA
                        lsaHandle = LsaRegisterLogonProcessHelper();
                        // we don't need our NT AUTHORITY\SYSTEM Token anymore so we can revert to our original token
                        Interop.RevertToSelf();
                    }
                }
            }

            return lsaHandle;
        }

        public static byte[] ExtractTicket(IntPtr lsaHandle, int authPack, LUID userLogonID, string targetName, UInt32 ticketFlags = 0)
        {
            // extracts an encoded KRB_CRED for a specified userLogonID (LUID) and targetName (SPN)
            // by calling LsaCallAuthenticationPackage() w/ the KerbRetrieveEncodedTicketMessage message type

            var responsePointer = IntPtr.Zero;
            var request = new Interop.KERB_RETRIEVE_TKT_REQUEST();
            var response = new Interop.KERB_RETRIEVE_TKT_RESPONSE();
            var returnBufferLength = 0;
            var protocalStatus = 0;
            KRB_CRED ticketKirbi = null;
            byte[] encodedTicket = null;

            // signal that we want encoded .kirbi's returned
            request.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveEncodedTicketMessage;

            // the specific logon session ID
            request.LogonId = userLogonID;
            //request.TicketFlags = ticketFlags;
            request.TicketFlags = ticketFlags;
            // Note: ^ if a ticket has the forwarded flag (instead of initial), hard specifying the ticket
            //      flags here results in no match, and a new (RC4_HMAC?) ticket is requested but not cached
            //      from https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_retrieve_tkt_request :
            //          "If there is no match in the cache, a new ticket with the default flag values will be requested."
            //  Yes, I know this is weird. No, I have no idea why it happens. Specifying 0x0 (the default) will return just the main
            //      (initial) TGT, or a forwarded ticket if that's all that exists (a la the printer bug)
            request.CacheOptions = 0x8; // KERB_CACHE_OPTIONS.KERB_RETRIEVE_TICKET_AS_KERB_CRED - return the ticket as a KRB_CRED credential
            request.EncryptionType = 0x0;

            // the target ticket name we want the ticket for
            var tName = new Interop.UNICODE_STRING(targetName);
            request.TargetName = tName;

            // the following is due to the wonky way LsaCallAuthenticationPackage wants the KERB_RETRIEVE_TKT_REQUEST
            //      for KerbRetrieveEncodedTicketMessages

            // create a new unmanaged struct of size KERB_RETRIEVE_TKT_REQUEST + target name max len
            var structSize = Marshal.SizeOf(typeof(Interop.KERB_RETRIEVE_TKT_REQUEST));
            var newStructSize = structSize + tName.MaximumLength;
            var unmanagedAddr = Marshal.AllocHGlobal(newStructSize);

            // marshal the struct from a managed object to an unmanaged block of memory.
            Marshal.StructureToPtr(request, unmanagedAddr, false);

            // set tName pointer to end of KERB_RETRIEVE_TKT_REQUEST
            var newTargetNameBuffPtr = (IntPtr)((long)(unmanagedAddr.ToInt64() + (long)structSize));

            // copy unicode chars to the new location
            Interop.CopyMemory(newTargetNameBuffPtr, tName.buffer, tName.MaximumLength);

            // update the target name buffer ptr            
            Marshal.WriteIntPtr(unmanagedAddr, IntPtr.Size == 8 ? 24 : 16, newTargetNameBuffPtr);

            // actually get the data
            int retCode = Interop.LsaCallAuthenticationPackage(lsaHandle, authPack,
                unmanagedAddr, newStructSize, out responsePointer,
                out returnBufferLength, out protocalStatus);

            // TODO: is this needed?
            //if (retCode != 0)
            //{
            //    throw new NtException(retCode);
            //}

            // translate the LSA error (if any) to a Windows error
            var winError = Interop.LsaNtStatusToWinError((uint)protocalStatus);

            if ((retCode == 0) && ((uint)winError == 0) &&
                (returnBufferLength != 0))
            {
                // parse the returned pointer into our initial KERB_RETRIEVE_TKT_RESPONSE structure
                response =
                    (Interop.KERB_RETRIEVE_TKT_RESPONSE)Marshal.PtrToStructure(
                        (System.IntPtr)responsePointer,
                        typeof(Interop.KERB_RETRIEVE_TKT_RESPONSE));

                var encodedTicketSize = response.Ticket.EncodedTicketSize;

                // extract the ticket, build a KRB_CRED object, and add to the cache
                encodedTicket = new byte[encodedTicketSize];
                Marshal.Copy(response.Ticket.EncodedTicket, encodedTicket, 0,
                    encodedTicketSize);

                ticketKirbi = new KRB_CRED(encodedTicket);
            }
            else
            {
                var errorMessage = new Win32Exception((int)winError).Message;
                Helpers.WriteConsole($"[X] Error {winError} calling LsaCallAuthenticationPackage() for target \"{targetName}\" : {errorMessage}");
            }

            // clean up
            Interop.LsaFreeReturnBuffer(responsePointer);
            Marshal.FreeHGlobal(unmanagedAddr);

            return encodedTicket;
        }

        public static List<SESSION_CRED> EnumerateTickets(bool extractTicketData = false, LUID targetLuid = new LUID(), string targetService = null, string targetUser = null, string targetServer = null, bool includeComputerAccounts = true, bool silent = false)
        {
            //  Enumerates Kerberos tickets with various targeting options

            //  targetLuid              -   the target logon ID (LUID) to extract tickets for. Requires elevation.
            //  targetService           -   the target service name to extract tickets for (use "krbtgt" for TGTs)
            //  extractTicketData       -   extract full ticket data instead of just metadata information
            //  targetUser              -   the target user name to extract tickets for
            //  targetServer            -   the target full SPN (i.e. cifs/machine.domain.com) to extract tickets for
            //  includeComputerAccounts -   bool to include computer accounts in the output

            //  For elevated enumeration, the code first elevates to SYSTEM and uses LsaRegisterLogonProcessHelper() connect to LSA
            //      then calls LsaCallAuthenticationPackage w/ a KerbQueryTicketCacheMessage message type to enumerate all cached tickets
            //      and finally uses LsaCallAuthenticationPackage w/ a KerbRetrieveEncodedTicketMessage message type
            //      to extract the Kerberos ticket data in .kirbi format (service tickets and TGTs)

            //  For elevated enumeration, the code first uses LsaConnectUntrusted() to connect and LsaCallAuthenticationPackage w/ a KerbQueryTicketCacheMessage message type
            //      to enumerate all cached tickets, then uses LsaCallAuthenticationPackage w/ a KerbRetrieveEncodedTicketMessage message type
            //      to extract the Kerberos ticket data in .kirbi format (service tickets and TGTs)

            // adapted partially from Vincent LE TOUX' work
            //      https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2939-L2950
            // and https://www.dreamincode.net/forums/topic/135033-increment-memory-pointer-issue/
            // also Jared Atkinson's work at https://github.com/Invoke-IR/ACE/blob/master/ACE-Management/PS-ACE/Scripts/ACE_Get-KerberosTicketCache.ps1


            // sanity checks
            if (!Helpers.IsHighIntegrity() && (((ulong)targetLuid != 0) || (!String.IsNullOrEmpty(targetUser))))
            {
                Helpers.WriteConsole("[X] You need to be in high integrity for the actions specified.");
                return null;
            }

            if (!silent)
            {
                // silent mode is for "monitor"/"harvest" to prevent this data display each time
                if (!String.IsNullOrEmpty(targetService))
                {
                    Console.WriteLine("[*] Target service  : {0:x}", targetService);
                }
                if (!String.IsNullOrEmpty(targetServer))
                {
                    Console.WriteLine("[*] Target server   : {0:x}", targetServer);
                }
                if (!String.IsNullOrEmpty(targetUser))
                {
                    Console.WriteLine("[*] Target user     : {0:x}", targetUser);
                }
                if (((ulong)targetLuid != 0))
                {
                    Console.WriteLine("[*] Target LUID     : {0:x}", targetLuid);
                }

                Console.WriteLine("[*] Current LUID    : {0}\r\n", Helpers.GetCurrentLUID());
            }

            int retCode;
            int authPack;
            var name = "kerberos";
            var sessionCreds = new List<SESSION_CRED>();

            Interop.LSA_STRING_IN LSAString;
            LSAString.Length = (ushort)name.Length;
            LSAString.MaximumLength = (ushort)(name.Length + 1);
            LSAString.Buffer = name;

            var lsaHandle = GetLsaHandle();

            try
            {
                // obtains the unique identifier for the kerberos authentication package.
                retCode = Interop.LsaLookupAuthenticationPackage(lsaHandle, ref LSAString, out authPack);

                // STEP 1 - enumerate all current longon session IDs (LUID)
                //          if not elevated, this returns the current user's LUID
                //          if elevated, this returns ALL LUIDs
                foreach (var luid in EnumerateLogonSessions())
                {
                    // if we're targeting a specific LUID, check and skip if needed
                    if (((ulong)targetLuid != 0) && (luid != targetLuid))
                        continue;

                    // STEP 2 - get the actual data for this logon session (username, domain, logon time, etc.)
                    var logonSessionData = new LogonSessionData();
                    try
                    {
                        logonSessionData = GetLogonSessionData(luid);
                    }
                    catch
                    {
                        continue;
                    }

                    // start building the result object we want
                    SESSION_CRED sessionCred = new SESSION_CRED();
                    sessionCred.LogonSession = logonSessionData;
                    sessionCred.Tickets = new List<KRB_TICKET>();

                    // phase 1 of targeting

                    // exclude computer accounts unless instructed otherwise
                    /*if (!includeComputerAccounts && Regex.IsMatch(logonSessionData.Username, ".*\\$$"))
                        continue;*/
                    // if we're enumerating tickets/logon sessions for a specific user
                    if (!String.IsNullOrEmpty(targetUser) && !Regex.IsMatch(logonSessionData.Username, Regex.Escape(targetUser), RegexOptions.IgnoreCase))
                        continue;

                    var ticketsPointer = IntPtr.Zero;
                    var returnBufferLength = 0;
                    var protocalStatus = 0;

                    var ticketCacheRequest = new Interop.KERB_QUERY_TKT_CACHE_REQUEST();
                    var ticketCacheResponse = new Interop.KERB_QUERY_TKT_CACHE_RESPONSE();
                    Interop.KERB_TICKET_CACHE_INFO_EX3 ticketCacheResult;

                    // input object for querying the ticket cache for a specific logon ID
                    ticketCacheRequest.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheEx3Message;
                    if (Helpers.IsHighIntegrity())
                    {
                        ticketCacheRequest.LogonId = logonSessionData.LogonID;
                    }
                    else
                    {
                        // if we're not elevated, we have to have a LUID of 0 here to prevent failure
                        ticketCacheRequest.LogonId = new LUID();
                    }

                    var tQueryPtr = Marshal.AllocHGlobal(Marshal.SizeOf(ticketCacheRequest));
                    Marshal.StructureToPtr(ticketCacheRequest, tQueryPtr, false);

                    // STEP 3 - query LSA, specifying we want information for the ticket cache for this particular LUID
                    retCode = Interop.LsaCallAuthenticationPackage(lsaHandle, authPack, tQueryPtr,
                        Marshal.SizeOf(ticketCacheRequest), out ticketsPointer, out returnBufferLength,
                        out protocalStatus);

                    if (retCode != 0)
                    {
                        throw new NtException(retCode);
                    }

                    if (ticketsPointer != IntPtr.Zero)
                    {
                        // parse the returned pointer into our initial KERB_QUERY_TKT_CACHE_RESPONSE structure
                        ticketCacheResponse = (Interop.KERB_QUERY_TKT_CACHE_RESPONSE)Marshal.PtrToStructure(
                            (System.IntPtr)ticketsPointer, typeof(Interop.KERB_QUERY_TKT_CACHE_RESPONSE));
                        var count2 = ticketCacheResponse.CountOfTickets;

                        if (count2 != 0)
                        {
                            // get the size of the structures we're iterating over
                            var dataSize = Marshal.SizeOf(typeof(Interop.KERB_TICKET_CACHE_INFO_EX3));

                            for (var j = 0; j < count2; j++)
                            {
                                // iterate through the result structures
                                var currTicketPtr = (IntPtr)(long)((ticketsPointer.ToInt64() + (int)(8 + j * dataSize)));

                                // parse the new ptr to the appropriate structure
                                ticketCacheResult = (Interop.KERB_TICKET_CACHE_INFO_EX3)Marshal.PtrToStructure(
                                    currTicketPtr, typeof(Interop.KERB_TICKET_CACHE_INFO_EX3));

                                KRB_TICKET ticket = new KRB_TICKET();
                                ticket.StartTime = DateTime.FromFileTime(ticketCacheResult.StartTime);
                                ticket.EndTime = DateTime.FromFileTime(ticketCacheResult.EndTime);
                                ticket.RenewTime = DateTime.FromFileTime(ticketCacheResult.RenewTime);
                                ticket.TicketFlags = (Interop.TicketFlags)ticketCacheResult.TicketFlags;
                                ticket.EncryptionType = ticketCacheResult.EncryptionType;
                                ticket.ServerName = Marshal.PtrToStringUni(ticketCacheResult.ServerName.Buffer, ticketCacheResult.ServerName.Length / 2);
                                ticket.ServerRealm = Marshal.PtrToStringUni(ticketCacheResult.ServerRealm.Buffer, ticketCacheResult.ServerRealm.Length / 2);
                                ticket.ClientName = Marshal.PtrToStringUni(ticketCacheResult.ClientName.Buffer, ticketCacheResult.ClientName.Length / 2);
                                ticket.ClientRealm = Marshal.PtrToStringUni(ticketCacheResult.ClientRealm.Buffer, ticketCacheResult.ClientRealm.Length / 2);
                                ticket.SessionKeyType = (Interop.KERB_ETYPE)ticketCacheResult.SessionKeyType;
                                ticket.BranchId = ticketCacheResult.BranchId;
                                ticket.CacheFlags = (Interop.LsaCacheFlags)ticketCacheResult.CacheFlags;
                                ticket.KdcCalled = Marshal.PtrToStringUni(ticketCacheResult.KdcCalled.Buffer, ticketCacheResult.KdcCalled.Length / 2);

                                bool includeTicket = true;

                                if (!String.IsNullOrEmpty(targetService) && !Regex.IsMatch(ticket.ServerName, String.Format(@"^{0}/.*", Regex.Escape(targetService)), RegexOptions.IgnoreCase))
                                {
                                    includeTicket = false;
                                }
                                if (!String.IsNullOrEmpty(targetServer) && !Regex.IsMatch(ticket.ServerName, String.Format(@".*/{0}", Regex.Escape(targetServer)), RegexOptions.IgnoreCase))
                                {
                                    includeTicket = false;
                                }

                                if (includeTicket)
                                {
                                    if (extractTicketData)
                                    {
                                        // STEP 4 - query LSA again, specifying we want the actual ticket data for this particular ticket (.kirbi/KRB_CRED)
                                        ticket.KrbCred = ExtractTicket(lsaHandle, authPack, ticketCacheRequest.LogonId, ticket.ServerName, ticketCacheResult.TicketFlags);
                                    }
                                    sessionCred.Tickets.Add(ticket);
                                }
                            }
                        }
                    }

                    // cleanup
                    Interop.LsaFreeReturnBuffer(ticketsPointer);
                    Marshal.FreeHGlobal(tQueryPtr);

                    sessionCreds.Add(sessionCred);
                }
                // disconnect from LSA
                Interop.LsaDeregisterLogonProcess(lsaHandle);

                return sessionCreds;
            }
            catch (Exception ex)
            {
                Helpers.WriteConsole($"[X] Exception: {ex}");
                return null;
            }
        }

        public static List<LUID> EnumerateLogonSessions()
        {
            // returns a List of LUIDs representing current logon sessions
            var luids = new List<LUID>();

            if (!Helpers.IsHighIntegrity())
            {
                luids.Add(Helpers.GetCurrentLUID());
            }

            else
            {
                var ret = Interop.LsaEnumerateLogonSessions(out var count, out var luidPtr);

                if (ret != 0)
                {
                    throw new Win32Exception(ret);
                }

                for (ulong i = 0; i < count; i++)
                {
                    var luid = (LUID)Marshal.PtrToStructure(luidPtr, typeof(LUID));
                    luids.Add(luid);
                    luidPtr = (IntPtr)(luidPtr.ToInt64() + Marshal.SizeOf(typeof(LUID)));
                }
                Interop.LsaFreeReturnBuffer(luidPtr);
            }

            return luids;
        }

        public class LogonSessionData
        {
            public LUID LogonID;
            public string Username;
            public string LogonDomain;
            public string AuthenticationPackage;
            public Interop.LogonType LogonType;
            public int Session;
            public string Sid;
            public DateTime LogonTime;
            public string LogonServer;
            public string DnsDomainName;
            public string Upn;
        }

        public enum TicketDisplayFormat : int
        {
            None = 0,           // if we're just after enumerated tickets
            Triage = 1,         // triage table output
            Klist = 2,          // traditional klist format
            Full = 3            // full ticket data extraction (a la "dump")
        }

        public static LogonSessionData GetLogonSessionData(LUID luid)
        {
            // gets additional logon session information for a given LUID

            var luidPtr = IntPtr.Zero;
            var sessionDataPtr = IntPtr.Zero;

            try
            {
                luidPtr = Marshal.AllocHGlobal(Marshal.SizeOf(luid));
                Marshal.StructureToPtr(luid, luidPtr, false);

                var ret = Interop.LsaGetLogonSessionData(luidPtr, out sessionDataPtr);
                if (ret != 0)
                {
                    throw new Win32Exception((int)ret);
                }

                var unsafeData =
                    (Interop.SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(sessionDataPtr,
                        typeof(Interop.SECURITY_LOGON_SESSION_DATA));

                return new LogonSessionData()
                {
                    AuthenticationPackage = Marshal.PtrToStringUni(unsafeData.AuthenticationPackage.Buffer, unsafeData.AuthenticationPackage.Length / 2),
                    DnsDomainName = Marshal.PtrToStringUni(unsafeData.DnsDomainName.Buffer, unsafeData.DnsDomainName.Length / 2),
                    LogonDomain = Marshal.PtrToStringUni(unsafeData.LoginDomain.Buffer, unsafeData.LoginDomain.Length / 2),
                    LogonID = unsafeData.LoginID,
                    LogonTime = DateTime.FromFileTime((long)unsafeData.LoginTime),
                    //LogonTime = systime.AddTicks((long)unsafeData.LoginTime),
                    LogonServer = Marshal.PtrToStringUni(unsafeData.LogonServer.Buffer, unsafeData.LogonServer.Length / 2),
                    LogonType = (Interop.LogonType)unsafeData.LogonType,
                    Sid = (unsafeData.PSiD == IntPtr.Zero ? null : (new SecurityIdentifier(unsafeData.PSiD)).ToString()),
                    Upn = Marshal.PtrToStringUni(unsafeData.Upn.Buffer, unsafeData.Upn.Length / 2),
                    Session = (int)unsafeData.Session,
                    Username = Marshal.PtrToStringUni(unsafeData.Username.Buffer, unsafeData.Username.Length / 2),
                };
            }
            finally
            {
                if (sessionDataPtr != IntPtr.Zero)
                    Interop.LsaFreeReturnBuffer(sessionDataPtr);

                if (luidPtr != IntPtr.Zero)
                    Marshal.FreeHGlobal(luidPtr);
            }
        }
    }
}
