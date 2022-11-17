using System;
using System.Security.Principal;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Linq;
using System.IO;
using System.Text.RegularExpressions;
using WonkaVision.lib.extra.Interop;

namespace WonkaVision.lib
{
    public class Helpers
    {
        public static bool IsBase64String(string s)
        {
            s = s.Trim();
            return (s.Length % 4 == 0) && Regex.IsMatch(s, @"^[a-zA-Z0-9\+/]*={0,3}$", RegexOptions.None);
        }

        public static byte[] StringToByteArray(string hex)
        {
            // converts a string into a byte array representation

            // yes I know this inefficient
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        //StackOverflow goodness
        public static string ByteArrayToString(byte[] bytes)
        {
            char[] c = new char[bytes.Length * 2];
            int b;
            for (int i = 0; i < bytes.Length; i++)
            {
                b = bytes[i] >> 4;
                c[i * 2] = (char)(55 + b + (((b - 10) >> 31) & -7));
                b = bytes[i] & 0xF;
                c[i * 2 + 1] = (char)(55 + b + (((b - 10) >> 31) & -7));
            }
            return new string(c);
        }

        public static bool IsHighIntegrity()
        {
            // returns true if the current process is running with adminstrative privs in a high integrity context
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        public static bool GetSystem()
        {
            // helper to elevate to SYSTEM for Kerberos ticket enumeration via token impersonation
            if (IsHighIntegrity())
            {
                IntPtr hToken;

                // Open winlogon's token with TOKEN_DUPLICATE accesss so ca can make a copy of the token with DuplicateToken
                Process[] processes = Process.GetProcessesByName("winlogon");
                IntPtr handle = processes[0].Handle;

                // TOKEN_DUPLICATE = 0x0002
                bool success = Interop.OpenProcessToken(handle, 0x0002, out hToken);
                if (!success)
                {
                    WriteConsole("[!] GetSystem() - OpenProcessToken failed!");
                    return false;
                }

                // make a copy of the NT AUTHORITY\SYSTEM token from winlogon
                // 2 == SecurityImpersonation
                IntPtr hDupToken = IntPtr.Zero;
                success = Interop.DuplicateToken(hToken, 2, ref hDupToken);
                if (!success)
                {
                    WriteConsole("[!] GetSystem() - DuplicateToken failed!");
                    return false;
                }

                success = Interop.ImpersonateLoggedOnUser(hDupToken);
                if (!success)
                {
                    WriteConsole("[!] GetSystem() - ImpersonateLoggedOnUser failed!");
                    return false;
                }

                // clean up the handles we created
                Interop.CloseHandle(hToken);
                Interop.CloseHandle(hDupToken);

                if (!IsSystem())
                {
                    return false;
                }

                return true;
            }
            else
            {
                return false;
            }
        }

        public static bool IsSystem()
        {
            // returns true if the current user is "NT AUTHORITY\SYSTEM"
            var currentSid = WindowsIdentity.GetCurrent().User;
            return currentSid.IsWellKnown(WellKnownSidType.LocalSystemSid);
        }

        public static LUID GetCurrentLUID()
        {
            // helper that returns the current logon session ID by using GetTokenInformation w/ TOKEN_INFORMATION_CLASS

            var TokenInfLength = 0;
            var luid = new LUID();

            // first call gets lenght of TokenInformation to get proper struct size
            var Result = Interop.GetTokenInformation(WindowsIdentity.GetCurrent().Token, Interop.TOKEN_INFORMATION_CLASS.TokenStatistics, IntPtr.Zero, TokenInfLength, out TokenInfLength);

            var TokenInformation = Marshal.AllocHGlobal(TokenInfLength);

            // second call actually gets the information
            Result = Interop.GetTokenInformation(WindowsIdentity.GetCurrent().Token, Interop.TOKEN_INFORMATION_CLASS.TokenStatistics, TokenInformation, TokenInfLength, out TokenInfLength);

            if (Result)
            {
                var TokenStatistics = (Interop.TOKEN_STATISTICS)Marshal.PtrToStructure(TokenInformation, typeof(Interop.TOKEN_STATISTICS));
                luid = new LUID(TokenStatistics.AuthenticationId);
            }
            else
            {
                var lastError = Interop.GetLastError();
                WriteConsole($"[X] GetTokenInformation error: {lastError}");
                Marshal.FreeHGlobal(TokenInformation);
            }

            return luid;
        }

        static public bool WriteBytesToFile(string filename, byte[] data, bool overwrite = false)
        {
            bool result = true;
            string filePath = Path.GetFullPath(filename);

            try
            {
                if (!overwrite)
                {
                    if (File.Exists(filePath))
                    {
                        throw new Exception(String.Format("{0} already exists! Data not written to file.\r\n", filePath));
                    }
                }
                File.WriteAllBytes(filePath, data);
            }
            catch (Exception e)
            {
                WriteConsole($"[X] Exception: {e.Message}");
                result = false;
            }

            return result;
        }

        public static string RandomString(int length)
        {
            Random random = new Random();

            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length)
                .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        public static void WriteConsole(string message)
        {
            if (message.StartsWith("[X]"))
            {
                Console.ForegroundColor = ConsoleColor.Red;
            }
            else if (message.StartsWith("[!]"))
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.White;
            }
            Console.WriteLine(message);
            Console.ForegroundColor = ConsoleColor.White;
        }
    }
}
