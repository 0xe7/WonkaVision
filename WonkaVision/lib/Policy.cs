using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WonkaVision.lib
{
    public class Policy
    {
        // implementation adapted from https://github.com/tevora-threat/SharpView
        public static Dictionary<string, Dictionary<string, Object>> GetGptTmplContent(string path, string user = null, string password = null)
        {
            Dictionary<string, Dictionary<string, Object>> IniObject = new Dictionary<string, Dictionary<string, Object>>();
            string sysvolPath = String.Format("\\\\{0}\\SYSVOL", (new System.Uri(path).Host));

            int result = AddRemoteConnection(null, sysvolPath, user, password);
            if (result != (int)Interop.SystemErrorCodes.ERROR_SUCCESS)
            {
                return null;
            }

            if (System.IO.File.Exists(path))
            {
                var content = File.ReadAllLines(path);
                var CommentCount = 0;
                var Section = "";
                foreach (var line in content)
                {
                    if (Regex.IsMatch(line, @"^\[(.+)\]"))
                    {
                        Section = Regex.Split(line, @"^\[(.+)\]")[1].Trim();
                        Section = Regex.Replace(Section, @"\s+", "");
                        IniObject[Section] = new Dictionary<string, object>();
                        CommentCount = 0;
                    }
                    else if (Regex.IsMatch(line, @"^(;.*)$"))
                    {
                        var Value = Regex.Split(line, @"^(;.*)$")[1].Trim();
                        CommentCount = CommentCount + 1;
                        var Name = @"Comment" + CommentCount;
                        IniObject[Section][Name] = Value;
                    }
                    else if (Regex.IsMatch(line, @"(.+?)\s*=(.*)"))
                    {
                        var matches = Regex.Split(line, @"=");
                        var Name = Regex.Replace(matches[0].Trim(), @"\s+", "");
                        var Value = Regex.Replace(matches[1].Trim(), @"\s+", "");
                        // var Values = Value.Split(',').Select(x => x.Trim());

                        // if ($Values -isnot [System.Array]) { $Values = @($Values) }

                        IniObject[Section][Name] = Value;
                    }
                }
            }

            result = RemoveRemoteConnection(null, sysvolPath);

            return IniObject;
        }

        public static int AddRemoteConnection(string host = null, string path = null, string user = null, string password = null)
        {
            var NetResourceInstance = Activator.CreateInstance(typeof(Interop.NetResource)) as Interop.NetResource;
            List<string> paths = new List<string>();
            int returnResult = 0;

            if (host != null)
            {
                string targetComputerName = host.Trim('\\');
                paths.Add(String.Format("\\\\{0}\\IPC$", targetComputerName));
            }
            else
            {
                paths.Add(path);
            }

            foreach (string targetPath in paths)
            {
                NetResourceInstance.RemoteName = targetPath;
                NetResourceInstance.ResourceType = Interop.ResourceType.Disk;

                NetResourceInstance.RemoteName = targetPath;

                if (Program.Verbose)
                    Helpers.WriteConsole($"[*] Attempting to mount: {targetPath}");


                int result = Interop.WNetAddConnection2(NetResourceInstance, password, user, 4);

                if (result == (int)Interop.SystemErrorCodes.ERROR_SUCCESS)
                {
                    if (Program.Verbose)
                        Helpers.WriteConsole($"[*] {targetPath} successfully mounted");
                }
                else
                {
                    Helpers.WriteConsole($"[X] Error mounting {targetPath} error code {(Interop.SystemErrorCodes)result} ({result})");
                    returnResult = result;
                }
            }
            return returnResult;
        }

        public static int RemoveRemoteConnection(string host = null, string path = null)
        {

            List<string> paths = new List<string>();
            int returnResult = 0;

            if (host != null)
            {
                string targetComputerName = host.Trim('\\');
                paths.Add(String.Format("\\\\{0}\\IPC$", targetComputerName));
            }
            else
            {
                paths.Add(path);
            }

            foreach (string targetPath in paths)
            {
                if (Program.Verbose)
                    Helpers.WriteConsole($"[*] Attempting to unmount: {targetPath}");
                int result = Interop.WNetCancelConnection2(targetPath, 0, true);

                if (result == 0)
                {
                    if (Program.Verbose)
                        Helpers.WriteConsole($"[*] {targetPath} successfully unmounted");
                }
                else
                {
                    Helpers.WriteConsole($"[X] Error unmounting {targetPath}");
                    returnResult = result;
                }
            }
            return returnResult;
        }
    }
}
