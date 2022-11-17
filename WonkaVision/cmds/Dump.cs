using System;
using System.Collections.Generic;
using System.IO;
using WonkaVision.lib.extra.Interop;

namespace WonkaVision.cmds
{
    public class Dump
    {
        public void Execute(Dictionary<string, string> arguments)
        {
            LUID targetLuid = new LUID();
            string targetUser = "";
            string targetService = "";
            string targetServer = "";
            string analyzePublicKey = null;
            string dumpDir = null;

            if (arguments.ContainsKey("/publickey"))
                analyzePublicKey = arguments["/publickey"];
            if (arguments.ContainsKey("/dumpdir"))
                dumpDir = arguments["/dumpdir"];

            if (!String.IsNullOrEmpty(dumpDir))
            {
                if (!Directory.Exists(dumpDir))
                {
                    lib.Helpers.WriteConsole($"[X] Error: Output directory {dumpDir} does not exist!");
                    lib.Info.Logo();
                    Console.WriteLine(lib.Info.DumpUsage());
                    return;
                }
            }

            if ((String.IsNullOrEmpty(analyzePublicKey) || String.IsNullOrEmpty(dumpDir)) && !arguments.ContainsKey("/analyze"))
            {
                lib.Helpers.WriteConsole("[X] Error: dumping tickets requires /publickey and /dumpdir to be passed to encrypt the output");
                lib.Info.Logo();
                Console.WriteLine(lib.Info.DumpUsage());
                return;
            }

            if (arguments.ContainsKey("/luid"))
            {
                try
                {
                    targetLuid = new LUID(arguments["/luid"]);
                }
                catch
                {
                    lib.Helpers.WriteConsole($"[X] Error: Invalid LUID format ({arguments["/luid"]})\r\n");
                    return;
                }
            }

            if (arguments.ContainsKey("/user"))
            {
                targetUser = arguments["/user"];
            }

            if (arguments.ContainsKey("/service"))
            {
                targetService = arguments["/service"];
            }

            if (arguments.ContainsKey("/server"))
            {
                targetServer = arguments["/server"];
            }
            // display tickets with the "Full" format
            lib.Dump.DumpSessionCreds(dumpDir, analyzePublicKey, targetLuid, targetService, targetUser, targetServer);
        }

        
    }
}
