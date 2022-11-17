using System;
using System.IO;
using System.Collections.Generic;
using WonkaVision.lib;
//using WonkaVision.lib.krb;

namespace WonkaVision.cmds
{
    public class Analyze
    {
        public void Execute(Dictionary<string, string> arguments)
        {
            bool dcsync = true;
            string credUser = null;
            string credPass = null;
            string credDomain = null;
            string privateKey = null;


            if (arguments.ContainsKey("/privatekey"))
            {
                privateKey = arguments["/privatekey"];
            }
            if (arguments.ContainsKey("/nodcsync"))
                dcsync = false;
            
            if (arguments.ContainsKey("/creduser"))
                credUser = arguments["/creduser"];
            if (arguments.ContainsKey("/credpass"))
                credPass = arguments["/credpass"];
            if (arguments.ContainsKey("/creddomain"))
                credDomain = arguments["/creddomain"];

            if (String.IsNullOrEmpty(credDomain) && !String.IsNullOrEmpty(credUser) && (credUser.Split('\\').Length > 1 || credUser.Split('@').Length > 1))
            {
                if (credUser.Split('\\').Length > 1)
                {
                    credDomain = credUser.Split('\\')[0];
                    credUser = credUser.Split('\\')[1];
                }
                else if (credUser.Split('@').Length > 1)
                {
                    credDomain = credUser.Split('@')[1];
                    credUser = credUser.Split('@')[0];
                }
            }

            if ((!String.IsNullOrEmpty(credUser) && (String.IsNullOrEmpty(credPass) || String.IsNullOrEmpty(credDomain))) ||
                (!String.IsNullOrEmpty(credPass) && (String.IsNullOrEmpty(credUser) || String.IsNullOrEmpty(credDomain))) ||
                (!String.IsNullOrEmpty(credDomain) && (String.IsNullOrEmpty(credUser) || String.IsNullOrEmpty(credPass))))
            {
                Helpers.WriteConsole("[X] Error: When supplying alternative credentials a /creduser, /credpass and /creddomain are required!");
                return;
            }


            /*if (arguments.ContainsKey("/ticket"))
            {
                string kirbi64 = arguments["/ticket"];

                if (Helpers.IsBase64String(kirbi64))
                {
                    byte[] kirbiBytes = Convert.FromBase64String(kirbi64);
                    KRB_CRED kirbi = new KRB_CRED(kirbiBytes);
                    //lib.Analyze.AnalyzeTicket(kirbi, null, dcsync, credUser, credPass, credDomain);
                }
                else if (File.Exists(kirbi64))
                {
                    byte[] kirbiBytes = File.ReadAllBytes(kirbi64);
                    KRB_CRED kirbi = new KRB_CRED(kirbiBytes);
                    //lib.Analyze.AnalyzeTicket(kirbi, null, dcsync, credUser, credPass, credDomain);
                }
                else
                {
                    Console.WriteLine("\r\n[X] /ticket:X must either be a .kirbi file or a base64 encoded .kirbi\r\n");
                }
                return;
            }*/
            if (arguments.ContainsKey("/dumpdir"))
            {
                if (String.IsNullOrEmpty(privateKey))
                {
                    Helpers.WriteConsole("[X] Error: Consuming dump files requires /privatekey:X to be passed");
                    Info.Logo();
                    Console.WriteLine(Info.AnalyzeUsage());
                    return;
                }
                string dumpDir = arguments["/dumpdir"];
                if (Directory.Exists(dumpDir))
                {
                    lib.Analyze.AnalyzeDumps(dumpDir, privateKey, dcsync, credUser, credPass, credDomain);
                }
                else
                {
                    Helpers.WriteConsole($"[X] Error: {dumpDir} does not exist!");
                    Info.Logo();
                    Console.WriteLine(Info.AnalyzeUsage());
                }
            }
            else
            {
                Helpers.WriteConsole("[X] Error: /dumpdir:X needs to be supplied!");
                Info.Logo();
                Console.WriteLine(Info.AnalyzeUsage());
                return;
            }
        }
    }
}
