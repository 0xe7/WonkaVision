using System;
using System.Collections.Generic;

namespace WonkaVision
{
    public class Program
    {
        public static bool Verbose = false;
        public static void Main(string[] args)
        {
            Dictionary<string, string> arguments;
            try
            {
                var parsed = lib.ArgumentParser.Parse(args);
                if (parsed.ParsedOk == false)
                {
                    Console.WriteLine(lib.Info.FullUsage());
                    return;
                }
                arguments = parsed.Arguments;

            }
            catch (Exception e)
            {
                lib.Helpers.WriteConsole("[X] Unhandled WonkaVision exception:\r\n");
                lib.Helpers.WriteConsole($"{e}");
                return;
            }
            if (arguments.Count == 0)
            {
                Console.WriteLine(lib.Info.FullUsage());
                return;
            }

            Verbose = arguments.ContainsKey("/verbose");

            if (arguments == null)
            {
                lib.Helpers.WriteConsole("[X] Unable to parse arguments!");
                Console.WriteLine(lib.Info.FullUsage());
                return;
            }

            if (arguments.ContainsKey("/dump"))
            {
                cmds.Dump dump = new cmds.Dump();
                dump.Execute(arguments);
            }
            else if (arguments.ContainsKey("/analyze"))
            {
                cmds.Analyze analyze = new cmds.Analyze();
                analyze.Execute(arguments);
            }
            else if (arguments.ContainsKey("/createkeys"))
            {
                cmds.GenerateKeys k = new cmds.GenerateKeys();
                k.DisplayKeys(arguments);
            }
        }
    }
}
