using System;

namespace WonkaVision.lib
{
    public class Info
    {
        public static void Logo()
        {
            string[] wonka = $@"   __          __         _         
   \ \        / /        | |        
    \ \  /\  / /__  _ __ | | ____ _ 
     \ \/  \/ / _ \| '_ \| |/ / _` |
      \  /\  / (_) | | | |   < (_| |
       \/  \/ \___/|_| |_|_|\_\__,_|".Split(new string[] {Environment.NewLine}, StringSplitOptions.None);
            string[] vision = @" __      ___     _             
 \ \    / (_)   (_)            
  \ \  / / _ ___ _  ___  _ __  
   \ \/ / | / __| |/ _ \| '_ \ 
    \  /  | \__ \ | (_) | | | |
     \/   |_|___/_|\___/|_| |_|".Split(new string[] {Environment.NewLine}, StringSplitOptions.None);
            int c = 0;
            Console.WriteLine();
            foreach (string w in wonka)
            {
                Console.ForegroundColor = ConsoleColor.Magenta;
                Console.Write(w);

                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine(vision[c]);
                c += 1;
            }
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"                                                                  v{Version.GetVersion()}");
        }

        public static string FullUsage()
        {
            Logo();
            string usage = $@"
{KeysUsage()}
{DumpUsage()}
{AnalyzeUsage()}
";
            return usage;
        }

        public static string KeysUsage()
        {
            string usage = @"
  Create Keys Command

    Create analysis public/private key pair and output them to the terminal as base64 encoded blobs:
      WonkaVision.exe /createkeys

    Create analysis public/private key pair and output them to files within the 'C:\temp' directory:
      WonkaVision.exe /createkeys /outdir:C:\temp
";
            return usage;
        }

        public static string DumpUsage()
        {
            string usage = @"
  Dump Command

    Dump session and ticket information using the public key at '\\server\share\public.key' and writing the dump to '\\server\share':
      WonkaVision.exe /dump /publickey:\\server\share\public.key /dumpdir:\\server\share
";
            return usage;
        }

        public static string AnalyzeUsage()
        {
            string usage = @"
  Analyze Command

    Analyze dump files using the private key at 'C:\keys\private.key' and dump directory 'C:\dumps':
      WonkaVision.exe /analyze /privatekey:C:\keys\private.key /dumpdir:C:\dumps
";
            return usage;
        }
    }
}
