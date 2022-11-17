using System;
using System.Collections.Generic;
using System.IO;

namespace WonkaVision.cmds
{
    public class GenerateKeys
    {
        public void DisplayKeys(Dictionary<string, string> arguments)
        {
            string outdir = null;

            if (arguments.ContainsKey("/outdir"))
                outdir = arguments["/outdir"];

            Tuple<byte[], byte[]> t = lib.Crypto.CreateKeys();
            byte[] publicBytes = t.Item1;
            byte[] privateBytes = t.Item2;

            if (publicBytes != null && privateBytes != null)
            {
                if (String.IsNullOrWhiteSpace(outdir))
                {
                    int indentLevel = 20;
                    Console.WriteLine("{0}PublicKey{0}", new string('=', indentLevel));
                    Console.WriteLine("{0}", Convert.ToBase64String(publicBytes));
                    Console.WriteLine("{0}End PublicKey{0}\r\n\r\n", new string('=', indentLevel - 2));
                    Console.WriteLine("{0}PrivateKey{0}", new string('=', indentLevel));
                    Console.WriteLine("{0}", Convert.ToBase64String(privateBytes));
                    Console.WriteLine("{0}End PrivateKey{0}\r\n\r\n", new string('=', indentLevel - 2));
                }
                else
                {
                    if (!Directory.Exists(outdir))
                    {
                        lib.Helpers.WriteConsole($"[X] Directory {outdir} does not exist!");
                        lib.Info.Logo();
                        Console.WriteLine(lib.Info.KeysUsage());
                        return;
                    }
                    lib.Helpers.WriteConsole($"[!] Writing key files to {outdir}, be sure to protect the private key as if it was the krbtgt key!");
                    try
                    {
                        File.WriteAllBytes($"{outdir}\\public.key", publicBytes);
                        Console.WriteLine($"[*] Written public key to {outdir}\\public.key");
                        File.WriteAllBytes($"{outdir}\\private.key", privateBytes);
                        Console.WriteLine($"[*] Written private key to {outdir}\\private.key");
                    }
                    catch (Exception ex)
                    {
                        lib.Helpers.WriteConsole($"[X] Unable to write keys: {ex.Message}");
                    }
                }
            }
        }
    }
}
