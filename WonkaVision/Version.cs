namespace WonkaVision
{
    public class Version
    {
        public short Major = 0;
        public short Minor = 2;
        public string Name = "swudge";

        public static string GetVersion()
        {
            Version version = new Version();
            return $"{version.Major}.{version.Minor}-{version.Name}";
        }
    }
}
