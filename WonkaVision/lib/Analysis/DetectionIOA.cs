namespace WonkaVision.lib.Analysis
{
    public class DetectionIOA
    {
        public bool Checked { get; set; }

        public string Description { get; set; }

        public string Value { get; set; }

        public uint Score { get; set; }

        public string Reason { get; set; }

        public uint MimiScore { get; set; }

        public uint ImpacketScore { get; set; }

        public uint RubeusScore { get; set; }

        public uint CobaltStrikeScore { get; set; }

        public DetectionIOA()
        {
            Checked = true;
            Score = 0;
            Reason = string.Empty;
            MimiScore = 0;
            ImpacketScore = 0;
            RubeusScore = 0;
            CobaltStrikeScore = 0;
        }
    }
}
