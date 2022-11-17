using System.Collections.Generic;

namespace WonkaVision.lib.Analysis
{
    public class TicketDetections
    {
        public Dictionary<string, DetectionIOA> Unencrypted { get; set; }

        public Dictionary<string, DetectionIOA> Encrypted { get; set; }

        public string ServiceName { get; set; }

        public string Username { get; set; }

        public bool IsTGT { get; set; }

        public uint FinalScore { get; set; }

        public uint MimikatzScore { get; set; }

        public uint ImpacketScore { get; set; }

        public uint RubeusScore { get; set; }

        public uint CobaltStrikeScore { get; set; }

        public bool EncryptedPopulated { get; set; }

        public TicketDetections()
        {
            IsTGT = false;
            FinalScore = 0;
            MimikatzScore = 0;
            ImpacketScore = 0;
            RubeusScore = 0;
            CobaltStrikeScore = 0;
            EncryptedPopulated = false;
            Encrypted = EncryptedDetections.GetEncrypted();
        }
    }
}
