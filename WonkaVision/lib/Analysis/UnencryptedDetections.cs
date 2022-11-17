using System.Collections.Generic;

namespace WonkaVision.lib.Analysis
{
    public class UnencryptedDetections
    {
        public static Dictionary<string, DetectionIOA> GetUnencrypted()
        {
            Dictionary<string, DetectionIOA> ud = new Dictionary<string, DetectionIOA>();
            ud["SessionUser"] = new DetectionIOA();
            ud["KDCCalled"] = new DetectionIOA();
            ud["TicketUser"] = new DetectionIOA();
            ud["UserRealm"] = new DetectionIOA();
            ud["ServiceName"] = new DetectionIOA();
            ud["ServiceRealm"] = new DetectionIOA();
            ud["TicketEndTime"] = new DetectionIOA();
            ud["TicketRenewTill"] = new DetectionIOA();
            ud["TicketFlags"] = new DetectionIOA();
            ud["EncryptionType"] = new DetectionIOA();
            ud["KeyType"] = new DetectionIOA();
            ud["EncryptedSize"] = new DetectionIOA();
            return SetDescriptions(ud);

        }

        private static Dictionary<string, DetectionIOA> SetDescriptions(Dictionary<string, DetectionIOA> ud)
        {
            ud["SessionUser"].Description = "The username for the session this ticket belongs to.";
            ud["KDCCalled"].Description = "The server used to request this ticket.";
            ud["TicketUser"].Description = "The user that the ticket is for.";
            ud["UserRealm"].Description = "The domain of the user that the ticket is for.";
            ud["ServiceName"].Description = "The SPN that the ticket is for.";
            ud["ServiceRealm"].Description = "The domain where the ticket was issued.";
            ud["TicketEndTime"].Description = "The end time for the ticket.";
            ud["TicketRenewTill"].Description = "The renew time for the ticket.";
            ud["TicketFlags"].Description = "The flags set on the ticket.";
            ud["EncryptionType"].Description = "The encryption algorithm used.";
            ud["KeyType"].Description = "The session key type used.";
            ud["EncryptedSize"].Description = "The size of the enc-part of the ticket.";
            return ud;
        }
    }
}
