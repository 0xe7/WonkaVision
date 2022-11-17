using System.Collections.Generic;

namespace WonkaVision.lib.Analysis
{
    public class EncryptedDetections
    {
        public static Dictionary<string, DetectionIOA> GetEncrypted()
        {
            Dictionary<string, DetectionIOA> ed = new Dictionary<string, DetectionIOA>();
            ed["ServerChecksum"] = new DetectionIOA();
            ed["KDCChecksum"] = new DetectionIOA();
            ed["TicketChecksum"] = new DetectionIOA();
            ed["LogoffTime"] = new DetectionIOA();
            ed["PasswordLastSet"] = new DetectionIOA();
            ed["PasswordCanChange"] = new DetectionIOA();
            ed["PasswordMustChange"] = new DetectionIOA();
            ed["FullName"] = new DetectionIOA();
            ed["LogonScript"] = new DetectionIOA();
            ed["ProfilePath"] = new DetectionIOA();
            ed["HomeDirectory"] = new DetectionIOA();
            ed["HomeDirectoryDrive"] = new DetectionIOA();
            ed["LogonCount"] = new DetectionIOA();
            ed["BadPasswordCount"] = new DetectionIOA();
            ed["UserID"] = new DetectionIOA();
            ed["PrimaryGID"] = new DetectionIOA();
            ed["GroupCount"] = new DetectionIOA();
            ed["GroupIds"] = new DetectionIOA();
            ed["LogonServer"] = new DetectionIOA();
            ed["NetBIOSName"] = new DetectionIOA();
            ed["UAC"] = new DetectionIOA();
            ed["ExtraSIDs"] = new DetectionIOA();
            ed["UpnDNSBuffer"] = new DetectionIOA();
            ed["RequestorBuffer"] = new DetectionIOA();
            ed["AttributesBuffer"] = new DetectionIOA();
            return SetDescriptions(ed);
        }

        private static Dictionary<string, DetectionIOA> SetDescriptions(Dictionary<string, DetectionIOA> ed)
        {
            ed["ServerChecksum"].Description = "Checksum of the PAC using the service key.";
            ed["KDCChecksum"].Description = "Checksum of the ServerChecksum using the krbtgt key.";
            ed["TicketChecksum"].Description = "Checksum of the EncTicketPart using the krbtgt key.";
            ed["LogoffTime"].Description = "Time the account next has to log off.";
            ed["PasswordLastSet"].Description = "Time the password was last set.";
            ed["PasswordCanChange"].Description = "Time an account can change it's password at the earliest.";
            ed["PasswordMustChange"].Description = "Time an account must change it's password, defined by the domain password policy.";
            ed["FullName"].Description = "Display name shown in LDAP.";
            ed["LogonScript"].Description = "Logon script used by the user.";
            ed["ProfilePath"].Description = "Profile path used by the user.";
            ed["HomeDirectory"].Description = "Home directory used by the user.";
            ed["HomeDirectoryDrive"].Description = "Drive letter used by the user for the home directory.";
            ed["LogonCount"].Description = "Number of times the user has logged on.";
            ed["BadPasswordCount"].Description = "Number of times a bad password has been attempted.";
            ed["UserID"].Description = "User RID.";
            ed["PrimaryGID"].Description = "Primary group RID.";
            ed["GroupCount"].Description = "Number of groups the user is a member of.";
            ed["GroupIds"].Description = "RIDs of the groups the user is a member of.";
            ed["LogonServer"].Description = "Logon server used.";
            ed["NetBIOSName"].Description = "NetBIOS name of the domain.";
            ed["UAC"].Description = "User account control PAC field.";
            ed["ExtraSIDs"].Description = "List of SIDs within the users SID history.";
            ed["UpnDNSBuffer"].Description = "UpnDNS PAC_INFO_BUFFER section.";
            ed["RequestorBuffer"].Description = "Requestor PAC_INFO_BUFFER section.";
            ed["AttributesBuffer"].Description = "Attributes PAC_INFO_BUFFER section.";
            return ed;
        }
    }
}
