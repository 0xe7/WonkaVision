using System;
using System.Collections.Generic;

namespace WonkaVision.lib.Analysis
{
    public class SessionIOAs
    {
        public static Dictionary<string, DetectionIOA> GetSessionIOAs()
        {
            Dictionary<string, DetectionIOA> sess = new Dictionary<string, DetectionIOA>();
            sess["AuthenticationPackage"] = new DetectionIOA();
            sess["LogonType"] = new DetectionIOA();
            sess["LacksTGT"] = new DetectionIOA();
            sess["UsernameMismatch"] = new DetectionIOA();
            return SetDescriptions(sess);
        }

        private static Dictionary<string, DetectionIOA> SetDescriptions(Dictionary<string, DetectionIOA> sess)
        {
            sess["AuthenticationPackage"].Description = "The authentication package in use by the session.";
            sess["LogonType"].Description = "The logon type used by the session.";
            sess["LacksTGT"].Description = "The session lacks an initial TGT";
            sess["UsernameMismatch"].Description = "The session username does not match the tickets.";
            return sess;
        }
    }
}
