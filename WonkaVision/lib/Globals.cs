using System;
using System.Collections.Generic;

namespace WonkaVision.lib
{
    static class Globals
    {
        // 'domainname': {}
        public static Dictionary<string, Dictionary<string, Dictionary<string, Object>>> DomainPolicy = new Dictionary<string, Dictionary<string, Dictionary<string, Object>>>();
        // 'domainname': {'samaccountname': {etype_int: 'keystring'}}
        public static Dictionary<string, Dictionary<string, Dictionary<int, string>>> AccountKeys = new Dictionary<string, Dictionary<string, Dictionary<int, string>>>();
        // 'domainname': {'samaccountname': {LDAP_OBJECT_DICTIONARY}}
        public static Dictionary<string, Dictionary<string, Dictionary<string, Object>>> AccountInformation = new Dictionary<string, Dictionary<string, Dictionary<string, Object>>>();
        // 'domainname': 'netbiosname'
        public static Dictionary<string, string> NetbiosName = new Dictionary<string, string>();
        // 'samaccountname': list<'spns'>
        public static Dictionary<string, List<string>> ServiceNameMapping = new Dictionary<string, List<string>>();

        public static string GetMappedUsername(string sname)
        {
            if (sname.Split('/')[0].ToLower().Equals("krbtgt"))
                return sname.ToLower();

            foreach (var username in ServiceNameMapping.Keys)
            {
                if (ServiceNameMapping[username].Contains(sname.ToLower()))
                    return username;
            }

            return null;
        }
    }
}
