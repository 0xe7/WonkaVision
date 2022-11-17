using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Security.Principal;

namespace WonkaVision.lib
{
    public class LDAP
    {
        public static DirectoryEntry GetLdapSearchRoot(System.Net.NetworkCredential cred, string OUName, string domainController, string domain)
        {
            DirectoryEntry directoryObject = null;
            string ldapPrefix = "";
            string ldapOu = "";

            //If we have a DC then use that instead of the domain name so that this works if user doesn't have
            //name resolution working but specified the IP of a DC
            if (!String.IsNullOrEmpty(domainController))
            {
                ldapPrefix = domainController;
            }
            else if (!String.IsNullOrEmpty(domain)) //If we don't have a DC then use the domain name (if we have one)
            {
                ldapPrefix = domain;
            }
            else if (cred != null) //If we don't have a DC or a domain name but have credentials, get domain name from them
            {
                ldapPrefix = cred.Domain;
            }

            if (!String.IsNullOrEmpty(OUName))
            {
                ldapOu = OUName.Replace("ldap", "LDAP").Replace("LDAP://", "");
            }
            else if (!String.IsNullOrEmpty(domain))
            {
                ldapOu = String.Format("DC={0}", domain.Replace(".", ",DC="));
            }

            //If no DC, domain, credentials, or OU were specified
            if (String.IsNullOrEmpty(ldapPrefix) && String.IsNullOrEmpty(ldapOu))
            {
                directoryObject = new DirectoryEntry();

            }
            else //If we have a prefix (DC or domain), an OU path, or both
            {
                string bindPath = "";
                if (!String.IsNullOrEmpty(ldapPrefix))
                {
                    bindPath = String.Format("LDAP://{0}", ldapPrefix);
                }
                if (!String.IsNullOrEmpty(ldapOu))
                {
                    if (!String.IsNullOrEmpty(bindPath))
                    {
                        bindPath = String.Format("{0}/{1}", bindPath, ldapOu);
                    }
                    else
                    {
                        bindPath = String.Format("LDAP://{0}", ldapOu);
                    }
                }

                directoryObject = new DirectoryEntry(bindPath);
            }

            if (cred != null)
            {
                // if we're using alternate credentials for the connection
                string userDomain = String.Format("{0}\\{1}", cred.Domain, cred.UserName);
                directoryObject.Username = userDomain;
                directoryObject.Password = cred.Password;
            }
            return directoryObject;
        }

        public static List<Dictionary<string, Object>> GetLdapQuery(System.Net.NetworkCredential cred, string OUName, string domainController, string domain, string filter)
        {
            var ActiveDirectoryObjects = new List<Dictionary<string, Object>>();
            if (String.IsNullOrEmpty(domainController))
            {
                domainController = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain().DomainControllers[0].Name;
            }
            if (String.IsNullOrEmpty(domainController))
            {
                Helpers.WriteConsole("[X] Unable to retrieve the domain information, try again with '/domain'.");
                return null;
            }
            DirectoryEntry directoryObject = null;
            DirectorySearcher searcher = null;
            try
            {
                directoryObject = GetLdapSearchRoot(cred, OUName, domainController, domain);
                searcher = new DirectorySearcher(directoryObject);
                // enable LDAP paged search to get all results, by pages of 1000 items
                searcher.PageSize = 1000;
            }
            catch (Exception ex)
            {
                if (ex.InnerException != null)
                {
                    Helpers.WriteConsole($"[X] Error creating the domain searcher: {ex.InnerException.Message}");
                }
                else
                {
                    Helpers.WriteConsole($"[X] Error creating the domain searcher: {ex.Message}");
                }
                return null;
            }

            // check to ensure that the bind worked correctly
            try
            {
                string dirPath = directoryObject.Path;
                if (String.IsNullOrEmpty(dirPath))
                {
                    if (Program.Verbose)
                        Helpers.WriteConsole($"[*] Searching the current domain for '{filter}'");
                }
                else
                {
                    if (Program.Verbose)
                        Helpers.WriteConsole($"[*] Searching path '{dirPath}' for '{filter}'");
                }
            }
            catch (DirectoryServicesCOMException ex)
            {
                if (!String.IsNullOrEmpty(OUName))
                {
                    Helpers.WriteConsole($"[X] Error validating the domain searcher for bind path \"{OUName}\" : {ex.Message}");
                }
                else
                {
                    Helpers.WriteConsole($"[X] Error validating the domain searcher: {ex.Message}");
                }
                return null;
            }

            try
            {
                searcher.Filter = filter;
            }
            catch (Exception ex)
            {
                Helpers.WriteConsole($"[X] Error settings the domain searcher filter: {ex.InnerException.Message}");
                return null;
            }

            SearchResultCollection results = null;

            try
            {
                results = searcher.FindAll();

                if (results.Count == 0)
                {
                    if (Program.Verbose)
                        Helpers.WriteConsole($"[X] No results returned by LDAP using filter: {filter}");
                    return null;
                }
            }
            catch (Exception ex)
            {
                if (ex.InnerException != null)
                {
                    Helpers.WriteConsole($"[X] Error executing the domain searcher: {ex.InnerException.Message}");
                }
                else
                {
                    Helpers.WriteConsole($"[X] Error executing the domain searcher: {ex.Message}");
                }
                return null;
            }

            ActiveDirectoryObjects = GetADObjects(results);

            return ActiveDirectoryObjects;
        }

        // variables specifying non default AD attribute types
        private static string[] stringArrayAttributeName =
        {
            "serviceprincipalname",
            "memberof"
        };
        private static string[] datetimeAttributes =
        {
            "lastlogon",
            "lastlogoff",
            "pwdlastset",
            "badpasswordtime",
            "lastlogontimestamp",
        };
        private static string[] dateStringAttributes =
        {
            "whenchanged",
            "whencreated"
        };
        private static string[] intAttributes =
        {
            "useraccountcontrol",
            "msds-supportedencryptiontypes",
            "logoncount",
            "badpwdcount",
            "primarygroupid"
        };

        static public List<Dictionary<string, Object>> GetADObjects(SearchResultCollection searchResults)
        {
            var ActiveDirectoryObjects = new List<Dictionary<string, Object>>();

            foreach (SearchResult result in searchResults)
            {
                Dictionary<string, Object> ActiveDirectoryObject = new Dictionary<string, Object>();

                foreach (string attribute in result.Properties.PropertyNames)
                {
                    // for string arrays like serviceprincipalname
                    if (stringArrayAttributeName.Contains(attribute))
                    {
                        List<string> values = new List<string>();
                        foreach (var value in result.Properties[attribute])
                        {
                            values.Add(value.ToString());
                        }
                        ActiveDirectoryObject.Add(attribute, values.ToArray());
                    }
                    // datetime attributes
                    else if (datetimeAttributes.Contains(attribute))
                    {
                        if (Int64.Parse(result.Properties[attribute][0].ToString()) != 0)
                        {
                            ActiveDirectoryObject.Add(attribute, DateTime.FromFileTimeUtc((long)result.Properties[attribute][0]));
                        }
                        else
                        {
                            ActiveDirectoryObject.Add(attribute, DateTime.MinValue);
                        }
                    }
                    // deal with objectsid
                    else if (attribute.Equals("objectsid"))
                    {
                        ActiveDirectoryObject.Add(attribute, new SecurityIdentifier((byte[])result.Properties[attribute][0], 0).Value);
                    }
                    else if (attribute.Equals("sidhistory"))
                    {
                        List<string> extraSids = new List<string>();
                        foreach (var sid in result.Properties[attribute])
                        {
                            extraSids.Add((new SecurityIdentifier((byte[])sid, 0)).Value);
                        }

                        ActiveDirectoryObject.Add(attribute, extraSids);
                    }
                    // deal with ints
                    else if (intAttributes.Contains(attribute))
                    {
                        ActiveDirectoryObject.Add(attribute, result.Properties[attribute][0]);
                    }
                    else if (attribute.Equals("logonhours"))
                    {
                        LogonHours logonHours = new LogonHours();
                        logonHours.ConvertLogonHours((byte[])result.Properties[attribute][0]);
                        ActiveDirectoryObject.Add(attribute, logonHours);
                    }
                    // default action convert to string
                    else
                    {
                        ActiveDirectoryObject.Add(attribute, result.Properties[attribute][0].ToString());
                    }
                }

                ActiveDirectoryObjects.Add(ActiveDirectoryObject);
            }

            return ActiveDirectoryObjects;
        }
    }
}
