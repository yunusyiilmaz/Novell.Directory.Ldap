using Novell.Directory.Ldap;
using Novell.Directory.Ldap.Utilclass;
using System.Net.Sockets;
using Novell.Directory.LdapService.Models;
using System.Security.Cryptography;
using System.Security.Principal;


namespace Novell.Directory.LdapService.Service
{
    public class LdapServices
    {
        public bool isServerReachable()//server access is controlled.
        {
            string ldapServer = "attempt.test.com";
            int ldapPort = 389;//port no
            bool isServerReachable = PingServer(ldapServer, ldapPort);
            return isServerReachable; // Exit early if the server is unreachable

        }
        private static bool PingServer(string ldapServer, int ldapPort)//ping server is checked.
        {

            using (TcpClient tcpClient = new TcpClient())
            {
                //Trying to connect to the server with the specified port
                try
                {
                    tcpClient.Connect(ldapServer, ldapPort);
                }
                catch (Exception ex)
                {

                    return false;
                }

                return true; // Connection successful
            }

        }
        public bool Authenticated(string username, string password, out LdapAuthenticationViewModel userProfile)
        {
            string ldapServer = "Server.com";
            int ldapPort = 389;
            string ldapUsername = "domain\\(example=center\\)" + username;
            userProfile = new LdapAuthenticationViewModel();
            try
            {
                using (var ldapConnection = new LdapConnection())
                {
                    ldapConnection.Connect(ldapServer, ldapPort);//connection is established.
                    ldapConnection.Bind(ldapUsername, password);//the user is queried.

                    if (ldapConnection.Bound)//If the connection is successful
                    {
                        string searcFilter = $"(sAMAccountName={username})";// Required filter and basis for LDAP search
                        string searchBase = "DC=attempt,DC=test,DC=com";// LDAP search base point

                        LdapSearchResults searchResults = (LdapSearchResults)ldapConnection.Search(
                        searchBase,
                        LdapConnection.ScopeSub,//Search scope is specified
                        searcFilter,
                        null,//Returns all attributes
                        false// Resolving aliases
                        );
                        if (searchResults.HasMore())// Get next record
                        {
                            LdapEntry entry = searchResults.Next(); 
                            userProfile.Email = GetAttributeValue(entry, "userPrincipalName");
                            userProfile.FirstName = GetAttributeValue(entry, "givenName");
                            userProfile.LastName = GetAttributeValue(entry, "sn");
                            userProfile.EmployeeType = GetAttributeValue(entry, "employeeType");
                            userProfile.ObjectSid = GetAttributeValueId(entry, "objectSid");
                            userProfile.ObjectGUID = GetAttributeValueId(entry, "objectGUID");
                            userProfile.ObjectClass = GetAttributeObjectClass(entry, "objectClass");
                            userProfile.DistinGuishedName = entry.Dn; // DN bilgisi
                            userProfile.UserName = GetAttributeValue(entry, "sAMAccountName");
                            userProfile.userPrincipalName = GetAttributeValue(entry, "userPrincipalName");
                            //You can add other attribute information

                        }
                    }
                }
                return true;
            }
            catch (Exception ex)
            {

                return false;
            }
        }

        public string GetAttributeValue(LdapEntry entry, string attributeName)
        {
            var attribute = entry.GetAttribute(attributeName);
            if (attribute != null)
            {
                return attribute.StringValue;
            }
            return null;
        }

        public string GetAttributeValueId(LdapEntry entry, string attributeName)
        {
            var attribute = entry.GetAttribute(attributeName);
            if (attribute != null)
            {
                var values = attribute.ByteValue;
                if (values != null && values.Length > 0)
                {
                    // If attributeName is 'objectGUID' convert to GUID
                    if (attributeName.Equals("objectGUID", StringComparison.OrdinalIgnoreCase))
                    {
                        return new Guid(values).ToString(); // Conversion from byte array to GUID
                    }
                    // If attributeName is 'objectSid' convert to SID format
                    else if (attributeName.Equals("objectSid", StringComparison.OrdinalIgnoreCase))
                    {
                        return ConvertSidToString(values); //Converts SID byte array to SID string
                    }
                    else
                    {
                        //For other byte arrays
                        return BitConverter.ToString(values); //Convert byte array to string
                    }
                }
                return attribute.StringValue;
            }
            return null;
        }

        private string ConvertSidToString(byte[] sidBytes)
        {
            SecurityIdentifier sid = new SecurityIdentifier(sidBytes, 0);
            return sid.ToString();
        }

        private string GetAttributeObjectClass(LdapEntry entry, string attributeName)
        {
            var attribute = entry.GetAttribute(attributeName);
            if (attribute != null)
            {
                var objectClass = entry.GetAttribute(attributeName).StringValueArray[3];
                return objectClass;
            }
            return null;
        }
    }
}
