using System;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Claims;

namespace ADauth
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine(ValidateUser("bognar.pal", Console.ReadLine()));
        }

        static bool ValidateUser(string login, string password)
        {
            try
            {
#if DEBUG
                var ldapServerUrl = "10.100.0.1";
#else
            var ldapServerUrl = "193.225.219.43"; // "jdc.jedlik.helyi";
#endif
                using (var connection = new LdapConnection(ldapServerUrl))
                {
                    var networkCredential = new NetworkCredential(login, password, "jedlikhelyi");
                    connection.Credential = networkCredential;
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                    {
                        connection.AuthType = AuthType.Basic;
                        connection.SessionOptions.ProtocolVersion = 3;
                    }
                    else
                        connection.AuthType = AuthType.Ntlm;
                    connection.Bind();

                    return true;


                    //Ha ki kell olvasni néhány info-t az AD-ből: az OU, DC értékek cégenként mások lesznek

                    SearchRequest searchRequest = new SearchRequest("DC=jedlik,DC=helyi", $"(samaccountname={login})", SearchScope.Subtree);
                    var result = (SearchResponse)connection.SendRequest(searchRequest);
                    if (result.Entries.Count == 1)
                    {
                        var entry = result.Entries[0];
                        var path = entry.DistinguishedName.Split(',');
                        var user = new
                        {
                            LoginName = entry.Attributes["samaccountname"][0].GetType() == typeof(string) ?
                                        entry.Attributes["samaccountname"][0].ToString() :
                                        System.Text.Encoding.GetEncoding(1252).GetString((byte[])entry.Attributes["samaccountname"][0]),
                            Name = entry.Attributes["displayname"][0].GetType() == typeof(string) ?
                                   entry.Attributes["displayname"][0].ToString() :
                                   System.Text.Encoding.GetEncoding(1252).GetString((byte[])entry.Attributes["displayname"][0]),
                            OMIdentifier = entry.Attributes.Contains("employeeid") ? entry.Attributes["employeeid"][0].ToString() : "",
                            Class = path[3] == "OU=Tanulók" ? path[1].Split('=')[1] : "",
                            IsTeacher = path[2] == "OU=Tanárok"
                        };
                    }
                }
            }
            catch (LdapException ex)
            {
#if DEBUG
                throw new Exception("Hiba az AD authentikáció során", ex);
#else
            throw new Exception("Hibás felhasználónév vagy jelszó", ex);
#endif
            }
            throw new Exception("Hibás felhasználónév vagy jelszó");
        }
    }
}
