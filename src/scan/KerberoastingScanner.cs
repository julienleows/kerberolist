using System.DirectoryServices.Protocols;
using System.Net;
using kerberolist.domain;

namespace kerberolist.Scan;

/// <summary>
/// Scanning an Active Directory server for users that may be vulnerable to Kerberoasting attacks.
/// </summary>
public sealed class KerberoastingScanner
{
    private static LdapConnection CreateConnection(IPAddress ip, int port, NetworkCredential credential, AuthType authType)
    {
        var connection = new LdapConnection(new LdapDirectoryIdentifier(ip.ToString(), port))
        {
            Credential = credential,
            AuthType = authType
        };
        return connection;
    }

    private static string GetBaseDN(LdapConnection ldapConnection)
    {
        try
        {
            var searchRequest = new SearchRequest(
                "",
                "(objectClass=*)",
                SearchScope.Base,
                "namingContexts"
            );

            var searchResponse = (SearchResponse)ldapConnection.SendRequest(searchRequest);
            var tpmDn = searchResponse.Entries
                .Cast<SearchResultEntry>()
                .SelectMany(entry =>
                {
                    if (entry.Attributes["namingContexts"] != null)
                    {
                        return entry.Attributes["namingContexts"].GetValues(typeof(string)).Cast<string>();
                    }

                    return [];
                })
                .ToList()
                .FirstOrDefault();

            // remove first CN=*,
            if (tpmDn != null && tpmDn.StartsWith("CN="))
            {
                return tpmDn[(tpmDn.IndexOf(',') + 1)..];
            }

            return tpmDn;
        }
        catch (LdapException e)
        {
            Console.WriteLine($"[Error] LDAP Error in GetBaseDN: {e.Message}");
            return null;
        }
        finally
        {
            ldapConnection.Dispose();
        }
    }

    private static List<User> PerformScan(LdapConnection ldapConnection, string dn)
    {
        try
        {
            if (string.IsNullOrEmpty(dn))
            {
                Console.WriteLine("[Error] Base DN not found");
                return new List<User>();
            }

            Console.WriteLine($"[Info] LDAP Bind Success. Base DN: {dn}");

            var searchRequest = new SearchRequest(
                dn,
                "(&(objectCategory=user)(objectClass=user))",
                SearchScope.Subtree,
                "sAMAccountName", "servicePrincipalName"
            );

            var searchResponse = (SearchResponse)ldapConnection.SendRequest(searchRequest);
            return searchResponse.Entries
                .Cast<SearchResultEntry>()
                .Where(entry => entry.Attributes["sAMAccountName"] != null)
                .Select(entry =>
                {
                    var samAccountName = entry.Attributes["sAMAccountName"].GetValues(typeof(string))
                        .Cast<string>().FirstOrDefault();

                    var spnValues = entry.Attributes["servicePrincipalName"] != null
                        ? entry.Attributes["servicePrincipalName"].GetValues(typeof(string)).Cast<string>().ToList()
                        : new List<string>();

                    return new User(samAccountName, spnValues.Any(), spnValues);
                })
                .ToList();
        }
        catch (LdapException e)
        {
            Console.WriteLine($"[Error] {e.Message}");
            return new List<User>();
        }
        finally
        {
            ldapConnection.Dispose();
        }
    }

    public List<User> Scan(IPAddress ip, int port)
    {
        var connection = CreateConnection(ip, port, new NetworkCredential(), AuthType.Anonymous);
        var dn = GetBaseDN(connection);
        return PerformScan(connection, dn);
    }

    public List<User> Scan(IPAddress ip, int port, string username, string password)
    {
        var dn = GetBaseDN(CreateConnection(ip, port, new NetworkCredential(), AuthType.Anonymous));
        var credential = new NetworkCredential(username, password, dn);
        var connection = CreateConnection(ip, port, credential, AuthType.Negotiate);
        return PerformScan(connection, dn);
    }
}