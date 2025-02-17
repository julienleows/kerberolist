using System.Text;
using kerberolist.domain;

namespace kerberolist.outputs;

/// <summary>
/// Terminal formatter.
/// </summary>
public sealed class Terminal : IOutputFormatter
{
    public string Format(List<User> users)
    {
        if (users == null || users.Count == 0)
        {
            return "[Info] No users.";
        }

        var output = new StringBuilder();
        output.AppendLine("[Info] Users list:");

        foreach (var user in users)
        {
            output.AppendLine($"\n{user.Username}");
            output.AppendLine($"   - Vulnerable to Kerberoasting: {(user.KerberostingVulnerable ? "MAYBE" : "NO")}");

            if (user.ServicePrincipalNames.Count > 0)
            {
                output.AppendLine("   - Service Principal Names (SPNs):");
                foreach (var spn in user.ServicePrincipalNames)
                {
                    output.AppendLine($"     - {spn}");
                }
            }
            else
            {
                output.AppendLine("   - No SPN");
            }
        }

        return output.ToString();
    }
}