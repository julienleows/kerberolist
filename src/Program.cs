using System.CommandLine;
using System.Net;
using kerberolist.outputs;
using kerberolist.Scan;
using kerberolist.domain;

namespace kerberolist;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        var ipOption = new Option<string>(
            name: "-ip",
            description: "IP address of the Active Directory server"
        ) { IsRequired = true };

        var portOption = new Option<int>(
            aliases: ["-p", "--port"],
            description: "Port of the Active Directory server",
            getDefaultValue: () => 389
        );
        portOption.AddValidator(result =>
        {
            var port = result.GetValueOrDefault<int>();
            if (port is < 1 or > 65535)
            {
                result.ErrorMessage = $"Invalid value for --port: {port}. The port must be between 1 and 65535.";
            }
        });

        var fileOption = new Option<string>(
            aliases: new[] { "-o", "--output" },
            description: "JSON output file path"
        );

        var usernameOption = new Option<string>(
            aliases: new[] { "-u", "--username" },
            description: "Account username"
        );

        var passwordOption = new Option<string>(
            aliases: new[] { "-pwd", "--password" },
            description: "Account password"
        );

        var bannerOption = new Option<bool>(
            aliases: new[] { "-nb", "--nobanner" },
            description: "Disable banner"
        );


        var rootCommand = new RootCommand("Check Kerberoasting accounts")
        {
            ipOption,
            portOption,
            fileOption,
            usernameOption,
            passwordOption,
            bannerOption
        };

        rootCommand.SetHandler(
            ProcessKerberolisting, ipOption, portOption,
            fileOption, usernameOption, passwordOption, bannerOption
        );

        return await rootCommand.InvokeAsync(args);
    }

    private static void ProcessKerberolisting(string ip, int port, string filePath, string username, string password,
        bool nobanner)
    {
        if (!nobanner)
        {
            Console.WriteLine(Banner());
        }

        Console.WriteLine(
            """
            Kerberolist, version 1.0.0, julienleows
            A vulnerability checking tool for system administrators
            """
        );

        try
        {
            List<User> users;
            // check ip address
            if (!IPAddress.TryParse(ip, out var ipAddress))
            {
                Console.Error.WriteLine("[Error] Invalid IP address");
                return;
            }

            if (!string.IsNullOrWhiteSpace(username) && string.IsNullOrWhiteSpace(password)
                || string.IsNullOrWhiteSpace(username) && !string.IsNullOrWhiteSpace(password))
            {
                Console.Error.WriteLine("[Error] An username with a password is required");
                return;
            }

            if (!string.IsNullOrWhiteSpace(username) && !string.IsNullOrWhiteSpace(password))
            {
                // scan with an user account
                Console.WriteLine($"[Info] Scan with {username}'s account...");
                users = new KerberoastingScanner().Scan(ipAddress, port, username, password);
            }
            else
            {
                // scan with anonymous user
                Console.WriteLine("[Info] Scan with anonymous account...");
                users = new KerberoastingScanner().Scan(ipAddress, port);
            }

            // format for the terminal
            var resultTerminal = new Terminal().Format(users);
            Console.WriteLine(resultTerminal);

            // format the results into JSON
            var resultJson = new Json().Format(users);

            if (!string.IsNullOrWhiteSpace(filePath))
            {
                using (var writer = new StreamWriter(filePath, append: false))
                {
                    writer.WriteLine(resultJson);
                }
                Console.WriteLine($"[Info] File {filePath} written");
            }
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"[Error] {e.Message}");
        }
    }

    private static string Banner()
    {
        return """
                _   __          _                    _ _     _   
               | | / /         | |                  | (_)   | |  
               | |/ /  ___ _ __| |__   ___ _ __ ___ | |_ ___| |_ 
               |    \ / _ \ '__| '_ \ / _ \ '__/ _ \| | / __| __|
               | |\  \  __/ |  | |_) |  __/ | | (_) | | \__ \ |_ 
               \_| \_/\___|_|  |_.__/ \___|_|  \___/|_|_|___/\__|
               """;
    }
}