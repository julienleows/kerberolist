<p align="center">
  <img src="logo.png" width="200" />
</p>

# Kerberolist
Kerberolist is a C# application designed to enumerate Active Directory (AD) user accounts and assess their 
vulnerability to Kerberoasting attacks. It connects to an AD server using the provided IP address and port, 
retrieves user accounts and outputs the results in a JSON file.  
By default, the tool tries to request with an anonymous authentication.  
To obtain output in json format, specify the output file with the '-o <file>' option.

```text
Description:
  Check Kerberoasting accounts

Usage:
  kerberolist [options]

Options:
  -ip <ip> (REQUIRED)          IP address of the Active Directory server
  -p, --port <port>            Port of the Active Directory server [default: 389]
  -o, --output <output>        JSON output file path
  -u, --username <username>    Account username
  -pwd, --password <password>  Account password
  --version                    Show version information
  -?, -h, --help               Show help and usage information
```

## Example
```bash
PS Z:\bin\Release\net9.0\win-x64\publish> .\kerberolist.exe -ip 192.168.1.13 -u admin -pwd strongpassword -o user.json
Kerberolist, version 1.0.0, julienleows
A vulnerability checking tool for system administrators
[Info] Scan with vagrant's account...
[Info] LDAP Bind Success. Base DN: DC=sevenkingdoms,DC=local
[Info] Users list:

Administrator
   - Vulnerable to Kerberoasting: NO
   - No SPN

Guest
   - Vulnerable to Kerberoasting: NO
   - No SPN

vagrant
   - Vulnerable to Kerberoasting: NO
   - No SPN

krbtgt
   - Vulnerable to Kerberoasting: MAYBE
   - Service Principal Names (SPNs):
     - kadmin/changepw

tywin.lannister
   - Vulnerable to Kerberoasting: NO
   - No SPN
   ...
```

## Compile
To compile the application, navigate to the `./kerberolist` directory and execute the following command:
```bash
dotnet publish -c Release -r win-x64
```  
The compiled file is saved in the `./kerberolist/bin/Release/net9.0/win-x64/publish` directory.
