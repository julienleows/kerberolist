namespace kerberolist.domain;

/// <summary>
/// User in the context of a Kerberoasting scan.
/// </summary>
public record User(
    string Username,
    bool KerberostingVulnerable,
    List<string> ServicePrincipalNames
);