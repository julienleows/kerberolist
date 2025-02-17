using System.Text.Json;
using kerberolist.domain;

namespace kerberolist.outputs;

/// <summary>
/// JSON Formatter.
/// </summary>
public sealed class Json : IOutputFormatter
{
    public string Format(List<User> users) => JsonSerializer.Serialize(users);
}