using kerberolist.domain;

namespace kerberolist.outputs;

/// <summary>
/// Output formatters that format a list of users.
/// </summary>
public interface IOutputFormatter
{
    string Format(List<User> users);
}