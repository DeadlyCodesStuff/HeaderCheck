namespace HeaderCheck.Core;

/// <summary>
/// YOURS TO WRITE. Every Set-Cookie header on <see cref="ScanContext.Final"/>
/// (use <c>context.Final.GetAll("Set-Cookie")</c>: one value per cookie).
/// Spec: tests/HeaderCheck.Tests/CookieCheckTests.cs. Run: dotnet test --filter CookieCheckTests
///
/// Rules per cookie (code, severity):
///   cookie.no-secure               Medium  No Secure attribute.
///   cookie.no-httponly             Low     No HttpOnly attribute.
///   cookie.no-samesite             Low     No SameSite attribute.
///   cookie.samesite-none-insecure  High    SameSite=None without Secure. Reported instead of cookie.no-secure.
///   cookie.bad-prefix              High    Name starts with __Secure- and Secure is absent; or starts with
///                                          __Host- and Secure is absent, Domain is present, or Path is not "/".
///
/// Parsing: "name=value; Attr; Attr=value". The name is everything before the first '='.
/// Attribute names and SameSite values are case-insensitive. Skip a value with no '=' before
/// the first ';' (not a cookie). Several cookies each get their own findings.
///
/// Evidence = the cookie NAME only. Never the value: it is often a session token, and reports
/// get shared.
/// </summary>
public sealed class CookieCheck : ICheck
{
    public string Id => "cookie";

    public string Name => "Cookies";

    public IEnumerable<Finding> Run(ScanContext context)
    {
        throw new NotImplementedException();
    }
}
