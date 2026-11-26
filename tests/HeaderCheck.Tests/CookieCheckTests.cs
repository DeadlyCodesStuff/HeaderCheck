using HeaderCheck.Core;

namespace HeaderCheck.Tests;

public class CookieCheckTests
{
    private static readonly CookieCheck Check = new();

    private static List<Finding> With(params string[] cookies) =>
        T.Run(Check, T.Final("https://a.test/", cookies.Select(c => ("Set-Cookie", c)).ToArray()));

    [Fact]
    public void No_cookies_no_findings() => T.Codes(With());

    [Theory]
    [InlineData("sid=abc; Secure; HttpOnly; SameSite=Lax")]
    [InlineData("sid=abc; secure; httponly; samesite=strict")]
    [InlineData("sid=abc; Path=/; Secure; HttpOnly; SameSite=None")]
    [InlineData("__Host-id=1; Secure; HttpOnly; SameSite=Lax; Path=/")]
    [InlineData("__Secure-id=1; Secure; HttpOnly; SameSite=Lax; Domain=a.test")]
    public void Well_set_cookies_pass(string cookie) => T.Codes(With(cookie));

    [Fact]
    public void A_bare_cookie_misses_all_three_attributes()
    {
        var findings = With("sid=abc");
        T.Codes(findings, "cookie.no-secure", "cookie.no-httponly", "cookie.no-samesite");
        Assert.Equal(Severity.Medium, T.One(findings, "cookie.no-secure").Severity);
        Assert.Equal(Severity.Low, T.One(findings, "cookie.no-httponly").Severity);
        Assert.Equal(Severity.Low, T.One(findings, "cookie.no-samesite").Severity);
    }

    [Fact]
    public void SameSite_none_without_secure_replaces_no_secure()
    {
        var findings = With("sid=abc; HttpOnly; SameSite=None");
        T.Codes(findings, "cookie.samesite-none-insecure");
        Assert.Equal(Severity.High, findings[0].Severity);
    }

    [Fact]
    public void Secure_prefix_needs_secure()
    {
        var findings = With("__Secure-id=1; HttpOnly; SameSite=Lax");
        T.Codes(findings, "cookie.bad-prefix", "cookie.no-secure");
        Assert.Equal(Severity.High, T.One(findings, "cookie.bad-prefix").Severity);
    }

    [Theory]
    [InlineData("__Host-id=1; Secure; HttpOnly; SameSite=Lax; Path=/; Domain=a.test")]
    [InlineData("__Host-id=1; Secure; HttpOnly; SameSite=Lax")]
    [InlineData("__Host-id=1; Secure; HttpOnly; SameSite=Lax; Path=/app")]
    public void Host_prefix_rules(string cookie)
    {
        var findings = With(cookie);
        T.Codes(findings, "cookie.bad-prefix");
        Assert.Equal(Severity.High, findings[0].Severity);
    }

    [Fact]
    public void Each_cookie_gets_its_own_findings_named_in_evidence()
    {
        var findings = With("a=1; Secure; HttpOnly; SameSite=Lax", "b=2; Secure; HttpOnly", "c=3; Secure; HttpOnly");
        T.Codes(findings, "cookie.no-samesite", "cookie.no-samesite");
        Assert.Equal(new[] { "b", "c" }, findings.Select(f => f.Evidence).OrderBy(e => e));
    }

    [Fact]
    public void Cookie_values_never_appear_in_findings()
    {
        var findings = With("session=SECRET-TOKEN-123");
        Assert.NotEmpty(findings);
        Assert.All(findings, f =>
        {
            Assert.Equal("session", f.Evidence);
            Assert.DoesNotContain("SECRET", f.Title);
            Assert.DoesNotContain("SECRET", f.Detail);
        });
    }

    [Fact]
    public void A_value_with_no_name_is_skipped() =>
        T.Codes(With("garbage; Secure"));
}
