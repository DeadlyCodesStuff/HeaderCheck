using HeaderCheck.Core;

namespace HeaderCheck.Tests;

public class HstsCheckTests
{
    private const string Hsts = "Strict-Transport-Security";
    private static readonly HstsCheck Check = new();

    private static List<Finding> Https(string? value) =>
        T.Run(Check, value is null ? T.Final("https://a.test/") : T.Final("https://a.test/", (Hsts, value)));

    [Fact]
    public void Missing_over_https_is_high()
    {
        var findings = Https(null);
        T.Codes(findings, "hsts.missing");
        Assert.Equal(Severity.High, findings[0].Severity);
    }

    [Fact]
    public void Sent_over_http_is_ignored_by_browsers()
    {
        var findings = T.Run(Check, T.Final("http://a.test/", (Hsts, "max-age=63072000; includeSubDomains")));
        T.Codes(findings, "hsts.over-http");
        Assert.Equal(Severity.Info, findings[0].Severity);
    }

    [Fact]
    public void Absent_over_http_is_left_to_the_redirect_check() =>
        T.Codes(T.Run(Check, T.Final("http://a.test/")));

    [Theory]
    [InlineData("max-age=63072000; includeSubDomains; preload")]
    [InlineData("max-age=31536000; includeSubDomains")]
    [InlineData("  MAX-AGE = \"31536000\" ; IncludeSubDomains ")]
    public void Strong_policies_pass(string value) => T.Codes(Https(value));

    [Fact]
    public void Short_max_age_is_medium_with_the_raw_value_as_evidence()
    {
        var findings = Https("max-age=86400; includeSubDomains");
        T.Codes(findings, "hsts.short-max-age");
        Assert.Equal(Severity.Medium, findings[0].Severity);
        Assert.Equal("max-age=86400; includeSubDomains", findings[0].Evidence);
    }

    [Fact]
    public void Zero_disables_hsts() =>
        T.Codes(Https("max-age=0; includeSubDomains"), "hsts.disabled");

    [Theory]
    [InlineData("includeSubDomains")]
    [InlineData("max-age=abc; includeSubDomains")]
    [InlineData("max-age=-5; includeSubDomains")]
    [InlineData("max-age=; includeSubDomains")]
    public void Unusable_max_age_reports_only_invalid(string value)
    {
        var findings = Https(value);
        T.Codes(findings, "hsts.invalid");
        Assert.Equal(Severity.High, findings[0].Severity);
    }

    [Fact]
    public void Missing_include_subdomains_is_low()
    {
        var findings = Https("max-age=31536000");
        T.Codes(findings, "hsts.no-subdomains");
        Assert.Equal(Severity.Low, findings[0].Severity);
    }

    [Fact]
    public void Preload_without_include_subdomains_is_not_eligible() =>
        T.Codes(Https("max-age=31536000; preload"), "hsts.no-subdomains", "hsts.preload-ineligible");

    [Fact]
    public void Preload_with_a_short_max_age_is_not_eligible() =>
        T.Codes(Https("max-age=600; includeSubDomains; preload"), "hsts.short-max-age", "hsts.preload-ineligible");
}
