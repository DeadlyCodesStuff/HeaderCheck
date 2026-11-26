using HeaderCheck.Core;

namespace HeaderCheck.Tests;

public class RedirectCheckTests
{
    private static readonly RedirectCheck Check = new();

    [Fact]
    public void Https_with_no_redirects_passes() =>
        T.Codes(T.Run(Check, T.Chain("https://a.test/")));

    [Fact]
    public void Staying_on_http_is_high()
    {
        var findings = T.Run(Check, T.Chain("http://a.test/"));
        T.Codes(findings, "redirect.no-https");
        Assert.Equal(Severity.High, findings[0].Severity);
    }

    [Theory]
    [InlineData(301)]
    [InlineData(308)]
    public void Permanent_upgrade_to_https_passes(int status) =>
        T.Codes(T.Run(Check, T.Chain("http://a.test/", ("http://a.test/", status, "https://a.test/"))));

    [Theory]
    [InlineData(302)]
    [InlineData(307)]
    public void Temporary_upgrade_is_noted(int status)
    {
        var findings = T.Run(Check, T.Chain("http://a.test/", ("http://a.test/", status, "https://a.test/")));
        T.Codes(findings, "redirect.temporary-upgrade");
        Assert.Equal(Severity.Info, findings[0].Severity);
        Assert.Equal("http://a.test/ -> https://a.test/", findings[0].Evidence);
    }

    [Fact]
    public void Downgrade_to_http_is_high_and_ends_on_http()
    {
        var findings = T.Run(Check, T.Chain("https://a.test/", ("https://a.test/", 301, "http://a.test/old")));
        T.Codes(findings, "redirect.downgrade", "redirect.no-https");
        var downgrade = T.One(findings, "redirect.downgrade");
        Assert.Equal(Severity.High, downgrade.Severity);
        Assert.Equal("https://a.test/ -> http://a.test/old", downgrade.Evidence);
    }

    [Fact]
    public void Each_downgrade_hop_is_its_own_finding() =>
        T.Codes(T.Run(Check, T.Chain("https://a.test/",
                ("https://a.test/", 301, "http://a.test/1"),
                ("http://a.test/1", 301, "https://a.test/2"),
                ("https://a.test/2", 301, "http://a.test/3"),
                ("http://a.test/3", 301, "https://a.test/4"))),
            "redirect.downgrade", "redirect.downgrade", "redirect.long-chain");

    [Fact]
    public void Three_hops_is_fine() =>
        T.Codes(T.Run(Check, T.Chain("https://a.test/",
            ("https://a.test/", 301, "https://a.test/1"),
            ("https://a.test/1", 301, "https://a.test/2"),
            ("https://a.test/2", 301, "https://a.test/3"))));

    [Fact]
    public void Four_hops_is_a_long_chain()
    {
        var findings = T.Run(Check, T.Chain("https://a.test/",
            ("https://a.test/", 301, "https://a.test/1"),
            ("https://a.test/1", 301, "https://a.test/2"),
            ("https://a.test/2", 301, "https://a.test/3"),
            ("https://a.test/3", 301, "https://a.test/4")));
        T.Codes(findings, "redirect.long-chain");
        Assert.Equal(Severity.Low, findings[0].Severity);
        Assert.Equal("4", findings[0].Evidence);
    }

    [Fact]
    public void Adding_www_is_not_another_host() =>
        T.Codes(T.Run(Check, T.Chain("https://example.test/", ("https://example.test/", 301, "https://www.example.test/"))));

    [Fact]
    public void Ending_on_another_host_is_noted()
    {
        var findings = T.Run(Check, T.Chain("https://a.test/", ("https://a.test/", 301, "https://b.test/")));
        T.Codes(findings, "redirect.other-host");
        Assert.Equal(Severity.Info, findings[0].Severity);
    }

    [Fact]
    public void Temporary_upgrade_only_counts_on_the_same_host() =>
        T.Codes(T.Run(Check, T.Chain("http://a.test/", ("http://a.test/", 302, "https://b.test/"))),
            "redirect.other-host");
}
