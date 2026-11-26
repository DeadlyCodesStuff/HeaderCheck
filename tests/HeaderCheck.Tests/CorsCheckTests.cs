using HeaderCheck.Core;

namespace HeaderCheck.Tests;

public class CorsCheckTests
{
    private const string Acao = "Access-Control-Allow-Origin";
    private const string Credentials = "Access-Control-Allow-Credentials";
    private static readonly CorsCheck Check = new();

    [Fact]
    public void A_failed_probe_is_noted()
    {
        var context = new ScanContext(new Uri("https://a.test/"), ResponseSnapshot.Create("https://a.test/", 200));
        var findings = T.Run(Check, context);
        T.Codes(findings, "cors.probe-failed");
        Assert.Equal(Severity.Info, findings[0].Severity);
    }

    [Fact]
    public void No_cors_headers_no_findings() => T.Codes(T.Run(Check, T.Probe()));

    [Fact]
    public void A_specific_partner_origin_is_fine() =>
        T.Codes(T.Run(Check, T.Probe((Acao, "https://partner.example"), (Credentials, "true"))));

    [Theory]
    [InlineData(ScanContext.ProbeOrigin, "true", "cors.reflects-origin-credentials", Severity.High)]
    [InlineData(ScanContext.ProbeOrigin, " TRUE ", "cors.reflects-origin-credentials", Severity.High)]
    [InlineData(ScanContext.ProbeOrigin, null, "cors.reflects-origin", Severity.Medium)]
    [InlineData(ScanContext.ProbeOrigin, "false", "cors.reflects-origin", Severity.Medium)]
    [InlineData("null", "true", "cors.null-origin-credentials", Severity.High)]
    [InlineData("null", null, "cors.null-origin", Severity.Medium)]
    [InlineData("*", "true", "cors.wildcard-credentials", Severity.Low)]
    [InlineData("*", null, "cors.wildcard", Severity.Info)]
    public void Origin_and_credentials_decide_the_finding(string acao, string? credentials, string code, Severity severity)
    {
        var headers = credentials is null
            ? new[] { (Acao, acao) }
            : new[] { (Acao, acao), (Credentials, credentials) };

        var findings = T.Run(Check, T.Probe(headers));

        T.Codes(findings, code);
        Assert.Equal(severity, findings[0].Severity);
        Assert.Equal(acao, findings[0].Evidence);
    }
}
