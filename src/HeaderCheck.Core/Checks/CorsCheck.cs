namespace HeaderCheck.Core;

/// <summary>
/// YOURS TO WRITE. Looks at <see cref="ScanContext.CorsProbe"/>: the response to a request that
/// sent <c>Origin: https://headercheck-probe.invalid</c> (<see cref="ScanContext.ProbeOrigin"/>).
/// A server that trusts that made-up origin trusts every site.
/// Spec: tests/HeaderCheck.Tests/CorsCheckTests.cs. Run: dotnet test --filter CorsCheckTests
///
/// Read Access-Control-Allow-Origin (ACAO) and Access-Control-Allow-Credentials (credentials
/// = the value "true", case-insensitive, trimmed).
///
/// Rules (code, severity):
///   cors.probe-failed                Info    CorsProbe is null (that request failed).
///   (no finding)                             ACAO absent, or a specific origin other than the probe's.
///   cors.reflects-origin-credentials High    ACAO equals the probe origin, with credentials.
///   cors.reflects-origin             Medium  ACAO equals the probe origin, without credentials.
///   cors.null-origin-credentials     High    ACAO is "null", with credentials.
///   cors.null-origin                 Medium  ACAO is "null", without credentials.
///   cors.wildcard-credentials        Low     ACAO is "*" with credentials (browsers refuse it, but it shows intent).
///   cors.wildcard                    Info    ACAO is "*" without credentials (fine for public data).
///
/// Evidence = the ACAO value.
/// </summary>
public sealed class CorsCheck : ICheck
{
    public string Id => "cors";

    public string Name => "CORS";

    public IEnumerable<Finding> Run(ScanContext context)
    {
        throw new NotImplementedException();
    }
}
