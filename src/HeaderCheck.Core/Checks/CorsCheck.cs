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
        if (context.CorsProbe == null)
        {
            yield return new Finding(
                "cors.probe-failed",
                Severity.Info,
                "The CORS check could not run",
                "The second request, sent with an Origin header, failed, so the site's CORS settings are unknown."
            );
            yield break;
        }

        var origin = context.CorsProbe.Get("Access-Control-Allow-Origin");
        if (origin is null)
        {
            yield break;
        }

        var credentialsHeader = context.CorsProbe.Get("Access-Control-Allow-Credentials");

        var credentials = string.Equals("true", credentialsHeader?.Trim(), StringComparison.OrdinalIgnoreCase);

        if (origin == ScanContext.ProbeOrigin)
        {
            yield return credentials
            ? new Finding("cors.reflects-origin-credentials", Severity.High, "Any website can read logged-in users' data",
            "The server copies whatever Origin it receives into Access-Control-Allow-Origin and allows credentials. A script on any site a logged-in user visits can call this site with their cookies and read the reply. Allow only a fixed list of trusted origins.", origin)
            :
            new Finding("cors.reflects-origin", Severity.Medium, "The server trusts any origin",
            "The server copies whatever Origin it receives into Access-Control-Allow-Origin, so any site's scripts can read its responses. No cookies are sent, but anything visible without logging in, such as internal network pages, is exposed. Allow only a fixed list of trusted origins.", origin);

        }
        else if (origin == "null")
        {
            yield return credentials
            ? new Finding("cors.null-origin-credentials", Severity.High, "The null origin can read logged-in users' data",
            "The server trusts the origin \"null\" and allows credentials. Attackers can produce a null origin on purpose from a sandboxed iframe, so this is as open as trusting every site. Never allow null.", origin)
            :
            new Finding("cors.null-origin", Severity.Medium, "The server trusts the null origin",
            "Sandboxed iframes and local files send the origin \"null\", and an attacker can create one on purpose. Trusting it lets their scripts read this site's responses. Never allow null.", origin);

        }
        else if (origin == "*")
        {
            yield return credentials
            ? new Finding("cors.wildcard-credentials", Severity.Low, "Wildcard CORS is combined with credentials",
            "Browsers refuse \"*\" together with Allow-Credentials, so this does not work as written, but it shows the intent to share logged-in data with every site. Use a fixed list of origins if credentials are needed.", origin)
            :
            new Finding("cors.wildcard", Severity.Info, "Responses are readable by any site",
            "\"*\" without credentials lets any site's scripts read responses that need no login. That is fine for public data such as an open API or fonts. Make sure nothing private is served here.", origin);
        }




    }
}



