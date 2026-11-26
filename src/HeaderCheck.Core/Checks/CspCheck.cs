namespace HeaderCheck.Core;

/// <summary>
/// YOURS TO WRITE. Content-Security-Policy on <see cref="ScanContext.Final"/>.
/// Spec: tests/HeaderCheck.Tests/CspCheckTests.cs. Run: dotnet test --filter CspCheckTests
///
/// Rules (code, severity):
///   csp.missing                High    Neither Content-Security-Policy nor Content-Security-Policy-Report-Only.
///   csp.report-only            Medium  Only the Report-Only header: nothing is enforced. Report only this, then stop.
///
///   Otherwise, parse the first Content-Security-Policy value:
///   csp.no-script-restriction  High    No script-src and no default-src.
///   csp.unsafe-inline          High    Script sources include 'unsafe-inline' and no 'nonce-...' or
///                                      'sha256-' / 'sha384-' / 'sha512-' source (a nonce or hash makes
///                                      modern browsers ignore 'unsafe-inline').
///   csp.unsafe-eval            Medium  Script sources include 'unsafe-eval'.
///   csp.wildcard-scripts       High    Script sources include *, http:, https: or data:.
///   csp.object-src             Medium  object-src (or default-src when object-src is absent) is not exactly 'none'.
///   csp.no-base-uri            Medium  base-uri is absent (it does not fall back to default-src).
///   csp.no-frame-ancestors     Low     frame-ancestors is absent (it does not fall back either).
///
/// "Script sources" = the script-src list, or default-src's when script-src is absent.
///
/// Parsing: directives are split by ';' and empty ones skipped. Each directive is a name then
/// sources, split on whitespace. Names and keywords ('self', 'none', 'unsafe-inline') are
/// case-insensitive. When a directive appears twice, browsers use the first and ignore the rest.
/// Tip: a small CspPolicy class that parses once (Dictionary of name to sources) keeps Run short.
/// </summary>
public sealed class CspCheck : ICheck
{
    public string Id => "csp";

    public string Name => "Content-Security-Policy";

    public IEnumerable<Finding> Run(ScanContext context)
    {
        throw new NotImplementedException();
    }
}
