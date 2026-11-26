namespace HeaderCheck.Core;

/// <summary>
/// YOURS TO WRITE. Strict-Transport-Security on <see cref="ScanContext.Final"/>.
/// Spec: tests/HeaderCheck.Tests/HstsCheckTests.cs. Run: dotnet test --filter HstsCheckTests
///
/// Rules (code, severity):
///   hsts.missing            High    Final is HTTPS and the header is absent.
///   hsts.over-http          Info    Final is HTTP and the header is present (browsers ignore it there).
///                                   Final is HTTP and absent: no finding; the redirect check covers HTTP.
///   hsts.invalid            High    max-age missing, or not a whole number of 0 or more. Report only this, then stop.
///   hsts.disabled           High    max-age=0 (tells browsers to forget HSTS).
///   hsts.short-max-age      Medium  max-age from 1 to 31535999 (under one year).
///   hsts.no-subdomains      Low     includeSubDomains is absent.
///   hsts.preload-ineligible Low     preload is present, but max-age is under a year or includeSubDomains is absent.
///
/// Parsing: directives are split by ';'. Names are case-insensitive and may have spaces around
/// them and around '='. The max-age value may be quoted: max-age="31536000".
/// Put the raw header value in Evidence.
/// </summary>
public sealed class HstsCheck : ICheck
{
    public const int OneYear = 31536000;

    public string Id => "hsts";

    public string Name => "Strict-Transport-Security";

    public IEnumerable<Finding> Run(ScanContext context)
    {
        throw new NotImplementedException();
    }
}
