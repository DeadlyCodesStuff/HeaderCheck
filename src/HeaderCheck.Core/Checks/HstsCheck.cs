namespace HeaderCheck.Core;

/// <summary>
/// Parses Strict-Transport-Security on the final response and checks that it is valid, lasts at
/// least a year, covers subdomains, and meets the preload rules when preload is requested.
/// </summary>
public sealed class HstsCheck : ICheck
{
    public const int OneYear = 31536000;

    public string Id => "hsts";

    public string Name => "Strict-Transport-Security";

    public IEnumerable<Finding> Run(ScanContext context)
    {
        bool includeSubDomains = false;
        bool preload = false;
        int? maxAge = null;   // null = "never found a usable max-age"


        var value = context.Final.Get("Strict-Transport-Security");

        if (value is null)
        {
            if (context.Final.IsHttps)
            {
                yield return new Finding(
                    "hsts.missing",
                    Severity.High,
                    "No HSTS header",
                    "Without Strict-Transport-Security, a browser will still try plain HTTP when someone types the address or follows an http:// link, and an attacker on the same network can stop the upgrade to HTTPS (SSL stripping). Send max-age=31536000; includeSubDomains.",
                    value
                );
            }
            yield break;
        }

        if (!context.Final.IsHttps)
        {
            yield return new Finding(
                "hsts.over-http",
                Severity.Info,
                "HSTS is sent over plain HTTP",
                "Browsers ignore Strict-Transport-Security on an unencrypted response, because an attacker could have added or removed it. Send it on the HTTPS response instead.",
                value
            );
            yield break;
        }

        foreach (var part in value.Split(';'))
        {
            var pieces = part.Split('=', 2);

            string name = pieces[0].Trim();

            if (pieces.Length == 2)
            {
                string val = pieces[1].Trim();

                if (string.Equals(name, "max-age", StringComparison.OrdinalIgnoreCase))
                {
                    val = val.Trim('"');
                    if (int.TryParse(val, out var n) && n >= 0)
                    {
                        maxAge = n;
                    }
                }
            }
            else
            {
                if (string.Equals(name, "includeSubDomains", StringComparison.OrdinalIgnoreCase))
                    includeSubDomains = true;
                else if (string.Equals(name, "preload", StringComparison.OrdinalIgnoreCase))
                    preload = true;
            }
        }
        if (maxAge is null)
        {
            yield return new Finding(
                "hsts.invalid",
                Severity.High,
                "The HSTS header has no usable max-age",
                "max-age is missing or is not a whole number, so browsers ignore the whole header and the site has no HSTS protection. Use max-age=31536000 or more.",
                value

            );
            yield break;
        }
        if (maxAge == 0)
        {
            yield return new Finding(
                "hsts.disabled",
                Severity.High,
                "HSTS is switched off",
                "max-age=0 tells browsers to forget any HSTS they remembered for this site, so the next visit can start over plain HTTP. Set max-age to at least a year unless you are deliberately removing HTTPS.",
                value

            );
        }
        if (maxAge >= 1 && maxAge < OneYear)
        {
            yield return new Finding(
                "hsts.short-max-age",
                Severity.Medium,
                "HSTS expires in under a year",
                "Browsers forget the policy when max-age runs out, and the first visit after that is open to SSL stripping again. A short max-age is fine while testing; raise it to at least 31536000 (one year).",
                value
            );
        }
        if (!includeSubDomains)
        {
            yield return new Finding(
                "hsts.no-subdomains",
                Severity.Low,
                "HSTS does not cover subdomains",
                "Without includeSubDomains, subdomains can still be reached over HTTP, and an attacker can use one to set or read cookies for the main site. Add includeSubDomains once every subdomain supports HTTPS.",
                value
            );
        }
        if (preload && (maxAge < OneYear || !includeSubDomains))
        {
            yield return new Finding(
                "hsts.preload-ineligible",
                Severity.Low,
                "Preload is requested but the policy does not qualify",
                "The browser preload list only accepts sites with max-age of at least a year and includeSubDomains, so asking for preload has no effect. Fix both, then submit the site at hstspreload.org.",
                value
            );
        }


    }
}
