namespace HeaderCheck.Core;

/// <summary>
/// Parses every Set-Cookie header and checks each cookie for Secure, HttpOnly, SameSite and the
/// __Secure- and __Host- prefix rules. Findings name the cookie but never show its value.
/// </summary>
public sealed class CookieCheck : ICheck
{
    public string Id => "cookie";

    public string Name => "Cookies";

    public IEnumerable<Finding> Run(ScanContext context)
    {

        foreach (var cookie in context.Final.GetAll("Set-Cookie"))
        {
            string name;
            bool secure = false;
            bool httponly =false;
            string? samesite = null;
            bool hasDomain = false;
            string? path = null;
            var segments = cookie.Split(';');
            
            var parts = segments[0].Split('=', 2);
            if (parts.Length < 2)
                continue;

            name = parts[0].Trim();
            foreach(var segment in  segments.Skip(1))
            {
                var pieces = segment.Split('=', 2);
                var attrName = pieces[0].Trim();
                var attrValue = pieces.Length == 2 ? pieces[1].Trim() : null;
                switch (attrName.ToLowerInvariant())
                {
                    case "secure":
                        secure = true;
                        break;

                    case "httponly":
                    httponly = true;
                    break;

                    case "samesite":
                    samesite = attrValue;
                    break;

                    case "domain":
                    hasDomain = true;
                    break;

                    case "path":
                    path = attrValue;
                    break;

                }
            }
            if (string.Equals(samesite, "None", StringComparison.OrdinalIgnoreCase) && !secure){
                yield return new Finding(
                "cookie.samesite-none-insecure",
                Severity.High,
                "SameSite=None cookie without Secure",
                "SameSite=None sends this cookie on requests from every other site, and browsers reject that unless the cookie is also Secure. As set, the cookie is dropped or, in older browsers, sent over plain HTTP. Add Secure.",
                name
                );
            }
            else if (!secure)
            {
                yield return new Finding(
                "cookie.no-secure",
                Severity.Medium,
                "Cookie can be sent over plain HTTP",
                "Without Secure, the browser also sends this cookie on unencrypted requests, where anyone on the network can read it. Add Secure.",
                name
                );
            }

            if (!httponly)
            {
                yield return new Finding(
                "cookie.no-httponly",
                Severity.Low,
                "Cookie is readable by JavaScript",
                "Without HttpOnly, any script on the page can read this cookie through document.cookie, so a single XSS bug can steal it. Add HttpOnly unless your own scripts need to read it.",
                name
                );
            }
            if (samesite == null)
            {
                yield return new Finding(
                "cookie.no-samesite",
                Severity.Low,
                "Cookie has no SameSite setting",
                "Without SameSite, the browser picks a default, and older browsers send the cookie on requests from other sites, which allows cross-site request forgery. Set SameSite=Lax, or Strict if the cookie is never needed when arriving from another site.",
                name
                );
            }

            if (name.StartsWith("__Secure-", StringComparison.Ordinal) && !secure)
            {
                yield return new Finding(
                "cookie.bad-prefix",
                Severity.High,
                "Cookie breaks its name prefix's rules",
                "A __Secure- cookie must have Secure. Browsers reject it otherwise, so the cookie is never stored. Add Secure.",
                name
                );
            }

            if (name.StartsWith("__Host-", StringComparison.Ordinal) && (!secure || hasDomain || path != "/"))
            {
                yield return new Finding(
                "cookie.bad-prefix",
                Severity.High,
                "Cookie breaks its name prefix's rules",
                "A __Host- cookie must have Secure and Path=/ and no Domain, which locks it to this exact host. Browsers reject it otherwise, so the cookie is never stored. Fix the attributes rather than renaming the cookie, or the protection is lost.",
                name
                );
            }



        }
    }
}
