namespace HeaderCheck.Core;

/// <summary>
/// Checks the redirect chain: whether the site ends up on HTTPS, whether any hop drops back to
/// HTTP, whether the HTTPS upgrade uses a temporary redirect, and how long the chain is.
/// </summary>
public sealed class RedirectCheck : ICheck
{
    public string Id => "redirect";

    public string Name => "Redirects";

    static string BareHost(Uri uri)
    {
        var host = uri.Host;
        return host.StartsWith("www.", StringComparison.OrdinalIgnoreCase)
            ? host[4..]
            : host;
    }
    public IEnumerable<Finding> Run(ScanContext context)
    {
        if (!context.Final.IsHttps)
        {
            yield return new Finding(
            "redirect.no-https",
            Severity.High,
            "The site never moves to HTTPS",
            "Everything, including cookies and form data, travels unencrypted. Redirect HTTP to HTTPS with a 301.",
            context.Final.Url.ToString()

            );

        }

        foreach (var redirect in context.Redirects)
        {
            if (Uri.UriSchemeHttps == redirect.From.Scheme && redirect.To.Scheme == Uri.UriSchemeHttp)
            {
                yield return new Finding(
                "redirect.downgrade",
                Severity.High,
                "A redirect drops from HTTPS to HTTP",
                "The user was already on an encrypted connection, and this redirect throws that protection away. Point the redirect at the HTTPS address instead.",
                $"{redirect.From} -> {redirect.To}"
                );
            }

            if (Uri.UriSchemeHttp == redirect.From.Scheme && redirect.To.Scheme == Uri.UriSchemeHttps && redirect.To.Host == redirect.From.Host && (redirect.StatusCode == 302 || redirect.StatusCode == 307))
            {
                yield return new Finding(
                    "redirect.temporary-upgrade",
                    Severity.Info,
                    "The HTTPS upgrade uses a temporary redirect",
                    "Browsers do not remember a 302 or 307, so every visit starts over plain HTTP, where an attacker on the same network can stop the upgrade (SSL stripping). Use a 301 or 308, and send HSTS.",
                    $"{redirect.From} -> {redirect.To}"
                );
            }
        }
        if (context.Redirects.Count > 3)
        {
            yield return new Finding(
                    "redirect.long-chain",
                    Severity.Low,
                    "The redirect chain is long",
                    "Each hop is another round trip before the page loads, and a long chain usually means old redirects nobody cleaned up. Redirect straight to the final address.",
                    $"{context.Redirects.Count}"
                );
        }
        if (BareHost(context.Requested) != BareHost(context.Final.Url))
        {
            yield return new Finding(
                    "redirect.other-host",
                    Severity.Info,
                    "The site ends up on a different host",
                    "The user lands somewhere other than the site they asked for. That is often intended, such as a login provider, but check that every host in the chain is yours.",
                    context.Final.Url.Host
                );
        }

    }
}
