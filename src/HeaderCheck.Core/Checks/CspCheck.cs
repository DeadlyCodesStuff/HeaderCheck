namespace HeaderCheck.Core;

/// <summary>
/// Parses the enforced Content-Security-Policy and checks how well it limits scripts (inline,
/// eval, wildcards), plugins (object-src), the page's base URL and who may frame the page.
/// Script and object rules fall back to default-src, as browsers do.
/// </summary>
public sealed class CspCheck : ICheck
{
    public string Id => "csp";

    public string Name => "Content-Security-Policy";

    public IEnumerable<Finding> Run(ScanContext context)
    {
        var policy = context.Final.Get("Content-Security-Policy");
        var reportOnly = context.Final.Get("Content-Security-Policy-Report-Only");

        if (policy is null)
        {
            if (reportOnly is null)
            {
                yield return new Finding(
                    "csp.missing",
                    Severity.High,
                    "No Content-Security-Policy",
                    "Without a CSP, the browser runs any script that ends up in the page, so one injection bug (XSS) gives an attacker full control of it. Start with default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'.",
                    null
                );
                yield break;
            }
            else
            {
                yield return new Finding(
                    "csp.report-only",
                    Severity.Medium,
                    "The CSP is report-only",
                    "Content-Security-Policy-Report-Only only reports what it would block; nothing is actually blocked. That is the right way to test a policy. Once the reports are clean, send it as Content-Security-Policy.",
                    reportOnly
                );
                yield break;
            }

        }

        var directives = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in policy.Split(';'))
        {
            var words = part.Split(' ', StringSplitOptions.RemoveEmptyEntries);

            if (words.Length == 0)
            {
                continue;
            }

            var name = words[0];
            directives.TryAdd(name, words[1..]);

        }
        if (!directives.TryGetValue("script-src", out var scripts)
            && !directives.TryGetValue("default-src", out scripts))
        {
            yield return new Finding(
                "csp.no-script-restriction",
                Severity.High,
                "The CSP does not restrict scripts",
                "The policy has neither script-src nor default-src, so scripts from anywhere are allowed and the CSP gives no protection against XSS. Add script-src, or a default-src that covers it.",
                policy);

        }
        else
        {
            if (scripts.Contains("'unsafe-inline'", StringComparer.OrdinalIgnoreCase)
                && !scripts.Any(s => s.StartsWith("'nonce-", StringComparison.OrdinalIgnoreCase)
                    || s.StartsWith("'sha256-", StringComparison.OrdinalIgnoreCase)
                    || s.StartsWith("'sha384-", StringComparison.OrdinalIgnoreCase)
                    || s.StartsWith("'sha512-", StringComparison.OrdinalIgnoreCase)))
            {
                yield return new Finding(
                    "csp.unsafe-inline",
                    Severity.High,
                    "Inline scripts are allowed",
                    "'unsafe-inline' lets any <script> block or onclick-style attribute in the page run, including ones an attacker injects, which undoes most of what CSP is for. Use a nonce or hash for the inline scripts you need.",
                    string.Join(' ', scripts));
            }

            if (scripts.Contains("'unsafe-eval'", StringComparer.OrdinalIgnoreCase))
            {
                yield return new Finding(
                    "csp.unsafe-eval",
                    Severity.Medium,
                    "eval() is allowed",
                    "'unsafe-eval' lets scripts turn text into code with eval(), new Function() and similar, so an attacker who controls some text can run it as code. Remove it and replace the code that needs it.",
                    string.Join(' ', scripts));
            }

            string[] wildcardSources = ["*", "http:", "https:", "data:"];
            if (scripts.Any(s => wildcardSources.Contains(s, StringComparer.OrdinalIgnoreCase)))
            {
                yield return new Finding(
                    "csp.wildcard-scripts",
                    Severity.High,
                    "Scripts can load from almost anywhere",
                    "*, http:, https: and data: each allow scripts from any host or from inline data URLs, so an attacker can load their own script from a server they control. List the specific hosts you load scripts from.",
                    string.Join(' ', scripts));
            }

        }

        directives.TryGetValue("object-src", out var objects);
        if (objects is null)
        {
            directives.TryGetValue("default-src", out objects);
        }

        bool locked = objects is not null
            && objects.Length == 1
            && objects[0].Equals("'none'", StringComparison.OrdinalIgnoreCase);

        if (!locked)
        {
            yield return new Finding(
                "csp.object-src",
                Severity.Medium,
                "Plugins are not blocked",
                "object-src (or default-src, which it falls back to) is not 'none', so <object> and <embed> can load plugin content, an old way to run code that slips past script-src. Set object-src 'none'.",
                objects is null ? null : string.Join(' ', objects));
        }
        if (!directives.ContainsKey("base-uri"))
        {
            yield return new Finding(
                "csp.no-base-uri",
                Severity.Medium,
                "The base URL can be changed",
                "Without base-uri, an injected <base> tag can point every relative script URL on the page at the attacker's server. base-uri does not fall back to default-src. Add base-uri 'self' or 'none'.",
                policy);
        }
        if (!directives.ContainsKey("frame-ancestors"))
        {
            yield return new Finding(
                "csp.no-frame-ancestors",
                Severity.Low,
                "Any site can frame this page",
                "Without frame-ancestors, other sites can show this page in a hidden frame and trick users into clicking it (clickjacking). It does not fall back to default-src. Add frame-ancestors 'none', or 'self' if you frame your own pages.",
                policy);
        }
    }
}