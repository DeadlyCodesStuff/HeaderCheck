using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace HeaderCheck.Core;

public static class JsonReport
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    public static string Render(ScanReport report) => JsonSerializer.Serialize(new
    {
        tool = "HeaderCheck 2.0",
        scannedAt = report.ScannedAt,
        requested = report.Requested.ToString(),
        finalUrl = report.FinalUrl.ToString(),
        statusCode = report.StatusCode,
        score = new { points = report.Score.Points, grade = report.Score.Grade },
        redirects = report.Redirects.Select(r => new { from = r.From.ToString(), status = r.StatusCode, to = r.To.ToString() }),
        findings = report.Findings,
        checks = report.Checks,
        headers = report.Presence.Select(p => new { name = p.Definition.Name, present = p.Present, value = p.Value })
    }, Options) + "\n";
}

public static class HtmlReport
{
    private static string E(string? text) => WebUtility.HtmlEncode(text ?? string.Empty);

    private static string SeverityClass(Severity severity) => severity.ToString().ToLowerInvariant();

    public static string Render(ScanReport report)
    {
        var html = new StringBuilder();
        html.Append($$"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>HeaderCheck: {{E(report.FinalUrl.Host)}}</title>
            <style>
              :root { --bg:#fff; --fg:#1b1d24; --muted:#5d6273; --line:#e3e5ec; --high:#b3261e; --medium:#a15c00; --low:#3b5ba5; --info:#5d6273; --ok:#1e7a3c; }
              @media (prefers-color-scheme: dark) { :root { --bg:#101218; --fg:#eceef4; --muted:#9aa0b2; --line:#2a2e3a; --high:#ff8a80; --medium:#ffb74d; --low:#8fb0ff; --info:#9aa0b2; --ok:#7ed69a; } }
              body { margin:0; background:var(--bg); color:var(--fg); font:15px/1.55 system-ui, sans-serif; }
              main { max-width:920px; margin:0 auto; padding:24px 16px 48px; }
              h1 { font-size:1.5rem; margin:0 0 4px; } h2 { font-size:1.1rem; margin:32px 0 8px; }
              .muted { color:var(--muted); } code { font:13px ui-monospace, monospace; overflow-wrap:anywhere; }
              .grade { display:inline-flex; align-items:baseline; gap:10px; margin:16px 0 4px; }
              .grade b { font-size:2.6rem; line-height:1; }
              table { width:100%; border-collapse:collapse; } th, td { text-align:left; padding:8px 6px; border-bottom:1px solid var(--line); vertical-align:top; }
              th { color:var(--muted); font-weight:600; font-size:.85rem; }
              .sev { font-weight:700; font-size:.8rem; text-transform:uppercase; letter-spacing:.04em; }
              .high { color:var(--high); } .medium { color:var(--medium); } .low { color:var(--low); } .info { color:var(--info); } .ok { color:var(--ok); }
              .wrap { overflow-x:auto; }
            </style>
            </head>
            <body>
            <main>
            <h1>HeaderCheck report</h1>
            <p class="muted">{{E(report.FinalUrl.ToString())}} · status {{report.StatusCode}} · {{E(report.ScannedAt.ToString("yyyy-MM-dd HH:mm 'UTC'"))}}</p>
            <div class="grade"><b>{{E(report.Score.Grade)}}</b><span>{{report.Score.Points}}/100</span></div>

            """);

        html.Append("<h2>Findings</h2>\n");
        if (report.Findings.Count == 0)
        {
            html.Append("<p class=\"ok\">No problems found by the checks that ran.</p>\n");
        }
        else
        {
            html.Append("<div class=\"wrap\"><table>\n<tr><th>Severity</th><th>Finding</th><th>Evidence</th></tr>\n");
            foreach (var f in report.Findings)
            {
                html.Append($"<tr><td class=\"sev {SeverityClass(f.Severity)}\">{f.Severity}</td>")
                    .Append($"<td><strong>{E(f.Title)}</strong><br><span class=\"muted\">{E(f.Detail)}</span><br><code class=\"muted\">{E(f.Code)}</code></td>")
                    .Append($"<td><code>{E(f.Evidence)}</code></td></tr>\n");
            }
            html.Append("</table></div>\n");
        }

        var skipped = report.Checks.Where(c => c.State != CheckState.Ran).ToList();
        if (skipped.Count > 0)
        {
            html.Append("<h2>Checks that did not run</h2>\n<ul>\n");
            foreach (var c in skipped)
            {
                var why = c.State == CheckState.NotWritten ? "not written yet" : $"crashed: {c.Error}";
                html.Append($"<li>{E(c.Name)}: <span class=\"muted\">{E(why)}</span></li>\n");
            }
            html.Append("</ul>\n");
        }

        if (report.Redirects.Count > 0)
        {
            html.Append("<h2>Redirects</h2>\n<ol>\n");
            foreach (var r in report.Redirects)
            {
                html.Append($"<li><code>{E(r.From.ToString())}</code> → {r.StatusCode} → <code>{E(r.To.ToString())}</code></li>\n");
            }
            html.Append("</ol>\n");
        }

        html.Append("<h2>Headers</h2>\n<div class=\"wrap\"><table>\n<tr><th>Header</th><th>Value</th></tr>\n");
        foreach (var p in report.Presence)
        {
            var value = p.Present ? $"<code>{E(p.Value)}</code>" : "<span class=\"high\">missing</span>";
            // Only http(s) links: a javascript: URL in an edited data.json would run when clicked.
            var name = p.Definition.Link.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
                       p.Definition.Link.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                ? $"<a href=\"{E(p.Definition.Link)}\">{E(p.Definition.Name)}</a>"
                : E(p.Definition.Name);
            html.Append($"<tr><td>{name}</td><td>{value}</td></tr>\n");
        }
        html.Append("</table></div>\n");

        html.Append("<p class=\"muted\">A missing header does not prove a site is vulnerable, and a present one does not prove it is safe.</p>\n");
        html.Append("</main>\n</body>\n</html>\n");
        return html.ToString();
    }
}
