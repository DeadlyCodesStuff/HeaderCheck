using System.Text;
using HeaderCheck.Core;

try
{
    Console.OutputEncoding = Encoding.UTF8;
}
catch (IOException)
{
}

return await Cli.RunAsync(args);

internal static class Cli
{
    private const int ExitOk = 0;
    private const int ExitFindings = 1;
    private const int ExitError = 2;

    private const string Usage = """
        Usage: HeaderCheck [url] [options]

          url                 Site to check. https:// is assumed when no scheme is given.
                              Leave it out to be asked, with a menu to read about missing headers.

        Options:
          --json <path>       Also write the report as JSON.
          --html <path>       Also write the report as a standalone HTML page.
          --fail-on <level>   Exit with code 1 when a finding is at least this severe:
                              low, medium or high. Useful in scripts and CI.
          --no-menu           Skip the missing-header menu.
          -h, --help          Show this help.

        Exit codes: 0 done, 1 a finding met --fail-on, 2 error.
        """;

    private sealed record Options(string? Url, string? JsonPath, string? HtmlPath, Severity? FailOn, bool NoMenu);

    public static async Task<int> RunAsync(string[] args)
    {
        if (args.Any(a => a is "-h" or "--help"))
        {
            Console.WriteLine(Usage);
            return ExitOk;
        }

        if (!TryParse(args, out var options, out var error))
        {
            Output.Error(error);
            Console.WriteLine();
            Console.WriteLine(Usage);
            return ExitError;
        }

        Output.Banner();

        var catalog = LoadCatalog();
        if (catalog is null)
        {
            return ExitError;
        }

        var interactive = options.Url is null;
        var rawUrl = options.Url;
        if (interactive)
        {
            Console.Write("  Target URL: ");
            rawUrl = Console.ReadLine();
            Console.WriteLine();
        }

        if (string.IsNullOrWhiteSpace(rawUrl))
        {
            Output.Error("No URL supplied.");
            return ExitError;
        }

        var url = rawUrl.Trim();
        if (!url.Contains("://", StringComparison.Ordinal))
        {
            url = "https://" + url;
        }

        if (!Uri.TryCreate(url, UriKind.Absolute, out var target) ||
            (target.Scheme != Uri.UriSchemeHttp && target.Scheme != Uri.UriSchemeHttps))
        {
            Output.Error("That does not look like a valid HTTP or HTTPS URL.");
            return ExitError;
        }

        ScanContext context;
        using (var handler = Scanner.CreateHandler())
        {
            try
            {
                context = await new Scanner(handler).ScanAsync(target);
            }
            catch (ScanException ex)
            {
                Output.Error(ex.Message);
                return ExitError;
            }
        }

        var report = Analyzer.Run(context, catalog);
        Output.Report(report);

        if (!await TryWriteAsync(options.JsonPath, () => JsonReport.Render(report), "JSON") ||
            !await TryWriteAsync(options.HtmlPath, () => HtmlReport.Render(report), "HTML"))
        {
            return ExitError;
        }

        if (interactive && !options.NoMenu && !Console.IsInputRedirected)
        {
            Output.Menu(report.Presence.Where(p => !p.Present).ToList());
        }

        return options.FailOn is { } level && report.Findings.Any(f => f.Severity >= level)
            ? ExitFindings
            : ExitOk;
    }

    private static bool TryParse(string[] args, out Options options, out string error)
    {
        string? url = null, json = null, html = null;
        Severity? failOn = null;
        var noMenu = false;
        options = new Options(null, null, null, null, false);
        error = string.Empty;

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            string? Value() => i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal)
                ? args[++i]
                : null;

            switch (arg)
            {
                case "--json":
                    json = Value();
                    if (json is null)
                    {
                        error = "--json needs a file path.";
                        return false;
                    }
                    break;

                case "--html":
                    html = Value();
                    if (html is null)
                    {
                        error = "--html needs a file path.";
                        return false;
                    }
                    break;

                case "--fail-on":
                    var level = Value();
                    if (level is null ||
                        !Enum.TryParse<Severity>(level, ignoreCase: true, out var parsed) ||
                        !Enum.IsDefined(parsed) ||
                        parsed == Severity.Info)
                    {
                        error = "--fail-on needs low, medium or high.";
                        return false;
                    }
                    failOn = parsed;
                    break;

                case "--no-menu":
                    noMenu = true;
                    break;

                default:
                    if (arg.StartsWith('-'))
                    {
                        error = $"Unknown option: {arg}";
                        return false;
                    }
                    if (url is not null)
                    {
                        error = "Give one URL at a time.";
                        return false;
                    }
                    url = arg;
                    break;
            }
        }

        options = new Options(url, json, html, failOn, noMenu);
        return true;
    }

    private static HeaderCatalog? LoadCatalog()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "data.json");
        try
        {
            var catalog = HeaderCatalog.Parse(File.ReadAllText(path));
            if (catalog.Headers.Count > 0)
            {
                return catalog;
            }
            Output.Error("data.json does not contain any headers.");
        }
        catch (System.Text.Json.JsonException ex)
        {
            Output.Error($"data.json is not valid JSON: {ex.Message}");
        }
        catch (IOException ex)
        {
            Output.Error($"Could not read data.json: {ex.Message}");
        }
        return null;
    }

    private static async Task<bool> TryWriteAsync(string? path, Func<string> render, string label)
    {
        if (path is null)
        {
            return true;
        }

        try
        {
            await File.WriteAllTextAsync(path, render());
            Console.WriteLine($"  {label} report written to {Path.GetFullPath(path)}");
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Output.Error($"Could not write the {label} report: {ex.Message}");
            return false;
        }
    }
}
