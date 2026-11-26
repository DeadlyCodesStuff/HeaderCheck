using System.Text;
using HeaderCheck.Core;

/// <summary>Everything the console shows. v1's look, extended for findings and grades.</summary>
internal static class Output
{
    public static void Banner()
    {
        var width = Math.Min(TerminalWidth(), 72);
        Console.WriteLine();
        Colored("  " + new string('═', width), ConsoleColor.DarkCyan);
        Console.WriteLine();
        Colored("  HeaderCheck", ConsoleColor.Cyan);
        Console.WriteLine("  ·  HTTP Security Header Audit");
        Colored("  " + new string('═', width), ConsoleColor.DarkCyan);
        Console.WriteLine();
        Console.WriteLine();
    }

    public static void Report(ScanReport report)
    {
        Heading("Summary");
        Console.WriteLine($"  {"Requested",-10}: {report.Requested}");
        Console.WriteLine($"  {"Final",-10}: {report.FinalUrl}");
        Console.WriteLine($"  {"Status",-10}: {report.StatusCode}");
        Console.WriteLine();

        if (report.Redirects.Count > 0)
        {
            Heading("Redirects");
            for (var i = 0; i < report.Redirects.Count; i++)
            {
                var hop = report.Redirects[i];
                Console.WriteLine($"  {i + 1,2}. {hop.StatusCode}  {hop.From}");
                Colored($"           -> {hop.To}", ConsoleColor.DarkGray);
                Console.WriteLine();
            }
            Console.WriteLine();
        }

        Heading("Findings");
        if (report.Findings.Count == 0)
        {
            Colored("  None from the checks that ran.", ConsoleColor.Green);
            Console.WriteLine();
        }

        foreach (var finding in report.Findings)
        {
            Console.Write("  ");
            Colored($"{finding.Severity.ToString().ToUpperInvariant(),-6}", SeverityColor(finding.Severity));
            Console.WriteLine($"  {finding.Title}");
            if (!string.IsNullOrEmpty(finding.Evidence))
            {
                Colored($"          {finding.Evidence}", ConsoleColor.DarkGray);
                Console.WriteLine();
            }
            Wrapped(finding.Detail, "          ");
        }
        Console.WriteLine();

        var notRun = report.Checks.Where(c => c.State != CheckState.Ran).ToList();
        if (notRun.Count > 0)
        {
            Heading("Checks that did not run");
            foreach (var check in notRun)
            {
                var why = check.State == CheckState.NotWritten ? "not written yet" : $"crashed: {check.Error}";
                Console.Write($"  {check.Name}: ");
                Colored(why, check.State == CheckState.NotWritten ? ConsoleColor.Yellow : ConsoleColor.Red);
                Console.WriteLine();
            }
            Console.WriteLine();
        }

        Heading("Headers");
        var nameWidth = Math.Max(16, report.Presence.Max(p => p.Definition.Name.Length));
        foreach (var item in report.Presence)
        {
            Console.Write($"  {item.Definition.Name.PadRight(nameWidth)}  ");
            if (item.Present)
            {
                Colored("✔ present", ConsoleColor.Green);
            }
            else
            {
                Colored("✘ missing", ConsoleColor.Red);
            }
            Console.WriteLine();
        }
        Console.WriteLine();

        Console.Write($"  {"Grade",-10}: ");
        Colored($"{report.Score.Grade}", GradeColor(report.Score.Grade));
        Console.WriteLine($"  ({report.Score.Points}/100)");
        if (notRun.Count > 0)
        {
            Colored("  Some checks did not run, so the grade is not the full picture.", ConsoleColor.DarkGray);
            Console.WriteLine();
        }
        Console.WriteLine();
    }

    public static void Menu(IReadOnlyList<HeaderPresence> missing)
    {
        if (missing.Count == 0)
        {
            return;
        }

        ListMissing(missing);
        while (true)
        {
            Console.WriteLine();
            Console.Write("  > ");
            var input = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(input) || input.Trim().Equals("q", StringComparison.OrdinalIgnoreCase))
            {
                break;
            }

            if (!int.TryParse(input.Trim(), out var choice) || choice < 1 || choice > missing.Count)
            {
                Colored($"  Please choose a number between 1 and {missing.Count}.", ConsoleColor.Yellow);
                continue;
            }

            Details(missing[choice - 1].Definition);
            Console.Write("  Press Enter to return to the menu...");
            Console.ReadLine();
            Console.WriteLine();
            ListMissing(missing);
        }
        Console.WriteLine();
    }

    private static void ListMissing(IReadOnlyList<HeaderPresence> missing)
    {
        Heading("Missing headers");
        for (var i = 0; i < missing.Count; i++)
        {
            Console.WriteLine($"  {i + 1,2}. {missing[i].Definition.Name}");
        }
        Console.WriteLine();
        Console.WriteLine("  Enter a number to learn more, or press Enter to exit.");
    }

    private static void Details(HeaderDefinition definition)
    {
        var ruleWidth = Math.Min(TerminalWidth(), 74);
        Console.WriteLine();
        Colored("  " + new string('─', ruleWidth), ConsoleColor.DarkGray);
        Console.WriteLine();
        Colored($"  {definition.Name}", ConsoleColor.Cyan);
        Console.WriteLine();
        Colored("  " + new string('─', ruleWidth), ConsoleColor.DarkGray);
        Console.WriteLine();

        Heading("What it does");
        Wrapped(definition.Description, "    ");
        Console.WriteLine();

        Heading("Recommended value");
        Wrapped(definition.RecommendedValue, "    ");
        Console.WriteLine();

        Heading("Reference");
        Console.Write("    ");
        Colored(definition.Link, ConsoleColor.Blue);
        Console.WriteLine();
        Console.WriteLine();

        Heading("Related vulnerabilities");
        for (var i = 0; i < definition.Vulnerabilities.Count; i++)
        {
            var vulnerability = definition.Vulnerabilities[i];
            Console.WriteLine();
            Colored($"  {i + 1}. {vulnerability.Name}", ConsoleColor.Red);
            Console.WriteLine();
            Wrapped(vulnerability.Description, "       ");
            Console.Write("       ");
            Colored(vulnerability.Link, ConsoleColor.Blue);
            Console.WriteLine();
        }

        if (definition.Notes.Count > 0)
        {
            Console.WriteLine();
            Heading("Bypasses & notes");
            foreach (var note in definition.Notes)
            {
                Wrapped("• " + note, "    ", "      ");
            }
        }
        Console.WriteLine();
    }

    public static void Error(string message)
    {
        Console.WriteLine();
        Colored($"  Error: {message}", ConsoleColor.Red);
        Console.WriteLine();
    }

    private static void Heading(string text)
    {
        Colored($"  {text}", ConsoleColor.Yellow);
        Console.WriteLine();
    }

    private static ConsoleColor SeverityColor(Severity severity) => severity switch
    {
        Severity.High => ConsoleColor.Red,
        Severity.Medium => ConsoleColor.Yellow,
        Severity.Low => ConsoleColor.Cyan,
        _ => ConsoleColor.DarkGray
    };

    private static ConsoleColor GradeColor(string grade) => grade switch
    {
        "A" or "B" => ConsoleColor.Green,
        "C" => ConsoleColor.Yellow,
        _ => ConsoleColor.Red
    };

    private static int TerminalWidth()
    {
        try
        {
            return Console.IsOutputRedirected ? 100 : Math.Clamp(Console.WindowWidth, 60, 120);
        }
        catch (IOException)
        {
            return 100;
        }
    }

    private static void Wrapped(string text, string firstIndent, string? continuationIndent = null)
    {
        continuationIndent ??= firstIndent;
        var indentWidth = Math.Max(firstIndent.Length, continuationIndent.Length);
        var width = Math.Max(30, TerminalWidth() - indentWidth - 2);
        var first = true;
        foreach (var line in Wrap(text, width))
        {
            Console.WriteLine((first ? firstIndent : continuationIndent) + line);
            first = false;
        }
    }

    private static IEnumerable<string> Wrap(string text, int width)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            yield return string.Empty;
            yield break;
        }

        var line = new StringBuilder();
        foreach (var word in text.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (line.Length > 0 && line.Length + 1 + word.Length > width)
            {
                yield return line.ToString();
                line.Clear();
            }
            if (line.Length > 0)
            {
                line.Append(' ');
            }
            line.Append(word);
        }
        if (line.Length > 0)
        {
            yield return line.ToString();
        }
    }

    private static void Colored(string text, ConsoleColor color)
    {
        if (Console.IsOutputRedirected)
        {
            Console.Write(text);
            return;
        }
        var previous = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.Write(text);
        Console.ForegroundColor = previous;
    }
}
