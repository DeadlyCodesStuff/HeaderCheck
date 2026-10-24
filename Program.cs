using System.Text;
using System.Text.Json;

try
{
    Console.OutputEncoding = Encoding.UTF8;
}
catch (IOException)
{
}

var jsonOptions = new JsonSerializerOptions
{
    PropertyNameCaseInsensitive = true,
    ReadCommentHandling = JsonCommentHandling.Skip,
    AllowTrailingCommas = true
};

PrintBanner();

var dataFile = FindDataFile();
if (dataFile is null)
{
    WriteError("Could not find data.json next to the program or in a parent folder.");
    return;
}

HeaderCatalog? catalog;
try
{
    var json = await File.ReadAllTextAsync(dataFile);
    catalog = JsonSerializer.Deserialize<HeaderCatalog>(json, jsonOptions);
}
catch (JsonException ex)
{
    WriteError($"data.json is not valid JSON: {ex.Message}");
    return;
}
catch (IOException ex)
{
    WriteError($"Could not read data.json: {ex.Message}");
    return;
}

if (catalog?.Headers is not { Count: > 0 })
{
    WriteError("data.json does not contain any headers to check.");
    return;
}

Console.Write("  Target URL: ");
var rawUrl = Console.ReadLine();
Console.WriteLine();

if (string.IsNullOrWhiteSpace(rawUrl))
{
    WriteError("No URL supplied.");
    return;
}

var url = NormalizeUrl(rawUrl.Trim());
if (!Uri.TryCreate(url, UriKind.Absolute, out var target) ||
    (target.Scheme != Uri.UriSchemeHttp && target.Scheme != Uri.UriSchemeHttps))
{
    WriteError("That does not look like a valid HTTP or HTTPS URL.");
    return;
}

using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
client.DefaultRequestHeaders.UserAgent.ParseAdd("HeaderCheck/1.0");
client.DefaultRequestHeaders.Accept.ParseAdd("text/html,application/xhtml+xml,*/*;q=0.8");

HttpResponseMessage response;
try
{
    response = await client.GetAsync(target);
}
catch (TaskCanceledException)
{
    WriteError("The request timed out after 15 seconds.");
    return;
}
catch (HttpRequestException ex)
{
    WriteError($"The request failed: {ex.Message}");
    return;
}

using (response)
{
    var results = catalog.Headers
        .Select(definition =>
        {
            var present = TryGetHeader(response, definition.Name, out var value);
            return new HeaderResult(definition, present, value);
        })
        .ToList();

    var missing = results.Where(result => !result.Present).ToList();
    var presentCount = results.Count - missing.Count;
    var percent = results.Count == 0 ? 0 : presentCount / (double)results.Count * 100;
    var (rating, ratingColor) = Rate(percent);

    PrintReport(target, response, results, presentCount, percent, rating, ratingColor);

    if (missing.Count == 0)
    {
        Console.WriteLine();
        WriteColored("  All checked security headers are present. Nice.", ConsoleColor.Green);
        Console.WriteLine();
        return;
    }

    PrintMissingMenu(missing);

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
            WriteColored($"  Please choose a number between 1 and {missing.Count}.", ConsoleColor.Yellow);
            continue;
        }

        PrintHeaderDetails(missing[choice - 1]);

        Console.Write("  Press Enter to return to the menu...");
        Console.ReadLine();
        Console.WriteLine();
        PrintMissingMenu(missing);
    }

    Console.WriteLine();
}

static void PrintBanner()
{
    var width = Math.Min(TerminalWidth(), 72);
    Console.WriteLine();
    WriteColored("  " + new string('═', width), ConsoleColor.DarkCyan);
    Console.WriteLine();
    WriteColored("  HeaderCheck", ConsoleColor.Cyan);
    Console.WriteLine("  ·  HTTP Security Header Audit");
    WriteColored("  " + new string('═', width), ConsoleColor.DarkCyan);
    Console.WriteLine();
}

static void PrintReport(
    Uri target,
    HttpResponseMessage response,
    IReadOnlyList<HeaderResult> results,
    int presentCount,
    double percent,
    string rating,
    ConsoleColor ratingColor)
{
    var nameWidth = Math.Max(16, results.Max(result => result.Definition.Name.Length));

    WriteColored("  Summary", ConsoleColor.Yellow);
    Console.WriteLine();
    Console.WriteLine($"  {"Target",-9}: {target}");
    Console.WriteLine($"  {"Status",-9}: {(int)response.StatusCode} {response.ReasonPhrase}");
    Console.WriteLine($"  {"Checked",-9}: {results.Count} security headers");
    Console.WriteLine();

    WriteColored("  Header audit", ConsoleColor.Yellow);
    Console.WriteLine();
    Console.WriteLine($"  {"#",2}  {"Header".PadRight(nameWidth)}  Status");
    Console.WriteLine($"  {new string('─', 2)}  {new string('─', nameWidth)}  {new string('─', 10)}");

    for (var i = 0; i < results.Count; i++)
    {
        var result = results[i];
        Console.Write($"  {i + 1,2}  {result.Definition.Name.PadRight(nameWidth)}  ");

        if (result.Present)
        {
            WriteColored("✔ present", ConsoleColor.Green);
        }
        else
        {
            WriteColored("✘ missing", ConsoleColor.Red);
        }

        Console.WriteLine();
    }

    Console.WriteLine();
    Console.Write($"  {"Score",-9}: {presentCount}/{results.Count} ({percent:0}%) - ");
    WriteColored(rating, ratingColor);
    Console.WriteLine();
    WriteColored("  Presence only: the strength of each value is not validated.", ConsoleColor.DarkGray);
    Console.WriteLine();
}

static void PrintMissingMenu(IReadOnlyList<HeaderResult> missing)
{
    Console.WriteLine();
    WriteColored("  Missing headers", ConsoleColor.Yellow);
    Console.WriteLine();
    Console.WriteLine($"  {new string('─', 15)}");

    for (var i = 0; i < missing.Count; i++)
    {
        Console.WriteLine($"  {i + 1,2}. {missing[i].Definition.Name}");
    }

    Console.WriteLine();
    Console.WriteLine("  Enter a number to learn more, or press Enter to exit.");
}

static void PrintHeaderDetails(HeaderResult result)
{
    var definition = result.Definition;
    var ruleWidth = Math.Min(TerminalWidth(), 74);

    Console.WriteLine();
    WriteColored("  " + new string('─', ruleWidth), ConsoleColor.DarkGray);
    Console.WriteLine();
    WriteColored($"  {definition.Name}", ConsoleColor.Cyan);
    Console.WriteLine();
    WriteColored("  " + new string('─', ruleWidth), ConsoleColor.DarkGray);
    Console.WriteLine();

    WriteColored("  What it does", ConsoleColor.Yellow);
    Console.WriteLine();
    WriteWrapped(definition.Description, "    ");
    Console.WriteLine();

    WriteColored("  Recommended value", ConsoleColor.Yellow);
    Console.WriteLine();
    WriteWrapped(definition.RecommendedValue, "    ");
    Console.WriteLine();

    WriteColored("  Reference", ConsoleColor.Yellow);
    Console.WriteLine();
    Console.Write("    ");
    WriteColored(definition.Link, ConsoleColor.Blue);
    Console.WriteLine();
    Console.WriteLine();

    WriteColored("  Related vulnerabilities", ConsoleColor.Yellow);
    Console.WriteLine();

    for (var i = 0; i < definition.Vulnerabilities.Count; i++)
    {
        var vulnerability = definition.Vulnerabilities[i];
        Console.WriteLine();
        WriteColored($"  {i + 1}. {vulnerability.Name}", ConsoleColor.Red);
        Console.WriteLine();
        WriteWrapped(vulnerability.Description, "       ");
        Console.Write("       ");
        WriteColored(vulnerability.Link, ConsoleColor.Blue);
        Console.WriteLine();
    }

    if (definition.Notes.Count > 0)
    {
        Console.WriteLine();
        WriteColored("  Bypasses & notes", ConsoleColor.Yellow);
        Console.WriteLine();

        foreach (var note in definition.Notes)
        {
            WriteWrapped("• " + note, "    ", "      ");
        }
    }

    Console.WriteLine();
}

static string? FindDataFile()
{
    for (var directory = new DirectoryInfo(Directory.GetCurrentDirectory());
         directory is not null;
         directory = directory.Parent)
    {
        var candidate = Path.Combine(directory.FullName, "data.json");
        if (File.Exists(candidate))
        {
            return candidate;
        }
    }

    var besideExecutable = Path.Combine(AppContext.BaseDirectory, "data.json");
    return File.Exists(besideExecutable) ? besideExecutable : null;
}

static string NormalizeUrl(string input) =>
    input.Contains("://", StringComparison.Ordinal) ? input : "https://" + input;

static bool TryGetHeader(HttpResponseMessage response, string name, out string value)
{
    if (response.Headers.TryGetValues(name, out var values) ||
        response.Content.Headers.TryGetValues(name, out values))
    {
        value = string.Join(", ", values);
        return true;
    }

    value = string.Empty;
    return false;
}

static (string Label, ConsoleColor Color) Rate(double percent) => percent switch
{
    >= 90 => ("Excellent", ConsoleColor.Green),
    >= 70 => ("Good", ConsoleColor.Green),
    >= 50 => ("Fair", ConsoleColor.Yellow),
    > 0 => ("Poor", ConsoleColor.Red),
    _ => ("Critical", ConsoleColor.Red)
};

static int TerminalWidth()
{
    try
    {
        return Math.Clamp(Console.WindowWidth, 60, 120);
    }
    catch (IOException)
    {
        return 100;
    }
}

static void WriteWrapped(string text, string firstIndent, string? continuationIndent = null)
{
    continuationIndent ??= firstIndent;
    var indentWidth = Math.Max(firstIndent.Length, continuationIndent.Length);
    var width = Math.Max(30, TerminalWidth() - indentWidth - 2);
    var firstLine = true;

    foreach (var line in WrapText(text, width))
    {
        Console.WriteLine((firstLine ? firstIndent : continuationIndent) + line);
        firstLine = false;
    }
}

static IEnumerable<string> WrapText(string text, int width)
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

static void WriteColored(string text, ConsoleColor color)
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

static void WriteError(string message)
{
    Console.WriteLine();
    WriteColored($"  Error: {message}", ConsoleColor.Red);
    Console.WriteLine();
}

internal sealed class HeaderCatalog
{
    public List<HeaderDefinition> Headers { get; set; } = new();
}

internal sealed class HeaderDefinition
{
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string RecommendedValue { get; set; } = string.Empty;
    public string Link { get; set; } = string.Empty;
    public List<string> Notes { get; set; } = new();
    public List<VulnerabilityInfo> Vulnerabilities { get; set; } = new();
}

internal sealed class VulnerabilityInfo
{
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Link { get; set; } = string.Empty;
}

internal sealed record HeaderResult(HeaderDefinition Definition, bool Present, string Value);
