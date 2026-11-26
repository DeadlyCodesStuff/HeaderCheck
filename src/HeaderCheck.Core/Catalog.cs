using System.Text.Json;
using System.Text.Json.Serialization;

namespace HeaderCheck.Core;

/// <summary>The header explanations from data.json.</summary>
public sealed class HeaderCatalog
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public List<HeaderDefinition> Headers { get; set; } = new();

    public static HeaderCatalog Parse(string json) =>
        JsonSerializer.Deserialize<HeaderCatalog>(json, Options) ?? new HeaderCatalog();

    public HeaderDefinition? Find(string name) =>
        Headers.FirstOrDefault(h => h.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
}

public sealed class HeaderDefinition
{
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string RecommendedValue { get; set; } = string.Empty;
    public string Link { get; set; } = string.Empty;

    /// <summary>
    /// Severity of a finding when this header is missing. Null when a deeper check
    /// (CSP, HSTS) already covers it, or the header is obsolete.
    /// </summary>
    public Severity? MissingSeverity { get; set; }

    public List<string> Notes { get; set; } = new();
    public List<VulnerabilityInfo> Vulnerabilities { get; set; } = new();
}

public sealed class VulnerabilityInfo
{
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Link { get; set; } = string.Empty;
}

/// <summary>Whether one catalog header was sent, and its value.</summary>
public sealed record HeaderPresence(HeaderDefinition Definition, bool Present, string? Value);

/// <summary>v1's check: is each catalog header there at all?</summary>
public sealed class PresenceCheck(HeaderCatalog catalog) : ICheck
{
    public string Id => "presence";

    public string Name => "Header presence";

    public IReadOnlyList<HeaderPresence> Inspect(ResponseSnapshot response) =>
        catalog.Headers
            .Select(definition => new HeaderPresence(definition, response.Has(definition.Name), response.Get(definition.Name)))
            .ToList();

    public IEnumerable<Finding> Run(ScanContext context)
    {
        foreach (var item in Inspect(context.Final))
        {
            if (item.Present || item.Definition.MissingSeverity is not { } severity)
            {
                continue;
            }

            yield return new Finding(
                $"presence.{item.Definition.Name.ToLowerInvariant()}",
                severity,
                $"{item.Definition.Name} is missing",
                $"Recommended: {item.Definition.RecommendedValue}");
        }
    }
}
