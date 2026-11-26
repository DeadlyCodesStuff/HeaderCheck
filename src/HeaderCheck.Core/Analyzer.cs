namespace HeaderCheck.Core;

public enum CheckState
{
    Ran,
    NotWritten,
    Crashed
}

/// <summary>How one check went. A crash in one check never stops the others.</summary>
public sealed record CheckOutcome(string Id, string Name, CheckState State, string? Error = null);

/// <summary>Score out of 100 and a letter grade.</summary>
public sealed record Score(int Points, string Grade);

/// <summary>Everything a report needs.</summary>
public sealed record ScanReport(
    DateTimeOffset ScannedAt,
    Uri Requested,
    Uri FinalUrl,
    int StatusCode,
    IReadOnlyList<RedirectHop> Redirects,
    IReadOnlyList<HeaderPresence> Presence,
    IReadOnlyList<Finding> Findings,
    IReadOnlyList<CheckOutcome> Checks,
    Score Score);

public static class Scoring
{
    /// <summary>Points lost per finding.</summary>
    public static int Penalty(Severity severity) => severity switch
    {
        Severity.High => 25,
        Severity.Medium => 10,
        Severity.Low => 3,
        _ => 0
    };

    /// <summary>
    /// Start at 100 and subtract each finding's penalty, never below 0.
    /// One High finding alone lands at 75, a C: a serious hole can never grade A or B.
    /// </summary>
    public static Score Calculate(IEnumerable<Finding> findings)
    {
        var points = Math.Max(0, 100 - findings.Sum(f => Penalty(f.Severity)));
        var grade = points switch
        {
            >= 90 => "A",
            >= 80 => "B",
            >= 70 => "C",
            >= 60 => "D",
            _ => "F"
        };
        return new Score(points, grade);
    }
}

public static class Analyzer
{
    /// <summary>Every check, in report order.</summary>
    public static IReadOnlyList<ICheck> DefaultChecks(HeaderCatalog catalog) => new ICheck[]
    {
        new RedirectCheck(),
        new HstsCheck(),
        new CspCheck(),
        new CookieCheck(),
        new CorsCheck(),
        new PresenceCheck(catalog)
    };

    public static ScanReport Run(ScanContext context, HeaderCatalog catalog, IEnumerable<ICheck>? checks = null)
    {
        var findings = new List<Finding>();
        var outcomes = new List<CheckOutcome>();

        foreach (var check in checks ?? DefaultChecks(catalog))
        {
            try
            {
                // ToList so a lazy (yield) check fails here, inside the try.
                findings.AddRange(check.Run(context).ToList());
                outcomes.Add(new CheckOutcome(check.Id, check.Name, CheckState.Ran));
            }
            catch (NotImplementedException)
            {
                outcomes.Add(new CheckOutcome(check.Id, check.Name, CheckState.NotWritten));
            }
            catch (Exception ex)
            {
                outcomes.Add(new CheckOutcome(check.Id, check.Name, CheckState.Crashed, ex.Message));
            }
        }

        var ordered = findings
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.Code, StringComparer.Ordinal)
            .ToList();

        return new ScanReport(
            DateTimeOffset.UtcNow,
            context.Requested,
            context.Final.Url,
            context.Final.StatusCode,
            context.Redirects,
            new PresenceCheck(catalog).Inspect(context.Final),
            ordered,
            outcomes,
            Scoring.Calculate(ordered));
    }
}
