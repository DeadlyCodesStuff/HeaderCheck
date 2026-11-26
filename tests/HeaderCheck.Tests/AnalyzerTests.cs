using HeaderCheck.Core;

namespace HeaderCheck.Tests;

public class ScoringTests
{
    private static Finding F(Severity severity) => new("x.y", severity, "t", "d");

    [Fact]
    public void No_findings_is_a_perfect_a() =>
        Assert.Equal(new Score(100, "A"), Scoring.Calculate(Array.Empty<Finding>()));

    [Fact]
    public void Info_costs_nothing() =>
        Assert.Equal(new Score(100, "A"), Scoring.Calculate(new[] { F(Severity.Info), F(Severity.Info) }));

    [Theory]
    [InlineData(Severity.Medium, 1, 90, "A")]
    [InlineData(Severity.Low, 4, 88, "B")]
    [InlineData(Severity.High, 1, 75, "C")]
    [InlineData(Severity.Medium, 4, 60, "D")]
    [InlineData(Severity.Medium, 5, 50, "F")]
    [InlineData(Severity.High, 5, 0, "F")]
    public void Points_and_grade(Severity severity, int count, int points, string grade) =>
        Assert.Equal(new Score(points, grade), Scoring.Calculate(Enumerable.Repeat(F(severity), count)));
}

public class AnalyzerTests
{
    private sealed class FixedCheck(string id, Func<IEnumerable<Finding>> run) : ICheck
    {
        public string Id => id;
        public string Name => id;
        public IEnumerable<Finding> Run(ScanContext context) => run();
    }

    private static IEnumerable<Finding> Lazy(Exception ex)
    {
        yield return new Finding("lazy.first", Severity.Low, "t", "d");
        throw ex;
    }

    private static readonly HeaderCatalog Empty = new();

    [Fact]
    public void Unwritten_and_crashing_checks_are_reported_without_stopping_the_rest()
    {
        var checks = new ICheck[]
        {
            new FixedCheck("todo", () => throw new NotImplementedException()),
            new FixedCheck("boom", () => Lazy(new InvalidOperationException("bad parse"))),
            new FixedCheck("ok", () => new[] { new Finding("ok.one", Severity.Low, "t", "d") })
        };

        var report = Analyzer.Run(T.Final("https://a.test/"), Empty, checks);

        Assert.Equal(CheckState.NotWritten, report.Checks[0].State);
        Assert.Equal(new CheckOutcome("boom", "boom", CheckState.Crashed, "bad parse"), report.Checks[1]);
        Assert.Equal(CheckState.Ran, report.Checks[2].State);
        // A check that crashed partway contributes nothing.
        Assert.Equal(new[] { "ok.one" }, report.Findings.Select(f => f.Code));
    }

    [Fact]
    public void Findings_are_ordered_worst_first_then_by_code()
    {
        var check = new FixedCheck("mix", () => new[]
        {
            new Finding("b.low", Severity.Low, "t", "d"),
            new Finding("z.high", Severity.High, "t", "d"),
            new Finding("a.low", Severity.Low, "t", "d")
        });

        var report = Analyzer.Run(T.Final("https://a.test/"), Empty, new[] { check });

        Assert.Equal(new[] { "z.high", "a.low", "b.low" }, report.Findings.Select(f => f.Code));
        Assert.Equal(new Score(69, "D"), report.Score);
    }

    [Fact]
    public void Default_checks_cover_every_area() =>
        Assert.Equal(
            new[] { "redirect", "hsts", "csp", "cookie", "cors", "presence" },
            Analyzer.DefaultChecks(Empty).Select(c => c.Id));
}

public class PresenceCheckTests
{
    private static readonly HeaderCatalog Catalog = HeaderCatalog.Parse("""
        { "headers": [
            { "name": "X-Content-Type-Options", "missingSeverity": "Medium", "recommendedValue": "nosniff" },
            { "name": "Content-Security-Policy", "missingSeverity": null },
            { "name": "Referrer-Policy", "missingSeverity": "Low" }
        ] }
        """);

    [Fact]
    public void Missing_headers_with_a_severity_become_findings()
    {
        var findings = new PresenceCheck(Catalog).Run(T.Final("https://a.test/", ("referrer-policy", "no-referrer"))).ToList();

        var finding = Assert.Single(findings);
        Assert.Equal("presence.x-content-type-options", finding.Code);
        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Contains("nosniff", finding.Detail);
    }

    [Fact]
    public void Inspect_lists_every_catalog_header_with_its_value()
    {
        var presence = new PresenceCheck(Catalog).Inspect(ResponseSnapshot.Create("https://a.test/", 200, ("Referrer-Policy", "no-referrer")));

        Assert.Equal(new[] { false, false, true }, presence.Select(p => p.Present));
        Assert.Equal("no-referrer", presence[2].Value);
    }

    [Fact]
    public void The_shipped_data_file_parses_and_every_header_has_a_link()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "data.json");
        var catalog = HeaderCatalog.Parse(File.ReadAllText(path));

        Assert.Equal(10, catalog.Headers.Count);
        Assert.All(catalog.Headers, h => Assert.StartsWith("https://", h.Link));
        Assert.Equal(Severity.Medium, catalog.Find("x-content-type-options")!.MissingSeverity);
        Assert.Null(catalog.Find("Content-Security-Policy")!.MissingSeverity);
    }
}
