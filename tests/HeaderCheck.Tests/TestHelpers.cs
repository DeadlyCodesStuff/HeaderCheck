using HeaderCheck.Core;

namespace HeaderCheck.Tests;

internal static class T
{
    /// <summary>A scan that ended on <paramref name="finalUrl"/> with no redirects.</summary>
    public static ScanContext Final(string finalUrl, params (string Name, string Value)[] headers) =>
        new(new Uri(finalUrl), ResponseSnapshot.Create(finalUrl, 200, headers));

    /// <summary>A scan whose CORS probe came back with these headers.</summary>
    public static ScanContext Probe(params (string Name, string Value)[] probeHeaders) =>
        new(new Uri("https://a.test/"),
            ResponseSnapshot.Create("https://a.test/", 200),
            corsProbe: ResponseSnapshot.Create("https://a.test/", 200, probeHeaders));

    /// <summary>Asks for <paramref name="requested"/>, follows <paramref name="hops"/>, ends on the last hop's target.</summary>
    public static ScanContext Chain(string requested, params (string From, int Status, string To)[] hops)
    {
        var list = hops.Select(h => new RedirectHop(new Uri(h.From), h.Status, new Uri(h.To))).ToList();
        var final = list.Count > 0 ? list[^1].To.ToString() : requested;
        return new ScanContext(new Uri(requested), ResponseSnapshot.Create(final, 200), list);
    }

    public static List<Finding> Run(ICheck check, ScanContext context) => check.Run(context).ToList();

    /// <summary>The findings' codes must be exactly these, in any order.</summary>
    public static void Codes(IEnumerable<Finding> findings, params string[] expected) =>
        Assert.Equal(expected.OrderBy(c => c), findings.Select(f => f.Code).OrderBy(c => c));

    public static Finding One(IEnumerable<Finding> findings, string code) =>
        Assert.Single(findings, f => f.Code == code);
}
