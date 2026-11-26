namespace HeaderCheck.Core;

/// <summary>How much a finding matters. Order matters: higher is worse.</summary>
public enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3
}

/// <summary>
/// One problem (or note) a check found.
/// <para><c>Code</c> is a stable id like <c>hsts.short-max-age</c>. Tests match on it, so the
/// title and detail wording is yours to choose.</para>
/// <para><c>Evidence</c> is the part of the response that triggered it. Never put cookie values
/// or other secrets in it: reports get shared.</para>
/// </summary>
public sealed record Finding(
    string Code,
    Severity Severity,
    string Title,
    string Detail,
    string? Evidence = null);

/// <summary>One redirect the scanner followed.</summary>
public sealed record RedirectHop(Uri From, int StatusCode, Uri To);

/// <summary>
/// The headers of one HTTP response, frozen so checks can run without the network.
/// Header names are case-insensitive. A header sent several times (Set-Cookie) keeps
/// each value separately.
/// </summary>
public sealed class ResponseSnapshot
{
    private readonly Dictionary<string, List<string>> _headers;

    public ResponseSnapshot(Uri url, int statusCode, IEnumerable<KeyValuePair<string, string>> headers)
    {
        Url = url;
        StatusCode = statusCode;
        _headers = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, value) in headers)
        {
            if (!_headers.TryGetValue(name, out var list))
            {
                list = new List<string>();
                _headers[name] = list;
            }
            list.Add(value);
        }
    }

    public Uri Url { get; }

    public int StatusCode { get; }

    public bool IsHttps => Url.Scheme == Uri.UriSchemeHttps;

    /// <summary>Every header, for reports.</summary>
    public IReadOnlyDictionary<string, List<string>> Headers => _headers;

    public bool Has(string name) => _headers.ContainsKey(name);

    /// <summary>The first value of a header, or null when it was not sent.</summary>
    public string? Get(string name) =>
        _headers.TryGetValue(name, out var values) && values.Count > 0 ? values[0] : null;

    /// <summary>Every value of a header, in the order received. Empty when it was not sent.</summary>
    public IReadOnlyList<string> GetAll(string name) =>
        _headers.TryGetValue(name, out var values) ? values : Array.Empty<string>();

    /// <summary>Test helper: <c>ResponseSnapshot.Create("https://a.test", 200, ("X-Frame-Options", "DENY"))</c>.</summary>
    public static ResponseSnapshot Create(string url, int statusCode, params (string Name, string Value)[] headers) =>
        new(new Uri(url), statusCode, headers.Select(h => new KeyValuePair<string, string>(h.Name, h.Value)));
}

/// <summary>Everything a check may look at.</summary>
public sealed class ScanContext
{
    /// <summary>The Origin header the CORS probe sends. A server that echoes it back trusts anyone.</summary>
    public const string ProbeOrigin = "https://headercheck-probe.invalid";

    public ScanContext(
        Uri requested,
        ResponseSnapshot final,
        IReadOnlyList<RedirectHop>? redirects = null,
        ResponseSnapshot? corsProbe = null)
    {
        Requested = requested;
        Final = final;
        Redirects = redirects ?? Array.Empty<RedirectHop>();
        CorsProbe = corsProbe;
    }

    /// <summary>The URL the user asked for, after adding https:// when no scheme was given.</summary>
    public Uri Requested { get; }

    /// <summary>The response the redirects ended on. Most checks look only at this.</summary>
    public ResponseSnapshot Final { get; }

    /// <summary>Each redirect followed, in order. Empty when the first response was final.</summary>
    public IReadOnlyList<RedirectHop> Redirects { get; }

    /// <summary>
    /// A second request to <see cref="Final"/>'s URL that sent <c>Origin: </c><see cref="ProbeOrigin"/>.
    /// Null when that request failed.
    /// </summary>
    public ResponseSnapshot? CorsProbe { get; }
}

/// <summary>A check looks at a scan and reports findings. It never touches the network.</summary>
public interface ICheck
{
    /// <summary>Short id, also the prefix of every finding code: "hsts".</summary>
    string Id { get; }

    /// <summary>Name for reports: "Strict-Transport-Security".</summary>
    string Name { get; }

    IEnumerable<Finding> Run(ScanContext context);
}
