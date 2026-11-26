namespace HeaderCheck.Core;

/// <summary>A request that could not complete (timeout, DNS, TLS, too many redirects).</summary>
public sealed class ScanException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>
/// Makes the requests: follows redirects one hop at a time so each is recorded,
/// then sends a second request with an Origin header for the CORS check.
/// </summary>
public sealed class Scanner
{
    public const int DefaultMaxRedirects = 10;

    private static readonly int[] RedirectCodes = { 301, 302, 303, 307, 308 };

    private readonly HttpClient _client;
    private readonly int _maxRedirects;

    /// <param name="handler">
    /// Must not follow redirects or keep cookies itself. Use <see cref="CreateHandler"/>,
    /// or a fake handler in tests.
    /// </param>
    public Scanner(HttpMessageHandler handler, TimeSpan? timeout = null, int maxRedirects = DefaultMaxRedirects)
    {
        _client = new HttpClient(handler, disposeHandler: false)
        {
            Timeout = timeout ?? TimeSpan.FromSeconds(15)
        };
        _client.DefaultRequestHeaders.UserAgent.ParseAdd("HeaderCheck/2.0");
        _client.DefaultRequestHeaders.Accept.ParseAdd("text/html,application/xhtml+xml,*/*;q=0.8");
        _maxRedirects = maxRedirects;
    }

    public static HttpMessageHandler CreateHandler() => new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        AutomaticDecompression = System.Net.DecompressionMethods.All
    };

    public async Task<ScanContext> ScanAsync(Uri target, CancellationToken cancellationToken = default)
    {
        var redirects = new List<RedirectHop>();
        var current = target;

        while (true)
        {
            var snapshot = await FetchAsync(current, origin: null, cancellationToken);

            var location = snapshot.Get("Location");
            if (!RedirectCodes.Contains(snapshot.StatusCode) || string.IsNullOrWhiteSpace(location))
            {
                var probe = await TryProbeCorsAsync(current, cancellationToken);
                return new ScanContext(target, snapshot, redirects, probe);
            }

            if (redirects.Count >= _maxRedirects)
            {
                throw new ScanException($"Stopped after {_maxRedirects} redirects. The site may be redirecting in a loop.");
            }

            if (!Uri.TryCreate(current, location.Trim(), out var next) ||
                (next.Scheme != Uri.UriSchemeHttp && next.Scheme != Uri.UriSchemeHttps))
            {
                throw new ScanException($"The site redirected to an address that cannot be followed: {location}");
            }

            redirects.Add(new RedirectHop(current, snapshot.StatusCode, next));
            current = next;
        }
    }

    private async Task<ResponseSnapshot?> TryProbeCorsAsync(Uri url, CancellationToken cancellationToken)
    {
        try
        {
            return await FetchAsync(url, ScanContext.ProbeOrigin, cancellationToken);
        }
        catch (ScanException)
        {
            return null;
        }
    }

    private async Task<ResponseSnapshot> FetchAsync(Uri url, string? origin, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        if (origin is not null)
        {
            request.Headers.TryAddWithoutValidation("Origin", origin);
        }

        try
        {
            // Headers only: the body is never needed, so do not download it.
            using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            var headers = response.Headers
                .Concat(response.Content.Headers)
                .SelectMany(header => header.Value.Select(value => new KeyValuePair<string, string>(header.Key, value)));
            return new ResponseSnapshot(url, (int)response.StatusCode, headers);
        }
        catch (TaskCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            throw new ScanException($"The request to {url} timed out after {_client.Timeout.TotalSeconds:0} seconds.", ex);
        }
        catch (HttpRequestException ex)
        {
            throw new ScanException($"The request to {url} failed: {ex.Message}", ex);
        }
    }
}
