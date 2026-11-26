using System.Net;
using HeaderCheck.Core;

namespace HeaderCheck.Tests;

public class ScannerTests
{
    /// <summary>Answers requests from a function instead of the network, and records them.</summary>
    private sealed class FakeHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public List<(Uri Url, string? Origin)> Requests { get; } = new();

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var origin = request.Headers.TryGetValues("Origin", out var values) ? values.Single() : null;
            Requests.Add((request.RequestUri!, origin));
            return Task.FromResult(respond(request));
        }
    }

    private static HttpResponseMessage Redirect(int status, string location)
    {
        var response = new HttpResponseMessage((HttpStatusCode)status);
        response.Headers.TryAddWithoutValidation("Location", location);
        return response;
    }

    [Fact]
    public async Task Follows_and_records_each_redirect_including_relative_ones()
    {
        var handler = new FakeHandler(request => request.RequestUri!.ToString() switch
        {
            "http://a.test/" => Redirect(301, "https://a.test/start"),
            "https://a.test/start" => Redirect(302, "/end"),
            _ => new HttpResponseMessage(HttpStatusCode.OK)
        });

        var context = await new Scanner(handler).ScanAsync(new Uri("http://a.test/"));

        Assert.Equal(2, context.Redirects.Count);
        Assert.Equal(new RedirectHop(new Uri("http://a.test/"), 301, new Uri("https://a.test/start")), context.Redirects[0]);
        Assert.Equal(new RedirectHop(new Uri("https://a.test/start"), 302, new Uri("https://a.test/end")), context.Redirects[1]);
        Assert.Equal(new Uri("https://a.test/end"), context.Final.Url);
        Assert.Equal(new Uri("http://a.test/"), context.Requested);
    }

    [Fact]
    public async Task Sends_the_cors_probe_last_and_only_to_the_final_url()
    {
        var handler = new FakeHandler(request => request.RequestUri!.AbsolutePath == "/"
            ? Redirect(301, "/home")
            : new HttpResponseMessage(HttpStatusCode.OK));

        var context = await new Scanner(handler).ScanAsync(new Uri("https://a.test/"));

        Assert.Equal(
            new (Uri, string?)[]
            {
                (new Uri("https://a.test/"), null),
                (new Uri("https://a.test/home"), null),
                (new Uri("https://a.test/home"), ScanContext.ProbeOrigin)
            },
            handler.Requests);
        Assert.NotNull(context.CorsProbe);
    }

    [Fact]
    public async Task Keeps_each_set_cookie_value_separately()
    {
        var handler = new FakeHandler(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK);
            response.Headers.TryAddWithoutValidation("Set-Cookie", "a=1; Secure");
            response.Headers.TryAddWithoutValidation("Set-Cookie", "b=2, with a comma; HttpOnly");
            response.Content = new StringContent("");
            response.Content.Headers.ContentType = new("text/html");
            return response;
        });

        var context = await new Scanner(handler).ScanAsync(new Uri("https://a.test/"));

        Assert.Equal(new[] { "a=1; Secure", "b=2, with a comma; HttpOnly" }, context.Final.GetAll("set-cookie"));
        Assert.StartsWith("text/html", context.Final.Get("Content-Type"));
    }

    [Fact]
    public async Task Stops_a_redirect_loop()
    {
        var handler = new FakeHandler(_ => Redirect(302, "https://a.test/"));
        var ex = await Assert.ThrowsAsync<ScanException>(() => new Scanner(handler, maxRedirects: 5).ScanAsync(new Uri("https://a.test/")));
        Assert.Contains("5 redirects", ex.Message);
        Assert.Equal(6, handler.Requests.Count);
    }

    [Fact]
    public async Task Refuses_a_redirect_to_a_non_http_scheme()
    {
        var handler = new FakeHandler(_ => Redirect(301, "ftp://a.test/file"));
        await Assert.ThrowsAsync<ScanException>(() => new Scanner(handler).ScanAsync(new Uri("https://a.test/")));
    }

    [Fact]
    public async Task A_network_failure_becomes_a_scan_exception()
    {
        var handler = new FakeHandler(_ => throw new HttpRequestException("no route"));
        var ex = await Assert.ThrowsAsync<ScanException>(() => new Scanner(handler).ScanAsync(new Uri("https://a.test/")));
        Assert.Contains("no route", ex.Message);
    }

    [Fact]
    public async Task A_failed_cors_probe_does_not_fail_the_scan()
    {
        var handler = new FakeHandler(request => request.Headers.Contains("Origin")
            ? throw new HttpRequestException("probe refused")
            : new HttpResponseMessage(HttpStatusCode.OK));

        var context = await new Scanner(handler).ScanAsync(new Uri("https://a.test/"));

        Assert.Null(context.CorsProbe);
        Assert.Equal(200, context.Final.StatusCode);
    }

    [Fact]
    public async Task A_redirect_without_location_is_treated_as_final()
    {
        var handler = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.Found));
        var context = await new Scanner(handler).ScanAsync(new Uri("https://a.test/"));
        Assert.Empty(context.Redirects);
        Assert.Equal(302, context.Final.StatusCode);
    }
}
