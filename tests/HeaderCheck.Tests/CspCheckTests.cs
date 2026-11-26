using HeaderCheck.Core;

namespace HeaderCheck.Tests;

public class CspCheckTests
{
    private const string Csp = "Content-Security-Policy";
    private const string ReportOnly = "Content-Security-Policy-Report-Only";

    /// <summary>Passes every rule. Tests below change one part of it.</summary>
    private const string Tail = "object-src 'none'; base-uri 'self'; frame-ancestors 'none'";

    private static readonly CspCheck Check = new();

    private static List<Finding> With(string policy) =>
        T.Run(Check, T.Final("https://a.test/", (Csp, policy)));

    [Fact]
    public void No_policy_at_all_is_high()
    {
        var findings = T.Run(Check, T.Final("https://a.test/"));
        T.Codes(findings, "csp.missing");
        Assert.Equal(Severity.High, findings[0].Severity);
    }

    [Fact]
    public void Report_only_enforces_nothing_and_stops_there()
    {
        var findings = T.Run(Check, T.Final("https://a.test/", (ReportOnly, "script-src 'unsafe-inline'")));
        T.Codes(findings, "csp.report-only");
        Assert.Equal(Severity.Medium, findings[0].Severity);
    }

    [Fact]
    public void Enforced_policy_is_checked_even_when_report_only_is_also_sent() =>
        T.Codes(T.Run(Check, T.Final("https://a.test/",
            (Csp, "default-src 'self'; " + Tail),
            (ReportOnly, "default-src 'none'"))));

    [Theory]
    [InlineData("default-src 'self'; " + Tail)]
    [InlineData("DEFAULT-SRC 'SELF'; OBJECT-SRC 'NONE'; BASE-URI 'self'; FRAME-ANCESTORS 'none'")]
    [InlineData("default-src 'self';; object-src 'none' ;  base-uri 'self'; frame-ancestors 'none';")]
    [InlineData("script-src 'self' 'nonce-r4nd0m' 'unsafe-inline'; " + Tail)]
    [InlineData("script-src 'self' 'sha256-abc123=' 'unsafe-inline'; " + Tail)]
    public void Strong_policies_pass(string policy) => T.Codes(With(policy));

    [Fact]
    public void First_copy_of_a_repeated_directive_wins() =>
        T.Codes(With("script-src 'self'; script-src 'unsafe-inline'; " + Tail));

    [Fact]
    public void No_script_or_default_src_leaves_scripts_open() =>
        T.Codes(With("img-src *; " + Tail), "csp.no-script-restriction");

    [Fact]
    public void Unsafe_inline_without_a_nonce_or_hash_is_high()
    {
        var findings = With("default-src 'self' 'unsafe-inline'; " + Tail);
        T.Codes(findings, "csp.unsafe-inline");
        Assert.Equal(Severity.High, findings[0].Severity);
    }

    [Fact]
    public void Unsafe_eval_is_medium()
    {
        var findings = With("script-src 'self' 'unsafe-eval'; " + Tail);
        T.Codes(findings, "csp.unsafe-eval");
        Assert.Equal(Severity.Medium, findings[0].Severity);
    }

    [Theory]
    [InlineData("*")]
    [InlineData("https:")]
    [InlineData("http:")]
    [InlineData("data:")]
    public void Wildcard_script_sources_are_high(string source) =>
        T.Codes(With($"script-src 'self' {source}; " + Tail), "csp.wildcard-scripts");

    [Fact]
    public void Script_src_overrides_default_src_but_object_src_falls_back_to_it() =>
        T.Codes(With("default-src *; script-src 'self'; base-uri 'self'; frame-ancestors 'none'"), "csp.object-src");

    [Fact]
    public void Only_script_src_misses_the_three_directives_with_no_fallback() =>
        T.Codes(With("script-src 'self'"), "csp.object-src", "csp.no-base-uri", "csp.no-frame-ancestors");

    [Fact]
    public void Severities_of_the_missing_directives()
    {
        var findings = With("script-src 'self'");
        Assert.Equal(Severity.Medium, T.One(findings, "csp.object-src").Severity);
        Assert.Equal(Severity.Medium, T.One(findings, "csp.no-base-uri").Severity);
        Assert.Equal(Severity.Low, T.One(findings, "csp.no-frame-ancestors").Severity);
    }
}
