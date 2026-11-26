namespace HeaderCheck.Core;

/// <summary>
/// YOURS TO WRITE. Looks at <see cref="ScanContext.Requested"/>, <see cref="ScanContext.Redirects"/>
/// (each hop: From, StatusCode, To) and <see cref="ScanContext.Final"/>.
/// Spec: tests/HeaderCheck.Tests/RedirectCheckTests.cs. Run: dotnet test --filter RedirectCheckTests
///
/// Rules (code, severity):
///   redirect.no-https          High    The final URL is HTTP.
///   redirect.downgrade         High    A hop goes from https to http. One finding per such hop.
///   redirect.temporary-upgrade Info    A hop goes from http to https on the same host with 302 or 307.
///                                      301 or 308 is better: browsers remember a permanent redirect.
///   redirect.long-chain        Low     More than 3 hops.
///   redirect.other-host        Info    The final host differs from the requested host, ignoring a
///                                      leading "www." and letter case.
///
/// Evidence for a hop = "From -> To". For long-chain, the hop count.
/// </summary>
public sealed class RedirectCheck : ICheck
{
    public string Id => "redirect";

    public string Name => "Redirects";

    public IEnumerable<Finding> Run(ScanContext context)
    {
        throw new NotImplementedException();
    }
}
