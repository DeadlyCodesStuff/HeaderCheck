# HeaderCheck

HeaderCheck is a small .NET console tool that looks at the security headers a website sends back. You give it a URL, it makes one request, and it prints a clean report showing what's there and what's missing. From there you can pick any missing header and read a short explanation of what it does, the value you'd normally want to see, the vulnerabilities it helps with, and where to read more.

It's deliberately simple: no crawling, no setup, no accounts. Just a quick way to sanity-check a site or learn what a particular header is actually for.

## What it checks

It looks for ten headers that come up in most security header recommendations:

| Header | What it does |
| --- | --- |
| `Content-Security-Policy` | Controls which scripts, styles, frames, and other resources the browser is allowed to load. |
| `Strict-Transport-Security` | Tells the browser to stick to HTTPS for future requests to the site. |
| `X-Content-Type-Options` | Stops browsers from guessing a file's type and potentially treating it as something executable. |
| `X-Frame-Options` | Decides whether the page can be embedded in a frame, which helps with clickjacking. |
| `X-XSS-Protection` | The old built-in XSS filter switch. It's obsolete now, but still commonly checked. |
| `Referrer-Policy` | Limits how much of the current URL gets sent to other sites in the `Referer` header. |
| `Permissions-Policy` | Turns browser features like the camera, microphone, and geolocation on or off. |
| `Cross-Origin-Opener-Policy` | Keeps other origins from holding a reference to the page's window. |
| `Cross-Origin-Resource-Policy` | Says who is allowed to embed the site's resources on their own pages. |
| `Cross-Origin-Embedder-Policy` | Requires cross-origin resources to opt in before the page can use them. |

## Requirements

You'll need the [.NET 10 SDK](https://dotnet.microsoft.com/download) or newer.

## Running it

Clone the repo and start it with `dotnet run`:

```bash
git clone <repo-url>
cd HeaderCheck
dotnet run
```

Then type a URL when prompted. You can enter `example.com` instead of a full URL; it assumes HTTPS if you leave the scheme off. Pressing Enter or typing `q` at the header menu exits.

## What the output looks like

```text
$ dotnet run
  ════════════════════════════════════════════════════════════════════════
  HeaderCheck  ·  HTTP Security Header Audit
  ════════════════════════════════════════════════════════════════════════

  Target URL: example.com

  Summary
  Target   : https://example.com/
  Status   : 200 OK
  Checked  : 10 security headers

  Header audit
   #  Header                        Status
  ──  ────────────────────────────  ──────────
   1  Content-Security-Policy       ✘ missing
   2  Strict-Transport-Security     ✘ missing
   3  X-Content-Type-Options        ✘ missing
   4  X-Frame-Options               ✘ missing
   5  X-XSS-Protection              ✘ missing
   6  Referrer-Policy               ✘ missing
   7  Permissions-Policy            ✘ missing
   8  Cross-Origin-Opener-Policy    ✘ missing
   9  Cross-Origin-Resource-Policy  ✘ missing
  10  Cross-Origin-Embedder-Policy  ✘ missing

  Score    : 0/10 (0%) - Critical
  Presence only: the strength of each value is not validated.

  Missing headers
  ───────────────
   1. Content-Security-Policy
   2. Strict-Transport-Security
   3. X-Content-Type-Options
   4. X-Frame-Options
   5. X-XSS-Protection
   6. Referrer-Policy
   7. Permissions-Policy
   8. Cross-Origin-Opener-Policy
   9. Cross-Origin-Resource-Policy
  10. Cross-Origin-Embedder-Policy

  Enter a number to learn more, or press Enter to exit.

  > 2
```

Pick a number and you get the details for that header:

```text
  ──────────────────────────────────────────────────────────────────────────
  Strict-Transport-Security
  ──────────────────────────────────────────────────────────────────────────

  What it does
    Instructs the browser to use HTTPS for every future request to this host
    for the lifetime given in max-age. This closes the window where a user
    types a bare hostname and the first request travels over plain HTTP.

  Recommended value
    max-age=63072000; includeSubDomains; preload

  Reference
    https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security

  Related vulnerabilities

  1. SSL stripping / man-in-the-middle
       An attacker on the network rewrites HTTPS links to HTTP and relays
       traffic, capturing credentials and session cookies in clear text.
       https://owasp.org/www-community/attacks/Manipulator-in-the-middle_attack

  ...

  Press Enter to return to the menu...
```

## Where the header information lives

The header descriptions, recommended values, notes, and vulnerability links all live in [`data.json`](data.json). The app loads that file on startup, so you can edit it and run again without touching any C#.

Each header looks roughly like this:

```json
{
  "name": "Strict-Transport-Security",
  "description": "Tells the browser to use HTTPS for future requests.",
  "recommendedValue": "max-age=63072000; includeSubDomains; preload",
  "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
  "notes": [
    "The header is ignored when the response was not served over HTTPS."
  ],
  "vulnerabilities": [
    {
      "name": "SSL stripping / man-in-the-middle",
      "description": "An attacker rewrites HTTPS links to HTTP and relays traffic.",
      "link": "https://owasp.org/www-community/attacks/Manipulator-in-the-middle_attack"
    }
  ]
}
```

To add a header, add another object to the `headers` array in `data.json`, keep the JSON valid, and run the app. That's the whole process.

## A few things to keep in mind

- It only checks whether a header is present, not whether the value is any good. A weak `Content-Security-Policy` still counts as present.
- It checks the one response it gets from the URL you enter. It doesn't crawl the site or try different paths.
- Redirects are followed, so the report describes the final response a browser would land on.
- `X-XSS-Protection` is obsolete and modern browsers ignore it. The tool still checks for it because people ask about it, but the recommended value is `0`, and the details explain why.
- A missing header doesn't automatically mean a site is vulnerable, and a present one doesn't mean it's safe. Treat this as a starting point, not a full security audit.

## Contributing

If a link is wrong, a description could be clearer, or you want to add another header, open an issue or send a pull request. Most contributions only need an edit to `data.json`. Try to keep descriptions short and point links at a reputable source like MDN, OWASP, or the relevant spec.

## License

MIT. See [LICENSE](LICENSE).
