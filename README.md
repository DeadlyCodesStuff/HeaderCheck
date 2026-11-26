# HeaderCheck

HeaderCheck is a small .NET console tool that audits the security headers a website sends back. You give it a URL and it follows the redirects itself, recording every hop. It then reads the headers on the page you land on and checks whether the important ones are there, and whether their values actually protect anything. At the end you get a list of findings, each with a severity and a plain explanation, plus a grade from A to F.

It's deliberately simple: no crawling, no setup, no accounts. It's a quick way to sanity-check a site, gate a build, or learn what a particular header is actually for.

## What it checks

### Five checks that read the values

| Check | What it looks at |
| --- | --- |
| Redirects | Whether the site ends up on HTTPS, whether any hop drops from HTTPS back to HTTP, whether the upgrade uses a temporary redirect (302/307) instead of a permanent one, long chains, and landing on a different host. |
| Strict-Transport-Security | Parses the header: a missing or unusable `max-age`, `max-age=0`, a policy under a year, missing `includeSubDomains`, and `preload` on a policy that can't qualify for the preload list. |
| Content-Security-Policy | Parses the enforced policy: no script restriction, `'unsafe-inline'` without a nonce or hash, `'unsafe-eval'`, wildcard script sources (`*`, `https:`, `data:`), plugins not blocked, and missing `base-uri` and `frame-ancestors`. Report-only policies are flagged, because they block nothing. |
| Cookies | Every `Set-Cookie`: missing `Secure`, `HttpOnly` or `SameSite`, `SameSite=None` without `Secure`, and broken `__Secure-` / `__Host-` prefix rules. Findings name the cookie but never show its value. |
| CORS | Sends a second request from a made-up origin. If the server lets that origin read the response, by reflecting it, trusting `null` or using `*`, it trusts every site. It's worse when credentials are allowed too. |

### Ten headers checked for presence

| Header | What it does | Missing costs |
| --- | --- | --- |
| `Content-Security-Policy` | Controls which scripts, styles, frames, and other resources the browser may load. | (covered by its check) |
| `Strict-Transport-Security` | Tells the browser to stick to HTTPS for future requests to the site. | (covered by its check) |
| `X-Content-Type-Options` | Stops browsers from guessing a file's type and treating it as something executable. | Medium |
| `X-Frame-Options` | Decides whether the page can be embedded in a frame, which helps with clickjacking. | Low |
| `X-XSS-Protection` | The old built-in XSS filter switch. Obsolete, but still commonly checked. | nothing |
| `Referrer-Policy` | Limits how much of the current URL is sent to other sites in the `Referer` header. | Low |
| `Permissions-Policy` | Turns browser features like the camera, microphone, and geolocation on or off. | Low |
| `Cross-Origin-Opener-Policy` | Keeps other origins from holding a reference to the page's window. | Info |
| `Cross-Origin-Resource-Policy` | Says who is allowed to embed the site's resources on their own pages. | Info |
| `Cross-Origin-Embedder-Policy` | Requires cross-origin resources to opt in before the page can use them. | Info |

### Grading

Every site starts at 100. Each High finding costs 25 points, Medium 10, Low 3 and Info 0. The grade is A at 90 or more, then B at 80, C at 70, D at 60, and F below that. A single High finding drops a site to 75, so a serious hole can never earn an A or a B.

## Requirements

You'll need the [.NET 10 SDK](https://dotnet.microsoft.com/download) or newer.

## Running it

Clone the repo and start it with `dotnet run`:

```bash
git clone https://github.com/DeadlyCodesStuff/HeaderCheck.git
cd HeaderCheck
dotnet run --project src/HeaderCheck
```

Then type a URL when prompted. You can enter `example.com` instead of a full URL; it assumes HTTPS if you leave the scheme off. After the report you get a menu of the missing headers. Pick a number to read about one, or press Enter or type `q` to exit.

Or pass the URL and options directly, which skips the prompt and the menu:

```bash
dotnet run --project src/HeaderCheck -- example.com --json report.json --html report.html --fail-on high
```

| Option | What it does |
| --- | --- |
| `--json <path>` | Also writes the report as JSON. |
| `--html <path>` | Also writes the report as a standalone HTML page you can open or share. |
| `--fail-on <level>` | Exits with code 1 when a finding is at least `low`, `medium` or `high`, so it can gate a CI build. |
| `--no-menu` | Skips the missing-header menu. |
| `-h`, `--help` | Shows every option. |

Exit codes are `0` when the scan finished, `1` when a finding met `--fail-on`, and `2` for an error, such as a bad URL, a timeout or an unreadable `data.json`.

## What the output looks like

A scan of github.com:

```text
$ dotnet run --project src/HeaderCheck -- github.com --no-menu

  Summary
  Requested : https://github.com/
  Final     : https://github.com/
  Status    : 200

  Findings
  LOW     Cookie is readable by JavaScript
          _octo
          Without HttpOnly, any script on the page can read this cookie through document.cookie,
          so a single XSS bug can steal it. Add HttpOnly unless your own scripts need to read it.
  LOW     Permissions-Policy is missing
          Recommended: camera=(), microphone=(), geolocation=(), payment=()
  INFO    Cross-Origin-Embedder-Policy is missing
          Recommended: require-corp
  ...

  Headers
  Content-Security-Policy       ✔ present
  Strict-Transport-Security     ✔ present
  ...
  Permissions-Policy            ✘ missing

  Grade     : A  (94/100)
```

When the site redirects, a **Redirects** section lists each hop with its status code. If a check crashes on an unusual response, the report says so under **Checks that did not run**, and notes that the grade isn't the full picture.

In the interactive menu, picking a missing header shows what it does, the recommended value, a reference link, and the vulnerabilities it helps with:

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

  Related vulnerabilities

  1. SSL stripping / man-in-the-middle
       An attacker on the network rewrites HTTPS links to HTTP and relays
       traffic, capturing credentials and session cookies in clear text.
       https://owasp.org/www-community/attacks/Manipulator-in-the-middle_attack
  ...
```

## Project layout

| Path | What it holds |
| --- | --- |
| `src/HeaderCheck.Core` | The scanner, the five checks, scoring, and the JSON and HTML reports. No console code. |
| `src/HeaderCheck.Core/Checks` | One file per check. |
| `src/HeaderCheck` | The console app and `data.json`. |
| `tests/HeaderCheck.Tests` | xUnit tests: one file per check, plus the scanner, scoring and analyzer. |

The scanner does all the network work up front and hands the checks a snapshot: the requested URL, every redirect hop, the final response and the CORS probe. The checks never touch the network, so each one can be tested with hand-written responses, with no real website involved.

## Running the tests

```bash
dotnet test
```

To run one check's tests while working on it:

```bash
dotnet test --filter CspCheckTests
```

## Where the header information lives

The header descriptions, recommended values, notes, and vulnerability links all live in [`src/HeaderCheck/data.json`](src/HeaderCheck/data.json). `dotnet run` copies it next to the app on every build, so you can edit it and run again without touching any C#.

Each header looks roughly like this:

```json
{
  "name": "X-Content-Type-Options",
  "description": "Disables MIME sniffing. Browsers must trust the declared Content-Type instead of guessing what a file is.",
  "recommendedValue": "nosniff",
  "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
  "missingSeverity": "Medium",
  "notes": [
    "Only helps when the server sends an accurate Content-Type; a wrong type is still honoured."
  ],
  "vulnerabilities": [
    {
      "name": "MIME confusion / content sniffing",
      "description": "A browser reinterprets a file as a different type than declared, turning an image or text file into executable script.",
      "link": "https://owasp.org/www-community/attacks/Content_Spoofing"
    }
  ]
}
```

`missingSeverity` sets the finding when the header is absent: `High`, `Medium`, `Low`, `Info`, or `null` for no finding. Use `null` for headers that a check already covers, such as CSP and HSTS.

To add a header, add another object to the `headers` array, keep the JSON valid, and run the app.

## A few things to keep in mind

- It makes two requests: the scan itself, and a second request with an `Origin` header for the CORS check. It doesn't crawl the site or try other paths.
- It follows up to 10 redirects and times out after 15 seconds.
- `X-XSS-Protection` is obsolete and modern browsers ignore it. The tool still lists it because people ask about it, but the recommended value is `0`, and the details explain why.
- A good grade doesn't mean a site is secure, and a finding doesn't always mean it's exploitable. Treat this as a starting point, not a full security audit.

## Contributing

If a link is wrong, a description could be clearer, or you want to add a header, open an issue or send a pull request. Most contributions only need an edit to `data.json`. Keep descriptions short, and point links at a reputable source such as MDN, OWASP, or the relevant spec. Changes to a check should come with a test.

## License

MIT. See [LICENSE](LICENSE).
