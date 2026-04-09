# CORS Anywhere

> Fork of [Rob--W/cors-anywhere](https://github.com/Rob--W/cors-anywhere), maintained by [wiesty](https://github.com/wiesty).  
> Includes security fixes, updated dependencies, Docker support, and additional features.

**CORS Anywhere** is a Node.js reverse proxy which adds CORS headers to the proxied request.

The URL to proxy is taken from the path, validated and proxied. The protocol part is optional and
defaults to `http`. If port 443 is specified, it defaults to `https`.

Cookies are stripped from requests. Requesting [user credentials](http://www.w3.org/TR/cors/#user-credentials) is disallowed.

## Docker

The easiest way to run this is via Docker:

```sh
docker run -p 8080:8080 ghcr.io/wiesty/cors-anywhere
```

Available environment variables:

| Variable | Default | Description |
|---|---|---|
| `HOST` | `0.0.0.0` | Host to listen on |
| `PORT` | `8080` | Port to listen on |
| `CORSANYWHERE_WHITELIST` | _(empty)_ | Comma-separated list of allowed origins |
| `CORSANYWHERE_BLACKLIST` | _(empty)_ | Comma-separated list of blocked origins |
| `CORSANYWHERE_RATELIMIT` | _(empty)_ | Rate-limit config (see below) |

## Usage

```sh
# npm
npx cors-anywhere

# or run directly
node server.js
```

Request examples:

* `http://localhost:8080/http://google.com/` - Proxies google.com with CORS headers
* `http://localhost:8080/google.com` - Same as above
* `http://localhost:8080/google.com:443` - Proxies `https://google.com/`
* `http://localhost:8080/` - Shows usage text (`lib/help.txt`)

## API

```javascript
var cors_proxy = require('cors-anywhere');
cors_proxy.createServer({
    originWhitelist: [],       // Allow all origins
    removeHeaders: ['cookie', 'cookie2'],
}).listen(8080, '0.0.0.0', function() {
    console.log('Running CORS Anywhere on port 8080');
});
```

### Options

| Option | Type | Description |
|---|---|---|
| `originWhitelist` | `string[]` | If non-empty, only these origins are allowed. Supports plain hostnames for subdomain matching (e.g. `"example.com"` also allows `api.example.com`). |
| `originBlacklist` | `string[]` | Requests from these origins are blocked. |
| `targetBlacklist` | `(string\|RegExp)[]` | Requests to these destination URLs/patterns are blocked. |
| `allowPrivateIPs` | `boolean` | Allow proxying to private/internal IPs. Default: `false` (SSRF protection). |
| `requireHeader` | `string[]` | Reject requests that don't include one of these headers. |
| `removeHeaders` | `string[]` | Strip these headers from the proxied request. |
| `setHeaders` | `object` | Set these headers on the proxied request. |
| `redirectSameOrigin` | `boolean` | Redirect same-origin requests instead of proxying. |
| `checkRateLimit` | `function` | Called with the request origin. Return a non-empty string to reject the request. |
| `corsMaxAge` | `number` | Value for `Access-Control-Max-Age` (seconds). |
| `helpFile` | `string` | Path to the help text file shown at `/`. |
| `getProxyForUrl` | `function` | Return an upstream proxy URL for a given target URL. |
| `httpProxyOptions` | `object` | Options passed directly to [http-proxy](https://github.com/nodejitsu/node-http-proxy#options). |
| `httpsOptions` | `object` | If set, starts an HTTPS server using these options. |

### Rate limiting

Set via `CORSANYWHERE_RATELIMIT` environment variable or `checkRateLimit` option.

Format: `<max_requests> <period_in_minutes> [whitelisted_origin ...]`

```sh
# 50 requests per 3 minutes; my.example.com is unlimited
export CORSANYWHERE_RATELIMIT='50 3 my.example.com my2.example.com'
node server.js
```

### Whitelist / Blacklist (env)

```sh
export CORSANYWHERE_WHITELIST=https://example.com,http://example.com
export CORSANYWHERE_BLACKLIST=https://abuse.example.com,http://abuse.example.com
node server.js
```

## Changes vs upstream

* **SSRF protection** (CVE-2020-36851) — requests to private/internal IPs are blocked by default
* **Subdomain whitelist** — plain hostname entries in `originWhitelist` also match subdomains
* **Target blacklist** — new `targetBlacklist` option to block specific destination URLs
* **AggregateError handling** — proper error messages for Node.js 15+ DNS failures
* **Crash prevention** — uncaught exceptions no longer bring down the server
* **Docker** — multi-platform image (`linux/amd64`, `linux/arm64`) on GitHub Container Registry
* **npx support** — run directly with `npx cors-anywhere`
* **Updated deps** — all dependencies updated to latest versions

## License

Copyright (C) 2013 - 2026 wiesty (Co-Author: Rob Wu <rob@robwu.nl>)

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
