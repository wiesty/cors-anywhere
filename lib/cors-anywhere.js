// © 2013 - 2026 wiesty (Co-Author: Rob Wu <rob@robwu.nl>)
// Released under the MIT license

'use strict';

var httpProxy = require('http-proxy');
var net = require('net');
var url = require('url');
var getProxyForUrl = require('proxy-from-env').getProxyForUrl;

var help_text = {};
function showUsage(help_file, headers, response) {
  var isHtml = /\.html$/.test(help_file);
  headers['content-type'] = isHtml ? 'text/html' : 'text/plain';
  if (help_text[help_file] != null) {
    response.writeHead(200, headers);
    response.end(help_text[help_file]);
  } else {
    require('fs').readFile(help_file, 'utf8', function(err, data) {
      if (err) {
        console.error(err);
        response.writeHead(500, headers);
        response.end();
      } else {
        help_text[help_file] = data;
        showUsage(help_file, headers, response); // Recursive call, but since data is a string, the recursion will end
      }
    });
  }
}

/**
 * Check whether the specified hostname is valid.
 *
 * @param hostname {string} Host name (excluding port) of requested resource.
 * @return {boolean} Whether the requested resource can be accessed.
 */
function isValidHostName(hostname) {
  return !!(
    /\.[a-zA-Z]{2,63}$/.test(hostname) ||
    net.isIPv4(hostname) ||
    net.isIPv6(hostname)
  );
}

/**
 * Check whether the hostname refers to a private/internal network resource.
 * Used to prevent SSRF (Server-Side Request Forgery) attacks (CVE-2020-36851).
 *
 * Blocks RFC 1918 private ranges, loopback, link-local (including cloud metadata
 * endpoints like 169.254.169.254), and IPv6 equivalents.
 *
 * @param hostname {string} Host name (excluding port) of requested resource.
 * @return {boolean} true if the hostname resolves to a private/internal address.
 */
function isPrivateHostname(hostname) {
  // Block localhost by name
  if (/^localhost$/i.test(hostname)) { return true; }

  // Block IPv4 private/reserved ranges
  if (net.isIPv4(hostname)) {
    var parts = hostname.split('.').map(Number);
    return (
      parts[0] === 0 ||                                           // 0.0.0.0/8        (reserved)
      parts[0] === 10 ||                                          // 10.0.0.0/8       (RFC 1918)
      parts[0] === 127 ||                                         // 127.0.0.0/8      (loopback)
      (parts[0] === 169 && parts[1] === 254) ||                   // 169.254.0.0/16   (link-local / IMDS)
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||  // 172.16.0.0/12    (RFC 1918)
      (parts[0] === 192 && parts[1] === 168) ||                   // 192.168.0.0/16   (RFC 1918)
      (parts[0] === 198 && parts[1] === 18) ||                    // 198.18.0.0/15    (benchmarking)
      (parts[0] === 198 && parts[1] === 19) ||
      (parts[0] === 203 && parts[1] === 0 && parts[2] === 113) || // 203.0.113.0/24   (documentation)
      (parts[0] >= 224 && parts[0] <= 239) ||                     // 224.0.0.0/4      (multicast)
      parts[0] >= 240                                             // 240.0.0.0/4      (reserved)
    );
  }

  // Block IPv6 private/reserved ranges
  if (net.isIPv6(hostname)) {
    var addr = hostname.toLowerCase().replace(/^\[|\]$/g, '');
    // Expand :: for simple prefix checks
    if (
      addr === '::1' ||                                // Loopback
      addr === '::' ||                                 // Unspecified
      /^fe[89ab]/i.test(addr) ||                       // fe80::/10  link-local
      /^f[cd]/i.test(addr) ||                          // fc00::/7   unique local
      /^ff/i.test(addr)                                // ff00::/8   multicast
    ) { return true; }
  }

  return false;
}

/**
 * Check whether origin is in the whitelist.
 * Supports exact origin matches (e.g. "https://example.com") and plain hostname
 * entries that also allow subdomains (e.g. "example.com" matches
 * "https://api.example.com"). Fixes #474.
 *
 * @param origin {string} Value of the Origin request header.
 * @param whitelist {string[]} The configured originWhitelist.
 * @return {boolean} Whether the origin is allowed.
 */
function isOriginAllowed(origin, whitelist) {
  if (!whitelist.length) { return true; }
  // Exact match (e.g. full origin "https://example.com")
  if (whitelist.indexOf(origin) !== -1) { return true; }

  // Subdomain / hostname match for plain-hostname entries
  var parsedOrigin = url.parse(origin);
  var host = parsedOrigin && parsedOrigin.hostname;
  if (host) {
    for (var i = 0; i < whitelist.length; i++) {
      var entry = whitelist[i];
      // Only apply subdomain logic to entries without a protocol scheme
      if (!/^https?:\/\//i.test(entry)) {
        if (host === entry || host.slice(-(entry.length + 1)) === '.' + entry) {
          return true;
        }
      }
    }
  }
  return false;
}

/**
 * Adds CORS headers to the response headers.
 *
 * @param headers {object} Response headers
 * @param request {ServerRequest}
 */
function withCORS(headers, request) {
  headers['access-control-allow-origin'] = '*';
  var corsMaxAge = request.corsAnywhereRequestState.corsMaxAge;
  if (request.method === 'OPTIONS' && corsMaxAge) {
    headers['access-control-max-age'] = corsMaxAge;
  }
  if (request.headers['access-control-request-method']) {
    headers['access-control-allow-methods'] = request.headers['access-control-request-method'];
    delete request.headers['access-control-request-method'];
  }
  if (request.headers['access-control-request-headers']) {
    headers['access-control-allow-headers'] = request.headers['access-control-request-headers'];
    delete request.headers['access-control-request-headers'];
  }

  headers['access-control-expose-headers'] = Object.keys(headers).join(',');

  return headers;
}

/**
 * Performs the actual proxy request.
 *
 * @param req {ServerRequest} Incoming http request
 * @param res {ServerResponse} Outgoing (proxied) http request
 * @param proxy {HttpProxy}
 */
function proxyRequest(req, res, proxy) {
  var location = req.corsAnywhereRequestState.location;
  req.url = location.path;

  var proxyOptions = {
    changeOrigin: false,
    prependPath: false,
    target: location,
    headers: {
      host: location.host,
    },
    // HACK: Get hold of the proxyReq object, because we need it later.
    // https://github.com/nodejitsu/node-http-proxy/blob/v1.11.1/lib/http-proxy/passes/web-incoming.js#L144
    buffer: {
      pipe: function(proxyReq) {
        var proxyReqOn = proxyReq.on;
        // Intercepts the handler that connects proxyRes to res.
        // https://github.com/nodejitsu/node-http-proxy/blob/v1.11.1/lib/http-proxy/passes/web-incoming.js#L146-L158
        proxyReq.on = function(eventName, listener) {
          if (eventName !== 'response') {
            return proxyReqOn.call(this, eventName, listener);
          }
          return proxyReqOn.call(this, 'response', function(proxyRes) {
            if (onProxyResponse(proxy, proxyReq, proxyRes, req, res)) {
              try {
                listener(proxyRes);
              } catch (err) {
                // Wrap in try-catch because an error could occur:
                // "RangeError: Invalid status code: 0"
                // https://github.com/Rob--W/cors-anywhere/issues/95
                // https://github.com/nodejitsu/node-http-proxy/issues/1080

                // Forward error (will ultimately emit the 'error' event on our proxy object):
                // https://github.com/nodejitsu/node-http-proxy/blob/v1.11.1/lib/http-proxy/passes/web-incoming.js#L134
                proxyReq.emit('error', err);
              }
            }
          });
        };
        return req.pipe(proxyReq);
      },
    },
  };

  var proxyThroughUrl = req.corsAnywhereRequestState.getProxyForUrl(location.href);
  if (proxyThroughUrl) {
    proxyOptions.target = proxyThroughUrl;
    proxyOptions.toProxy = true;
    // If a proxy URL was set, req.url must be an absolute URL. Then the request will not be sent
    // directly to the proxied URL, but through another proxy.
    req.url = location.href;
  }

  // Start proxying the request
  try {
    proxy.web(req, res, proxyOptions);
  } catch (err) {
    proxy.emit('error', err, req, res);
  }
}

/**
 * This method modifies the response headers of the proxied response.
 * If a redirect is detected, the response is not sent to the client,
 * and a new request is initiated.
 *
 * client (req) -> CORS Anywhere -> (proxyReq) -> other server
 * client (res) <- CORS Anywhere <- (proxyRes) <- other server
 *
 * @param proxy {HttpProxy}
 * @param proxyReq {ClientRequest} The outgoing request to the other server.
 * @param proxyRes {ServerResponse} The response from the other server.
 * @param req {IncomingMessage} Incoming HTTP request, augmented with property corsAnywhereRequestState
 * @param req.corsAnywhereRequestState {object}
 * @param req.corsAnywhereRequestState.location {object} See parseURL
 * @param req.corsAnywhereRequestState.getProxyForUrl {function} See proxyRequest
 * @param req.corsAnywhereRequestState.proxyBaseUrl {string} Base URL of the CORS API endpoint
 * @param req.corsAnywhereRequestState.maxRedirects {number} Maximum number of redirects
 * @param req.corsAnywhereRequestState.redirectCount_ {number} Internally used to count redirects
 * @param res {ServerResponse} Outgoing response to the client that wanted to proxy the HTTP request.
 *
 * @returns {boolean} true if http-proxy should continue to pipe proxyRes to res.
 */
function onProxyResponse(proxy, proxyReq, proxyRes, req, res) {
  var requestState = req.corsAnywhereRequestState;

  var statusCode = proxyRes.statusCode;

  if (!requestState.redirectCount_) {
    res.setHeader('x-request-url', requestState.location.href);
  }
  // Handle redirects
  if (statusCode === 301 || statusCode === 302 || statusCode === 303 || statusCode === 307 || statusCode === 308) {
    var locationHeader = proxyRes.headers.location;
    var parsedLocation;
    if (locationHeader) {
      locationHeader = url.resolve(requestState.location.href, locationHeader);
      parsedLocation = parseURL(locationHeader);
    }
    if (parsedLocation) {
      if (statusCode === 301 || statusCode === 302 || statusCode === 303) {
        // Exclude 307 & 308, because they are rare, and require preserving the method + request body
        requestState.redirectCount_ = requestState.redirectCount_ + 1 || 1;
        if (requestState.redirectCount_ <= requestState.maxRedirects) {
          // Handle redirects within the server, because some clients (e.g. Android Stock Browser)
          // cancel redirects.
          // Set header for debugging purposes. Do not try to parse it!
          res.setHeader('X-CORS-Redirect-' + requestState.redirectCount_, statusCode + ' ' + locationHeader);

          req.method = 'GET';
          req.headers['content-length'] = '0';
          delete req.headers['content-type'];
          requestState.location = parsedLocation;

          // Remove all listeners (=reset events to initial state)
          req.removeAllListeners();

          // Remove the error listener so that the ECONNRESET "error" that
          // may occur after aborting a request does not propagate to res.
          // https://github.com/nodejitsu/node-http-proxy/blob/v1.11.1/lib/http-proxy/passes/web-incoming.js#L134
          proxyReq.removeAllListeners('error');
          proxyReq.once('error', function catchAndIgnoreError() {});
          proxyReq.abort();

          // Initiate a new proxy request.
          proxyRequest(req, res, proxy);
          return false;
        }
      }
      proxyRes.headers.location = requestState.proxyBaseUrl + '/' + locationHeader;
    }
  }

  // Strip cookies
  delete proxyRes.headers['set-cookie'];
  delete proxyRes.headers['set-cookie2'];

  proxyRes.headers['x-final-url'] = requestState.location.href;
  withCORS(proxyRes.headers, req);
  return true;
}


/**
 * @param req_url {string} The requested URL (scheme is optional).
 * @return {object} URL parsed using url.parse
 */
function parseURL(req_url) {
  var match = req_url.match(/^(?:(https?:)?\/\/)?(([^\/?]+?)(?::(\d{0,5})(?=[\/?]|$))?)([\/?][\S\s]*|$)/i);
  //                              ^^^^^^^          ^^^^^^^^      ^^^^^^^                ^^^^^^^^^^^^
  //                            1:protocol       3:hostname     4:port                 5:path + query string
  //                                              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  //                                            2:host
  if (!match) {
    return null;
  }
  if (!match[1]) {
    if (/^https?:/i.test(req_url)) {
      // The pattern at top could mistakenly parse "http:///" as host="http:" and path=///.
      return null;
    }
    // Scheme is omitted.
    if (req_url.lastIndexOf('//', 0) === -1) {
      // "//" is omitted.
      req_url = '//' + req_url;
    }
    req_url = (match[4] === '443' ? 'https:' : 'http:') + req_url;
  }
  var parsed = url.parse(req_url);
  if (!parsed.hostname) {
    // "http://:1/" and "http:/notenoughslashes" could end up here.
    return null;
  }
  return parsed;
}

// Request handler factory
function getHandler(options, proxy) {
  var corsAnywhere = {
    handleInitialRequest: null,     // Function that may handle the request instead, by returning a truthy value.
    getProxyForUrl: getProxyForUrl, // Function that specifies the proxy to use
    maxRedirects: 5,                // Maximum number of redirects to be followed.
    originBlacklist: [],            // Requests from these origins will be blocked.
    originWhitelist: [],            // If non-empty, requests not from an origin in this list will be blocked.
    checkRateLimit: null,           // Function that may enforce a rate-limit by returning a non-empty string.
    redirectSameOrigin: false,      // Redirect the client to the requested URL for same-origin requests.
    requireHeader: null,            // Require a header to be set?
    removeHeaders: [],              // Strip these request headers.
    setHeaders: {},                 // Set these request headers.
    corsMaxAge: 0,                  // If set, an Access-Control-Max-Age header with this value (in seconds) will be added.
    helpFile: __dirname + '/help.txt',
    targetBlacklist: [],            // If non-empty, requests targeting these URLs/patterns will be blocked.
    allowPrivateIPs: false,         // If false (default), requests to private/internal IPs are blocked (SSRF protection).
  };

  Object.keys(corsAnywhere).forEach(function(option) {
    if (Object.prototype.hasOwnProperty.call(options, option)) {
      corsAnywhere[option] = options[option];
    }
  });

  // Convert corsAnywhere.requireHeader to an array of lowercase header names, or null.
  if (corsAnywhere.requireHeader) {
    if (typeof corsAnywhere.requireHeader === 'string') {
      corsAnywhere.requireHeader = [corsAnywhere.requireHeader.toLowerCase()];
    } else if (!Array.isArray(corsAnywhere.requireHeader) || corsAnywhere.requireHeader.length === 0) {
      corsAnywhere.requireHeader = null;
    } else {
      corsAnywhere.requireHeader = corsAnywhere.requireHeader.map(function(headerName) {
        return headerName.toLowerCase();
      });
    }
  }
  var hasRequiredHeaders = function(headers) {
    return !corsAnywhere.requireHeader || corsAnywhere.requireHeader.some(function(headerName) {
      return Object.prototype.hasOwnProperty.call(headers, headerName);
    });
  };

  return function(req, res) {
    // Catch-all to prevent uncaught exceptions from crashing the server (#522)
    try {
      req.corsAnywhereRequestState = {
        getProxyForUrl: corsAnywhere.getProxyForUrl,
        maxRedirects: corsAnywhere.maxRedirects,
        corsMaxAge: corsAnywhere.corsMaxAge,
      };

      var cors_headers = withCORS({}, req);
      if (req.method === 'OPTIONS') {
        // Pre-flight request. Reply successfully:
        res.writeHead(200, cors_headers);
        res.end();
        return;
      }

      var location = parseURL(req.url.slice(1));

      if (corsAnywhere.handleInitialRequest && corsAnywhere.handleInitialRequest(req, res, location)) {
        return;
      }

      if (!location) {
        // Special case http:/notenoughslashes, because new users of the library frequently make the
        // mistake of putting this application behind a server/router that normalizes the URL.
        // See https://github.com/Rob--W/cors-anywhere/issues/238#issuecomment-629638853
        if (/^\/https?:\/[^/]/i.test(req.url)) {
          res.writeHead(400, 'Missing slash', cors_headers);
          res.end('The URL is invalid: two slashes are needed after the http(s):.');
          return;
        }
        // Invalid API call. Show how to correctly use the API
        showUsage(corsAnywhere.helpFile, cors_headers, res);
        return;
      }

      if (location.host === 'iscorsneeded') {
        // Is CORS needed? This path is provided so that API consumers can test whether it's necessary
        // to use CORS. The server's reply is always No, because if they can read it, then CORS headers
        // are not necessary.
        res.writeHead(200, {'Content-Type': 'text/plain'});
        res.end('no');
        return;
      }

      if (location.port > 65535) {
        // Port is higher than 65535
        res.writeHead(400, 'Invalid port', cors_headers);
        res.end('Port number too large: ' + location.port);
        return;
      }

      if (!/^\/https?:/.test(req.url) && !isValidHostName(location.hostname)) {
        // Don't even try to proxy invalid hosts (such as /favicon.ico, /robots.txt)
        res.writeHead(404, 'Invalid host', cors_headers);
        res.end('Invalid host: ' + location.hostname);
        return;
      }

      // SSRF protection: block requests to private/internal network addresses (#521 / CVE-2020-36851)
      if (!corsAnywhere.allowPrivateIPs && isPrivateHostname(location.hostname)) {
        res.writeHead(403, 'Forbidden', cors_headers);
        res.end('Request to private/internal network address "' + location.hostname + '" is not allowed.');
        return;
      }

      if (!hasRequiredHeaders(req.headers)) {
        res.writeHead(400, 'Header required', cors_headers);
        res.end('Missing required request header. Must specify one of: ' + corsAnywhere.requireHeader);
        return;
      }

      var origin = req.headers.origin || '';
      if (corsAnywhere.originBlacklist.indexOf(origin) >= 0) {
        res.writeHead(403, 'Forbidden', cors_headers);
        res.end('The origin "' + origin + '" was blacklisted by the operator of this proxy.');
        return;
      }

      // Use isOriginAllowed for subdomain-aware whitelist matching (#474)
      if (!isOriginAllowed(origin, corsAnywhere.originWhitelist)) {
        res.writeHead(403, 'Forbidden', cors_headers);
        res.end('The origin "' + origin + '" was not whitelisted by the operator of this proxy.');
        return;
      }

      var rateLimitMessage = corsAnywhere.checkRateLimit && corsAnywhere.checkRateLimit(origin);
      if (rateLimitMessage) {
        res.writeHead(429, 'Too Many Requests', cors_headers);
        res.end('The origin "' + origin + '" has sent too many requests.\n' + rateLimitMessage);
        return;
      }

      if (corsAnywhere.redirectSameOrigin && origin && location.href[origin.length] === '/' &&
          location.href.lastIndexOf(origin, 0) === 0) {
        // Send a permanent redirect to offload the server. Badly coded clients should not waste our resources.
        cors_headers.vary = 'origin';
        cors_headers['cache-control'] = 'private';
        cors_headers.location = location.href;
        res.writeHead(301, 'Please use a direct request', cors_headers);
        res.end();
        return;
      }

      // Target URL blacklist (#455): block requests to specific destination URLs
      if (corsAnywhere.targetBlacklist.length) {
        var targetHref = location.href;
        var isTargetBlocked = corsAnywhere.targetBlacklist.some(function(blocked) {
          if (blocked instanceof RegExp) { return blocked.test(targetHref); }
          return targetHref.indexOf(blocked) !== -1;
        });
        if (isTargetBlocked) {
          res.writeHead(403, 'Forbidden', cors_headers);
          res.end('The target URL "' + targetHref + '" was blacklisted by the operator of this proxy.');
          return;
        }
      }

      var isRequestedOverHttps = req.connection.encrypted || /^\s*https/.test(req.headers['x-forwarded-proto']);
      var proxyBaseUrl = (isRequestedOverHttps ? 'https://' : 'http://') + req.headers.host;

      corsAnywhere.removeHeaders.forEach(function(header) {
        delete req.headers[header];
      });

      Object.keys(corsAnywhere.setHeaders).forEach(function(header) {
        req.headers[header] = corsAnywhere.setHeaders[header];
      });

      req.corsAnywhereRequestState.location = location;
      req.corsAnywhereRequestState.proxyBaseUrl = proxyBaseUrl;

      proxyRequest(req, res, proxy);
    } catch (err) {
      // Prevent any unexpected exception from crashing the server (#522)
      console.error('Unexpected error handling request:', err);
      try {
        if (!res.headersSent) {
          res.writeHead(500, {'Access-Control-Allow-Origin': '*'});
          res.end('Internal proxy error.');
        }
      } catch (writeErr) {
        // Ignore errors when trying to send the error response
      }
    }
  };
}

// Create server with default and given values
// Creator still needs to call .listen()
exports.createServer = function createServer(options) {
  options = options || {};

  // Default options:
  var httpProxyOptions = {
    xfwd: true,            // Append X-Forwarded-* headers
    secure: process.env.NODE_TLS_REJECT_UNAUTHORIZED !== '0',
  };
  // Allow user to override defaults and add own options
  if (options.httpProxyOptions) {
    Object.keys(options.httpProxyOptions).forEach(function(option) {
      httpProxyOptions[option] = options.httpProxyOptions[option];
    });
  }

  var proxy = httpProxy.createServer(httpProxyOptions);
  var requestHandler = getHandler(options, proxy);
  var server;
  if (options.httpsOptions) {
    server = require('https').createServer(options.httpsOptions, requestHandler);
  } else {
    server = require('http').createServer(requestHandler);
  }

  // When the server fails, just show a 404 instead of Internal server error
  proxy.on('error', function(err, req, res) {
    if (res.headersSent) {
      // This could happen when a protocol error occurs when an error occurs
      // after the headers have been received (and forwarded). Do not write
      // the headers because it would generate an error.
      // Prior to Node 13.x, the stream would have ended.
      // As of Node 13.x, we must explicitly close it.
      if (res.writableEnded === false) {
        res.end();
      }
      return;
    }

    // When the error occurs after setting headers but before writing the response,
    // then any previously set headers must be removed.
    var headerNames = res.getHeaderNames ? res.getHeaderNames() : Object.keys(res._headers || {});
    headerNames.forEach(function(name) {
      res.removeHeader(name);
    });

    // Provide a helpful message for AggregateError (Node.js 15+, #482)
    var errorMessage;
    if (err && err.name === 'AggregateError' && Array.isArray(err.errors) && err.errors.length) {
      errorMessage = 'Not found because of proxy error: ' +
        err.errors.map(function(e) { return e.message || String(e); }).join(', ');
    } else {
      errorMessage = 'Not found because of proxy error: ' + err;
    }

    res.writeHead(404, {'Access-Control-Allow-Origin': '*'});
    res.end(errorMessage);
  });

  return server;
};
