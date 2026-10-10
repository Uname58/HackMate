# Stored XSS — Skill

## Definition
Stored XSS (persistent XSS) occurs when attacker-controlled input is saved by the application — in a database, file, cache, log, message queue, search index, or other persistent storage — and later rendered into an HTML, JavaScript, CSS, URL, or document context without sufficient output encoding or sanitization. The script then executes in the browser of any user who views the affected page, with the privileges and origin of the vulnerable application.

## Root Cause
- Missing or incorrect output encoding at render time.
- Context mismatch: data encoded for one context is later used in another.
- Trusting stored data as safe because it was validated or sanitized on input.
- Applying sanitization only before storage, only after retrieval, or not at all.
- Use of dangerous sinks: `innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout(string)`, `dangerouslySetInnerHTML`, `v-html`, `|safe`, `noescape`.
- Rich text, Markdown, WYSIWYG, or template parsers that allow unsafe tags, attributes, or protocols.
- Second-order XSS: input is stored in one component and rendered in another, often an admin panel, email, PDF, or export.

## Where Stored XSS Occurs
Common sources and storage locations include:
- Comments, posts, reviews, forums, wikis, issue trackers.
- User profiles: display name, bio, location, avatar URL, custom fields, signatures.
- Private messages, chat, support tickets, feedback forms, contact requests.
- File uploads: filenames, metadata, EXIF, SVG, HTML, PDF, CSV, office documents.
- Logs, audit trails, error messages, email templates, notifications, webhooks.
- E-commerce: product names, descriptions, addresses, order notes, gift messages.
- CMS: pages, templates, widgets, menus, settings, user roles.
- APIs and GraphQL: stored JSON, integrations, third-party data, imported content.
- Search queries, search history, redirects, 404 pages, canonical URLs.
- Admin dashboards, moderation queues, analytics, reporting views.
- HTTP headers stored in logs and viewed in admin UIs: `User-Agent`, `Referer`, `X-Forwarded-For`, `X-Real-IP`.
- Storage backends: SQL, NoSQL, Redis, Memcached, S3, local files, message queues, Elasticsearch, email, PDFs.

## Sinks and Execution Contexts
- HTML body: most common, e.g., between `<div>` and `</div>`.
- HTML attribute: value attributes, event handlers, `style`, URL attributes (`href`, `src`, `action`, `formaction`, `data-*`, `srcdoc`).
- JavaScript: between `<script>` tags, inside JS strings, inside JSON embedded in scripts, inside event handler attributes.
- URL contexts: `href`, `src`, `action`, `ping`, `formaction`, `srcdoc`, CSS `url()`.
- CSS contexts: `style` attribute, `<style>` blocks, CSS variables.
- JSON/XML responses parsed and rendered by client-side code.
- SVG and MathML: script execution and event handlers.
- Markdown and rich text: parser and sanitizer bypasses.
- Template engines: server-side and client-side rendering with unescaped interpolation.

## Impact
- Session hijacking and account takeover.
- CSRF protection bypass.
- Keylogging, phishing, defacement, and arbitrary UI manipulation.
- Theft of sensitive data: tokens, PII, internal documents.
- Internal network scanning and pivoting from the victim's browser.
- Wormable propagation through stored user content.
- Privilege escalation, especially when administrators view stored content.
- Persistent backdoor or staged payloads in the application.
- Reputation damage, legal exposure, and loss of user trust.

## Testing Workflow
1. Map all input points: forms, API endpoints, GraphQL, WebSockets, headers, file uploads, imports, third-party integrations.
2. Identify where each input is stored and how it is later retrieved.
3. Submit a unique canary, such as `xss12345` or a benign tag with a unique attribute. Use different canaries per field.
4. Locate all render locations: user views, admin views, public pages, API responses, emails, PDFs, exports, notifications.
5. Determine the exact output context around the canary: HTML body, attribute, JS string, URL, CSS, JSON, SVG, template.
6. Test with a context-appropriate proof-of-concept. Start with harmless execution proof such as `alert(1)` or a DOM change. Avoid destructive payloads.
7. Verify persistence: refresh, re-login, use another browser or account, and wait for asynchronous rendering.
8. Test blind XSS: inject a canary that calls back to an authorized listener for admin-only or delayed views.
9. Assess encoding and sanitization: try encoded variants, case variations, alternate tags and events.
10. Evaluate mitigations: CSP, HttpOnly, SameSite, Trusted Types, WAF, sanitizer behavior.
11. Document the exact input, storage location, render point, context, payload, execution proof, and impact.

## Payload and Bypass Techniques
Use only in authorized testing and prefer harmless proof-of-concept payloads.

- HTML body:
  - `<script>alert(1)</script>`
  - `<img src=x onerror=alert(1)>`
  - `<svg onload=alert(1)>`
  - `<details open ontoggle=alert(1)>`
  - `<video><source onerror=alert(1)>`
  - `<iframe srcdoc="<script>alert(1)</script>">`
- Attribute value:
  - Break out with `"` or `'`, then add an event handler.
  - `" autofocus onfocus=alert(1) x="`
  - `' onmouseover=alert(1) x='`
- URL attributes:
  - `javascript:alert(1)`
  - `data:text/html,<script>alert(1)</script>`
  - `vbscript:msgbox(1)`
- JavaScript string:
  - `';alert(1)//`
  - `\';alert(1)//`
  - `</script><script>alert(1)</script>`
  - `${alert(1)}` inside template literals
- JavaScript context inside script:
  - `</script><script>alert(1)</script>`
  - `\u003c/script\u003e...`
  - `\x3c/script\x3e...`
- CSS:
  - `</style><script>alert(1)</script>`
  - Legacy `expression(alert(1))`
  - `background:url(javascript:alert(1))`
- JSON embedded in script:
  - `</script><script>alert(1)</script>`
  - `{"x":"</script><script>alert(1)</script>"}`
- Markdown:
  - `[x](javascript:alert(1))`
  - `<img src=x onerror=alert(1)>`
  - `<svg/onload=alert(1)>`
- SVG:
  - `<svg><script>alert(1)</script></svg>`
  - `<svg onload=alert(1)>`
- Encoding bypass:
  - HTML entities: `&#x3c;script&#x3e;`
  - URL encoding: `%3Cscript%3E`
  - Double encoding: `%253Cscript%253E`
  - Unicode escapes, hex escapes, JS escapes.
- Filter bypass:
  - Mixed case: `<ScRiPt>`
  - Null byte: `<scr\0ipt>`
  - Comments: `<scr<!-- -->ipt>`
  - Malformed tags: `<img src=x onerror=alert(1)//>`
  - Nested tags: `<scr<script>ipt>`
  - Alternate event handlers: `ontoggle`, `onpointerover`, `onanimationstart`, `onfocus`, `onblur`.
- CSP bypass:
  - JSONP endpoints.
  - AngularJS sandbox escapes.
  - `base-uri` injection.
  - Script gadgets.
  - Nonce reuse.
  - Dangling markup.
  - `strict-dynamic` bypass.
- WAF bypass:
  - Parameter pollution.
  - Content-type confusion.
  - Chunked transfer encoding.
  - Unicode normalization.
  - Multipart/form-data.
  - Header-based injection.
- Mutation XSS (mXSS):
  - Browser parser differences and namespace confusion.
  - `innerHTML` mutations that turn safe input into executable markup.
- DOM clobbering:
  - Named elements overriding global variables to influence client-side logic.

## Tools
- Burp Suite: Scanner, Repeater, Collaborator.
- OWASP ZAP.
- XSStrike, dalfox, XSSer.
- XSS Hunter or Burp Collaborator for blind XSS.
- Browser DevTools and DOM Invader.
- CSP Evaluator.
- Semgrep, CodeQL, or similar for static detection.
- DAST, IAST, and manual code review.

## Common Pitfalls and False Positives
- Payload is reflected but encoded and does not execute.
- Payload is stored but only rendered to the submitting user.
- CSP blocks inline script execution.
- HttpOnly cookies prevent direct session token theft.
- Sanitizer strips dangerous tags; test mutation XSS and parser differentials.
- Client-side framework escapes by default; check unsafe escape hatches.
- Data is stored in one context and rendered in another, causing second-order XSS.
- Blind XSS is not visible to the tester; use out-of-band detection.
- WAF blocks the payload; try encoding, alternate vectors, or different content types.
- Browser version and rendering engine may affect payload execution.

## Defense and Remediation
- Context-aware output encoding:
  - HTML entity encoding for HTML body.
  - Attribute encoding for HTML attributes.
  - JavaScript encoding for JS contexts.
  - URL encoding for URL contexts.
  - CSS encoding for CSS contexts.
  - Use framework auto-escaping whenever possible.
- Input validation:
  - Use allowlists for expected data.
  - Reject or escape dangerous characters where appropriate.
- Sanitization:
  - Use well-maintained libraries for rich text: DOMPurify, OWASP Java HTML Sanitizer, sanitize-html, Bleach.
  - Sanitize on output, not only on input.
  - Keep sanitizer libraries updated.
- Avoid dangerous sinks:
  - `innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout(string)`.
  - `dangerouslySetInnerHTML`, `v-html`, `|safe`, `noescape`.
  - Prefer `textContent`, `createElement`, `setAttribute`, and safe DOM APIs.
- Content Security Policy:
  - Strict CSP with nonces or hashes.
  - `default-src 'self'`
  - `script-src 'self' 'nonce-...'`
  - `object-src 'none'`
  - `base-uri 'self'`
  - `require-trusted-types-for 'script'`
- Trusted Types:
  - Enforce for DOM sinks to prevent string-based injection.
- Cookies:
  - `HttpOnly`, `Secure`, `SameSite=Strict` or `Lax`.
- Framework hardening:
  - React escapes by default; avoid unsafe raw HTML.
  - Angular sanitizes by default; review bypasses.
  - Vue `v-html` is dangerous; avoid or sanitize.
  - Template engines should autoescape by default.
- Subresource Integrity:
  - Use SRI for third-party scripts.
- Regular testing:
  - SAST, DAST, IAST, manual review, bug bounty, and secure code review.
- Defense in depth:
  - WAF, CSP reporting, monitoring, and anomaly detection.

## References
- OWASP Cross Site Scripting (XSS)
- OWASP XSS Prevention Cheat Sheet
- OWASP DOM XSS
- OWASP Content Security Policy Cheat Sheet
- PortSwigger Web Security Academy: Cross-site scripting