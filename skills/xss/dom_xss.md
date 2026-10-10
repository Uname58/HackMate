# DOM XSS — Skill

## 1. Definition & Scope

DOM XSS (DOM-based cross-site scripting) is a client-side code-injection class where attacker-controlled data flows from a **source** to a dangerous **sink** entirely within the browser's DOM, executed by client-side JavaScript. The payload never needs to be reflected or stored by the server; the server response can be byte-identical for attacker and victim.

Core implications:

- The vulnerable code is JavaScript that reads from the DOM/BOM and writes to a dangerous API without proper handling.
- Server-side output encoding is irrelevant to the flaw; classic server-side escaping fixes do not address it.
- Response-diffing scanners and server-side WAFs are structurally blind: fragment data (`#...`) is never sent to the server.
- Detection requires dynamic runtime tracing or JavaScript-aware static analysis with data-flow reasoning.

**Classification / sibling variants:**

- **Pure client-side DOM XSS** — source and sink both client-side (e.g. `location.hash` → `innerHTML`).
- **Server-side (reflected) DOM XSS** — the server reflects/embeds input into the response (HTML attribute, inline JSON, text), and client-side JS later reads it from the DOM and passes it to a sink. Payload must traverse the server first; the exploit still happens client-side.
- **Stored DOM XSS** — tainted data is persisted (localStorage, IndexedDB, server storage fetched later, cache) and reaches a sink on a later visit/route.
- **mXSS (mutation XSS)** — sanitized markup mutates into executable markup when the browser re-parses it (see §8).
- **Scriptless variants** — dangling markup injection and CSS-based exfiltration when script execution is blocked.

## 2. Impact

Same as reflected/stored XSS at the origin where it executes:

- Session/token theft: non-HttpOnly cookies, `localStorage`/`sessionStorage`/`IndexedDB` bearer tokens, in-memory app secrets.
- Authenticated action execution / CSRF bypass: reading CSRF tokens from the DOM, issuing state-changing requests with the victim's session.
- Keylogging, form/credential harvesting, UI redressing, phishing overlays.
- Data exfiltration via `fetch`/`img`/`WebSocket` to attacker-controlled endpoints.
- Worm propagation in SPAs and hybrid apps (self-replicating via hash links, postMessage, or stored fragments).
- Bypass of network-perimeter assumptions: scripts executing inside an authenticated origin reach internal APIs and same-origin data.

Severity scales with the privileges of the origin, whether the flow is reachable by a link/redirect, and whether the app exposes tokens to JS.

## 3. Sources (taint origins)

| Source | Notes |
|---|---|
| `location`, `location.href`, `location.search`, `location.hash`, `location.pathname`, `location.protocol`, `location.host*` | Hash/query are the classic vectors; fragment never reaches the server |
| `document.URL`, `document.documentURI`, `document.baseURI` | Reflect navigational input |
| `document.referrer` | Attacker-influenced by the linking page; fragment is stripped by browsers |
| `window.name` | Persists across navigations within a tab; settable from other origins by opening/navigating the tab |
| `document.cookie` | Second-order: set by sibling subdomain or another vulnerability |
| `localStorage`, `sessionStorage`, `IndexedDB`, Cache API | Second-order storage; often populated by another route/flow |
| `history.state`, `history.pushState` data | Persisted per history entry; survives back/forward |
| `MessageEvent.data` from `postMessage` | Any window (opener, iframe, popup) can send; check origin validation |
| `WebSocket` messages, `EventSource`, `BroadcastChannel`, `SharedWorker`/`ServiceWorker` messages | Server- or peer-fed data reaching sinks |
| `fetch`/`XHR`/JSONP responses | Server-controlled data read then written to a sink (server-side DOM XSS) |
| `URLSearchParams` / custom URL parsers | Abstractions over `location` |
| Element attributes/values from attacker-influenced HTML | DOM clobbering, dangling markup, injected templates |
| `FileReader`/`Blob` text, clipboard paste handlers, drag-and-drop `dataTransfer` | User/attacker-assisted input |
| `window.opener`/`window.parent` data, `iframe.name` | Cross-window channels |

## 4. Sinks (dangerous operations)

**HTML injection sinks** — parse a string as markup:

- `element.innerHTML`, `element.outerHTML`
- `element.insertAdjacentHTML()`
- `document.write()`, `document.writeln()`
- `Range.createContextualFragment()`
- `DOMParser.parseFromString()` → imported/adopted nodes
- jQuery: `.html()`, `.append()`, `.prepend()`, `.before()`, `.after()`, `.replaceWith()`, `.wrap()`, `.wrapAll()`, `.wrapInner()`, `$.parseHTML()`, and `$()` when the argument starts with `<`
- `element.setHTMLUnsafe()` / `setHTML()` (Sanitizer API — safe only when a sanitizing config applies)
- `iframe.srcdoc`
- `<template>` content injected and later adopted

Behavior notes: `<script>` inserted via `innerHTML`/`insertAdjacentHTML`/`outerHTML` is inert; event-handler attributes and nested browsing contexts still execute. `document.write` **does** execute scripts (and after page load triggers `document.open`, wiping the document). jQuery's `domManip` evaluates `<script>` strings passed to `.html()`/`.append()`.

**JavaScript execution sinks:**

- `eval()`, `Function()` / `new Function()`
- `setTimeout()` / `setInterval()` called with a **string**
- `execScript()`, `$.globalEval()`, `import()` with an attacker-controlled specifier
- `javascript:` URI navigation (via location sinks below)

**Navigation / URL sinks:**

- `location.assign()`, `location.replace()`, `location.href =`
- `window.open()`
- `element.href`, `element.src`, `form.action`, `button.formaction`, `iframe.src`, `script.src`, `link.href`, `object.data`, `embed.src`, `base.href`
- `javascript:`, `data:`, `blob:` schemes; `postMessage(data, '*')` (leaks/forwards taint to another window)
- `<a target="_blank">` without `rel="noopener"` (reverse tabnabbing, not XSS per se)

**CSS sinks:**

- `element.style.*`, `cssText`, injected `<style>` blocks, `@import`, `url()` (exfiltration channel)
- Legacy `expression()` (old IE), and CSS-based data extraction when scripts are blocked

**Attribute sinks:**

- `setAttribute('on*')`, `setAttribute('href'|'src'|'style', ...)`, `dataset` writes read later

**Framework-specific sinks:**

- React: `dangerouslySetInnerHTML`, `href`/`src` with untrusted URL strings
- Angular: `[innerHTML]`, `bypassSecurityTrustHtml`/`*Script`/`*Url`
- AngularJS 1.x: expression evaluation `{{ }}` in attacker-controlled text → client-side template injection
- Vue: `v-html`, dynamic `:href`/`:src`/`:style`
- jQuery: `$()` with an HTML string; `$(location.hash)` is a classic pattern

## 5. Data Flow & Taint Propagation

- **Direct flows**: `location.hash` → `innerHTML` with no processing.
- **Transformations in between**: `decodeURIComponent`, `unescape`, `replace`, `slice`/`split`, string concatenation, template literals, `JSON.parse`, base64 decode, `.trim()`. What matters is the string that actually reaches the sink, and whether *every* branch applies the same processing.
- **Branching**: sanitization applied on one code path but not another; early returns; error handlers that fall back to raw values.
- **Round trips**: data fetched from a server or storage, parsed, then written to a sink (second-order).
- **Indirect creation of sinks**: DOM clobbering can redirect code to a different object/property than the author intended; prototype pollution can inject values consumed by library sinks. Neither requires an obvious source→sink path in the source code.

## 6. Testing Workflow

**1) Recon / static enumeration**

- Enumerate inputs reachable without a server round trip: fragment, query, path, referrer, `window.name`, storage, `postMessage` listeners, WebSocket/EventSource streams, paste/drop handlers.
- Identify client-side routing (SPA routers frequently parse `location.hash`/`pathname`) and all routes that render attacker-influenced state.
- Beautify/minify-decode bundles; use source maps when available. Grep for source and sink identifiers (§3, §4).
- Audit `onmessage`/`addEventListener('message')` handlers: missing or weak `event.origin` checks are a direct path.
- Note framework/library versions (jQuery, DOMPurify, AngularJS, Vue, React) for known DOM-XSS advisories.

**2) Dynamic tracing**

- Inject a unique canary token into one source at a time, then exercise every route and interaction.
- Breakpoint sinks: in DevTools console, `debug(fn)` on sink functions (or temporarily wrap `Element.prototype.innerHTML` setter, `Element.prototype.insertAdjacentHTML`, `setAttribute`, `document.write`, `location.assign`, etc.) to log arguments and stack traces on every call.
- Use DOM breakpoints ("subtree modifications") and Event Listener Breakpoints to catch rendering-time execution.
- Inspect the exact string at the sink and its context: HTML text, attribute value, JS string inside a script block, URL, CSS. Note every transformation applied.
- Confirm the canary reaches the sink **unencoded**; distinguish "present in the DOM but escaped" from "live at the sink".
- For server-side DOM XSS variants, submit payloads to the server and watch for the reflected value reaching a client-side sink.
- Taint-tracking tooling (browser instrumentation that hooks sources and sinks, canary-injection extensions) automates this.

**3) Confirming exploitability**

- Craft a payload specific to the sink's parsing context; verify in the target browser.
- Check blockers: CSP (`unsafe-inline`, `unsafe-eval`), Trusted Types enforcement, sanitizers, user-activation requirements for `javascript:` URLs, sandboxed iframes.
- Test across engines; parsing/normalization differences are decisive for mXSS and fragment handling.

**4) Automation caveats**

- Response-diffing scanners cannot find DOM XSS.
- Static analyzers (CodeQL, Semgrep, ESLint `no-unsanitized`) surface candidate flows but produce many false positives and miss dynamic/compound flows; always confirm with runtime tracing.
- Headless-browser instrumentation with taint tracking gives confirmed flows and is the practical CI approach.

## 7. Payload Strategy per Sink Context

| Context at the sink | Strategy | Example shape |
|---|---|---|
| HTML text (`innerHTML`, `insertAdjacentHTML`, `outerHTML`) | Injected element with event handler; `script` tags are inert | `<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>`, `<details open ontoggle=...>`, `<iframe srcdoc="<script>...</script>">` |
| Inside an HTML attribute value | Break out of the quoting/tag, then inject handler | `"><img src=x onerror=alert(1)>`, `" autofocus onfocus=alert(1) x="` |
| Inside a JS string inside `<script>` | Terminate the string and statement | `';alert(1)//`, `\';alert(1)//`, `</script><script>alert(1)</script>` |
| `eval` / `Function` / string `setTimeout` | Raw JavaScript; obfuscate identifiers | `alert(1)`, `\u0061lert(1)`, `top['ale'+'rt'](1)`, `[].constructor.constructor('alert(1)')()` |
| `document.write` | HTML, including script tags | `</script><script>alert(1)</script>`, `<img src=x onerror=alert(1)>` (note post-load writes wipe the page) |
| URL sinks (`href`/`src`/`action`/`location`) | Scheme abuse or redirect chaining | `javascript:alert(1)` (may need user activation), `data:text/html,...`, `//attacker/...` chained to another flaw |
| jQuery `$()` / `domManip` | HTML string consumed as markup/selector | `<img src=x onerror=alert(1)>`, `#<img ...>` in selector position, `<script>...</script>` (evaluated by `.html()`/`.append()`) |
| AngularJS expression | Client-side template injection | `{{constructor.constructor('alert(1)')()}}` (sandbox escapes for older 1.x) |
| Vue `v-html` / dynamic bindings | HTML payload or JS URI | `<img src=x onerror=alert(1)>`, `:href` with `javascript:` |
| CSS context | Break out of style block | `</style><img src=x onerror=alert(1)>`; legacy `expression()` |
| `postMessage` handler | Deliver the payload the receiving sink expects | message data carrying the appropriate HTML/JS string for that sink |

## 8. Bypass Techniques

**Encoding and obfuscation**

- HTML entities in HTML context (`&#x3c;`, `&#106;avascript:`), URL and double-URL encoding, JS escapes (`\xNN`, `\uNNNN`), octal escapes in sloppy mode, `String.fromCharCode`, template literals, string concatenation.
- Whitespace/comment splitting (`/**/`, newlines, tabs), case variation, mixed/unquoted attribute syntax, event handler aliases (`onerror` vs. `onload` vs. `ontoggle`).
- Fragment immunity: payloads in `#` never reach the server, so server-side filtering and WAFs are bypassed entirely — only client-side logic matters.

**Sanitizer / filter bypass**

- Single-pass keyword replacement: split or nest the keyword (`<scr<script>ipt>`), use a different execution vector that needs no `<script>`, exploit case-insensitivity gaps.
- Validate-then-decode ordering flaws: entity or percent decoding performed *after* the check; `decodeURIComponent` applied downstream of validation; `escape`/`unescape` mismatches.
- Regexes without anchors, with greedy matches, or that operate on the wrong context.
- Only allowlisted tags are filtered, but allowlisted tags still carry event handlers or dangerous URL attributes.
- Sanitizer misconfiguration: permissive `ALLOW_*`/`ADD_*`/`FORBID_*` combinations, custom hooks that reintroduce taint, `RETURN_DOM` misuse, sanitizing before concatenation, or output re-decoded after sanitization.
- mXSS: sanitizer output mutates on re-parse — SVG/MathML namespace confusion, RCDATA/`<noscript>` contexts, comment/`<style>` parsing, template round trips. Test by comparing the sanitized string with the DOM produced after re-parsing.

**DOM clobbering**

- Named elements create/override globals: `<a id=x>`, `<img name=config>`, `<form id=x><input name=y>` (→ `x.y`).
- Duplicate names yield `HTMLCollection`s, defeating `typeof x === 'string'` checks and enabling coercion or `.value`/`.src`/`.href` reads of attacker-chosen values.
- Uses: defeat `if (window.feature)` guards, supply fake config objects that a library later reads into a sink, force a code path that treats a non-sink as a sink.
- Limits: non-configurable window properties (`location`, `document`, `top`, `parent`, `self`) cannot be clobbered; clobbering works through named access on the window and `document`, and through form element properties.

**Prototype pollution → DOM XSS**

- Pollution sources: `__proto__`/`constructor.prototype` keys in query strings, hash fragments, or JSON parsed by deep-merge/query-parsing helpers; `Object.assign` patterns that copy untrusted keys.
- Gadget sinks: libraries that read `obj.src`, `obj.href`, `obj.innerHTML`, `obj.srcdoc`, `obj.data`, `obj.template`, `obj.url` from an options object and assign them to a DOM sink → polluted value lands in HTML/URL context. Framework template compilers reading polluted options can yield direct code execution.
- Chain shape: pollution source (client-side URL/hash parsing) + gadget in a UI component or AJAX helper.

**CSP interaction**

- Inline event handlers require `script-src 'unsafe-inline'`; string `eval`/`setTimeout` require `'unsafe-eval'`. With a strict CSP, HTML-only payloads cannot execute JavaScript.
- Bypass routes when CSP is present but weak: whitelisted JSONP endpoints, whitelisted libraries with gadget behaviors (Angular, RxJS), missing `base-uri` (base-tag injection), nonce/hash handling flaws, `strict-dynamic` chains via injected script loaders.
- If execution is truly blocked: scriptless exfiltration (dangling markup injection to capture CSRF tokens/page content via `img`/`form`), CSS-based data extraction, DOM clobbering to subvert nonce checks or enable a non-sink path.

**Trusted Types**

- With `require-trusted-types-for 'script'` enforced, assigning a raw string to an HTML/script/navigation sink throws a `TypeError` — sinks become non-exploitable unless a permissive policy exists (a default policy that passes strings through is as good as no defense), or the policy itself is reachable/bypassable.

**Browser and platform restrictions to plan around**

- `javascript:` navigation and popup-based `javascript:` URLs generally require user activation in modern browsers; sandboxed iframes without `allow-scripts` block execution.
- `<script>` inserted via `innerHTML`/`insertAdjacentHTML`/`outerHTML` is inert; `Range.createContextualFragment` behavior varies by engine — event-handler vectors are the reliable route; `document.write` and jQuery's script-eval path do execute scripts.
- Sanitizer API `setHTML` sanitizes by default; `setHTMLUnsafe` does not.

## 9. Defense

**Primary — remove the sink**

- Use `textContent`/`innerText`, `value`, `replaceChildren`, `createElement` + text nodes instead of markup-building APIs.
- Never construct HTML by concatenating untrusted data; keep template and data separate.
- Rely on framework auto-escaping (React/Angular/Vue) and avoid escape hatches: `dangerouslySetInnerHTML`, `bypassSecurityTrust*`, `v-html`.

**When HTML is unavoidable**

- Sanitize on output with a maintained library (DOMPurify) or the Sanitizer API (`setHTML`), with a restrictive allowlist; sanitize the final string, after all decoding, immediately before insertion; never sanitize then re-transform.
- Keep sanitizers and frameworks patched (jQuery ≥ 3.5.0 for the `htmlPrefilter` advisories; current DOMPurify/Angular/Vue).

**URL handling**

- Parse with `new URL()` and enforce a scheme allowlist (`http`/`https`); reject `javascript:`, `data:`, `blob:` for untrusted navigation; validate that resolved URLs stay on expected origins.
- Never assign untrusted input directly to `location`, `href`, `src`, `action`, `srcdoc`, or `window.open`.

**JavaScript execution**

- Ban `eval`, `Function`, and string arguments to `setTimeout`/`setInterval`; use function callbacks. Never `eval` data derived from the DOM.

**Data sources**

- Treat `location.*`, `document.referrer`, `window.name`, `postMessage` data, storage, and fetched responses as untrusted.
- For `postMessage`, validate both `event.origin` and `event.source`, and always specify an explicit `targetOrigin` when sending.
- Avoid storing bearer tokens in JS-readable storage; use `HttpOnly`/`Secure` cookies where possible to reduce theft impact.

**Encoding discipline**

- Contextual encoding only: HTML entities for HTML text/attributes, JS string escaping for script data, percent-encoding for URL components. `encodeURIComponent` does not make data safe for HTML or JS contexts.

**Deployment hardening**

- Strict CSP: nonce/hash-based `script-src` with `strict-dynamic`, no `unsafe-inline`/`unsafe-eval`; plus `base-uri 'none'`, `object-src 'none'`, `frame-ancestors`.
- Enforce Trusted Types with a locked-down policy set and no permissive default policy — this converts string-to-sink assignments into exceptions and eliminates whole sink families.
- Subresource Integrity for third-party scripts; isolate untrusted content on separate origins or in sandboxed iframes.

**Detection and process**

- Continuous dynamic scanning with source/sink instrumentation in CI (canary-injection + sink breakpointing).
- JS-aware SAST and lint rules (no-unsanitized, taint analysis) as a triage net, confirmed dynamically.
- Code-review focus: any path from §3 sources to §4 sinks, especially in routers, hash handlers, `message` listeners, and third-party integrations.

## 10. Quick Checklist

- Any `location`/`referrer`/`window.name`/`postMessage`/storage value reaching `innerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `Function`, string timers, `location.assign`, `href`/`src`, `srcdoc`, or a framework escape hatch?
- Is the payload deliverable via a fragment (server-blind), a crafted link, a popup/iframe `postMessage`, or persisted storage?
- Is the sink context HTML text, attribute, JS string, URL, or CSS — and does the payload match that grammar?
- Are sanitization/encoding steps applied consistently on every branch, before the sink, and after all decoding?
- Is there clobberable state or a prototype-pollution path that changes which object reaches the sink?
- What does CSP and Trusted Types permit, and what browser restrictions (user activation, sandbox) apply?
- Does the flow survive re-parsing (mXSS) and differ across engines?