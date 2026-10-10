# Reflection XSS — Skill

## What it is
- User input is reflected immediately in the HTTP response (URL parameter, form field, or header) without proper output encoding.
- The payload executes in the victim's browser within the vulnerable site's origin, typically delivered via a crafted link.
- Non-persistent: nothing is stored server-side; the payload only fires for the request that carries it.

## Reflection points (where input comes back)
- URL query parameters (GET/POST).
- Search boxes and form fields echoed into the page.
- HTTP headers echoed into the response: Referer, User-Agent, Cookie.
- Hidden form fields.
- Two output contexts matter: text node vs attribute value (`value="..."`, `src="..."`, `href="..."`) — each needs different escaping.

## Testing workflow
1. Enumerate input points: params, forms, headers, hidden fields.
2. Inject a probe: special chars (`>`, `'`, `"`, `<`, `/`) plus a unique marker; submit and read the returned HTML source to see whether/where the value is reflected and how it was processed.
3. Locate the marker and analyze the surrounding syntax to determine how to break out and build a JS-executing context.
4. Submit the crafted payload and confirm execution.

## Bypass techniques (generic)
1. Build `<script>` tags with `<` and `>`.
2. `javascript:` pseudo-protocol in tag attributes: `href`, `lowsrc`, `bgsound`, `background`, `value`, `action`, `dynsrc`.
3. Break keyword filters with quotes / semicolons / newlines.
4. ASCII-encode attribute values.
5. Event handlers that fire on load: `<img src=# onerror=...>`.
6. CSS `expression` / `@import`.
7. Case confusion, single vs no quotes, full-width chars, `/**/` comment confusion.
8. Character encoding: unicode / escapes / hex / octal.

## What to check (hunting & defense)
- `htmlspecialchars` without `ENT_QUOTES` leaves single-quote breakout open.
- `str_replace` that is case-sensitive (missing `strtolower`) → case confusion.
- `str_replace` to empty (vs placeholder) → double-write / nested-keyword bypass.
- Header values (Referer / User-Agent / Cookie) echoed without sanitization.
- Attribute context vs text-node context: different escaping requirements.
