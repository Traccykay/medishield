# `public/assets/` — Static Assets

Publicly served static files (no PHP, no application logic). Today the only
HTTP-allowlisted asset is the stylesheet under `css/`. Future JavaScript,
images, or fonts remain denied until their exact paths and MIME types are added
to both runtime boundaries and their tests.

Serving assets from our **own origin** (rather than a third-party CDN) is a
deliberate security choice: it keeps the demo working offline and lets the
Content-Security-Policy in `includes/headers.php` stay strict, with no external
style/script origins to allow-list.

## Contents

| Path | Purpose |
|------|---------|
| `css/style.css` | The application's self-contained stylesheet (see `css/README.md`). |

The PHP development router sends this file as
`text/css; charset=utf-8` with `X-Content-Type-Options: nosniff` and a public
cache policy. `public/.htaccess` applies the same MIME/cache contract under the
supported Apache vhost. Dynamic session-bearing pages use a separate central
private/no-store policy.
