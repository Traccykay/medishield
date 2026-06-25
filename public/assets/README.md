# `public/assets/` — Static Assets

Publicly served static files (no PHP, no application logic). Today this is just
the stylesheet under `css/`; future deliverables may add JavaScript or images
here.

Serving assets from our **own origin** (rather than a third-party CDN) is a
deliberate security choice: it keeps the demo working offline and lets the
Content-Security-Policy in `includes/headers.php` stay strict, with no external
style/script origins to allow-list.

## Contents

| Path | Purpose |
|------|---------|
| `css/style.css` | The application's self-contained stylesheet (see `css/README.md`). |
