# `public/assets/css/` — Stylesheet

## `style.css`

The application's single, self-contained stylesheet. It is **not** a third-party
Bootstrap bundle: a small, Bootstrap-inspired utility set is hand-written here so
that

- the app works fully offline, and
- the Content-Security-Policy can forbid external style origins.

### Conventions

- Every class is prefixed **`ms-`** (MediShield) to avoid collisions and to make
  markup self-documenting.
- Colours, spacing and radii are defined once as CSS custom properties in
  `:root` and reused, so the theme can be retuned in one place.
- The HTML that uses these classes is produced by `includes/layout.php` and the
  individual pages in `public/`. When you add a new `ms-*` class in a page, add
  its rule here.

### Class groups

| Prefix | Used for |
|--------|----------|
| `ms-nav*`, `ms-brand`, `ms-main`, `ms-footer` | Page shell / navigation. |
| `ms-card*` | Content panels. |
| `ms-h1`, `ms-h2`, `ms-muted`, `ms-help` | Typography. |
| `ms-label`, `ms-input` | Form fields. |
| `ms-btn*` | Buttons (`-primary`, `-sm`, `-block`). |
| `ms-alert*` | Coloured message boxes (`-success/-danger/-warning/-info`). |
| `ms-grid`, `ms-stat*` | Admin dashboard metric tiles. |
| `ms-table*`, `ms-row-warn`, `ms-badge*` | Data tables (user list, audit log). |
