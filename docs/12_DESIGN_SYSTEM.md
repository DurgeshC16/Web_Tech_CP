# 12 — Design System ("Gradient + Glass")

Component catalogue for everyone touching page markup. Vivid brand gradient,
frosted-glass surfaces, purposeful motion — in **light and dark**, responsive
from 360 px, WCAG AA, no external JS/images.

## 0. House rules

1. **No `style=""` attributes.** Use a component class or a utility (§7). If
   nothing fits, add a class to the page stylesheet. Dynamic values (bar
   widths, positions) are set from JS with `el.style.setProperty('--bar', '42%')`
   (CSSOM is allowed by the CSP; inline attributes are what we are removing).
2. **No inline `<script>` / `on*=""`** (CSP `script-src 'self'`,
   `script-src-attr 'none'`). Behaviour goes in `public/assets/js/*.js`.
3. **No `data:` URIs or external images** (CSP `img-src 'self' blob:`) — not in
   markup and not in CSS (`url(data:…)` / `mask-image` would be blocked and
   reported). Icons are inline SVG with `aria-hidden="true" focusable="false"`.
4. **Tokens only** — never hard-code theme colours; every rule must work under
   `<html data-theme="light|dark">`.
5. **Keep hooks**: ids, `name`s, `data-*` attributes and the classes listed in
   tests (`verdict-seal-<verdict>`, `guest-quota-*`, `otp-input`, `pw-*`,
   `status-*`, `alert-*`, `btn*`, `table`, `table-wrap`, `card`, …). Grep
   `tests/` and `public/assets/js/` before renaming anything.
6. **Static asset size** — keep each CSS/JS file you add under ~56 KB: PHP's
   built-in server (used by the browser tests) intermittently stalls on larger
   static files.

## 1. Files and load order

| File | Content |
|---|---|
| `src/partials/head_fonts.php` | Google Fonts: **Plus Jakarta Sans** 600–800 (display) + **Inter** 400–700 (body) |
| `assets/css/style.css` | §1–9: tokens, base, background, layout, header/footer, glass surfaces, buttons, forms, badges |
| `assets/css/components.css` | §10–16: alerts/toasts, tables, tabs, stats, verdict seals, steppers/timeline/empty/skeleton, auth layout |
| `assets/css/features.css` | §17–22: landing, verify/credential/2FA/analytics modules, motion, utilities, responsive, reduced motion, print |
| `assets/css/pages/{auth,verify,student,admin}.css` | page refinements (all four load on every page, after the above) |
| `assets/js/theme.js` | sync in `<head>`: adds `html.js`, theme cookie, `#themeToggle`, `#navToggle` drawer (Esc / outside click closes) |
| `assets/js/ui.js` | deferred: confirm, password eye, copy, reveal, counters, ripple, tilt, toasts … (§6) |

`<body>` carries `page-<script-name>` (underscores → hyphens), e.g.
`body.page-admin-dashboard`, `body.page-verify` — scope page rules with it.
A page may set `$body_class = 'x y';` before including `head.php`.

## 2. Tokens (custom properties on `:root`, overridden by `[data-theme="dark"]`)

| Group | Tokens |
|---|---|
| Brand | `--brand-1` indigo `#4f46e5`, `--brand-2` violet `#7c3aed`, `--brand-3` cyan `#0891b2`; `--grad-brand`, `--grad-btn`, `--grad-btn-hover`, `--grad-text`, `--grad-hero` |
| Text | `--ink` (headings/body), `--ink-2` (secondary), `--muted` (help text, ≥ 6:1 on surfaces) |
| Surfaces | `--bg`, `--surface` (solid), `--surface-2` (inset), `--paper` (legacy inset), `--border`, `--border-strong` |
| Glass | `--glass-bg`, `--glass-bg-strong`, `--glass-border`, `--glass-blur` |
| Accent | `--accent`, `--accent-hover`, `--accent-soft`, `--focus`; legacy aliases `--seal`, `--seal-hover` |
| Semantic | `--verified`, `--danger`, `--warn`, `--info` (superseded), `--neutral` — each with `-soft` (tinted bg) and `-solid` (fill behind white text) |
| Type | `--font-display`, `--font-sans`, `--font-mono` (`--font-serif` = legacy alias of display) |
| Radii | `--radius-sm` 8, `--radius` 12, `--radius-lg` 18, `--radius-xl` 26, `--radius-pill` |
| Space | `--sp-1`…`--sp-9` = 4, 8, 12, 16, 24, 32, 48, 64, 96 px |
| Elevation | `--shadow-sm`, `--shadow-md`, `--shadow-lg`, `--shadow-glow` |
| Motion | `--ease-out`, `--ease-spring`, `--dur-1` .15s, `--dur-2` .3s, `--dur-3` .6s |

Semantic text colours (`--verified` etc.) are for text/borders on surfaces;
white text only ever sits on `*-solid` or the brand gradients (all ≥ 4.5:1).

## 3. Layout

```html
<main id="main">                                   <!-- padded page area -->
  <div class="container shell-wide">               <!-- glass page panel; shell-narrow = 560px -->
    <div class="page-head">
      <div><h1>Title</h1><p class="page-head-sub">Subtitle</p></div>
      <div class="page-head-actions"><a class="btn btn-primary" href="…">Action</a></div>
    </div>
    <div class="dashboard-grid">                   <!-- 2fr / 1fr from 1024px -->
      <section class="card">…</section>
      <aside class="card">…</aside>
    </div>
  </div>
</main>
```

* `.wrap` (1200px centred) / `.wrap-narrow` (720px) — full-bleed sections (landing).
* `.grid-2`, `.grid-3`, `.grid-4` — responsive grids (1 → 2 → n columns); `.grid-container` auto-fill cards.
* `.form-row` — two form columns from 768px. `.split > .split-main + .split-side` — detail pages.
* `.stack`, `.stack-sm`, `.cluster`, `.actions-row`, `.btn-row`, `.inline-form`, `.form-inline-stack`.
* `.section`, `.section-alt`, `.section-head` (eyebrow + h2 + p, centred).
* Breakpoints: 479 / 639 / 767 / 1023 / 1199 / 1280. Hamburger drawer by menu
  width: guest / super admin < 900px, student (`.is-mid`) < 1024px, admin
  (`.is-dense`) < 1200px (900px+ it opens as a right-aligned dropdown panel).
  Rules live at the top of `components.css`.

## 4. Components

**Glass / cards**
```html
<div class="glass">…</div>  <div class="card">…</div>  <div class="card card-hover">lifts on hover</div>
<div class="card card-accent-valid">left rail</div>    <!-- -danger -warn -info -brand -->
<div class="card card-gradient">gradient border</div>  <div class="panel-muted">inset note box</div>
<div class="card"><div class="card-head"><h2>Title</h2><span class="badge badge-info">x</span></div>
  <div class="card-title">…</div><div class="card-meta">…</div><div class="card-actions">…</div></div>
```
Glass = translucent `--glass-bg` + `backdrop-filter` inside `@supports`; solid
`--surface` otherwise. Cards nested in `.container`/`.card` become flat inset tiles (no second blur).

**Buttons** — `.btn` + one of `btn-primary` (gradient + glow), `btn-secondary`
(surface + border), `btn-ghost`, `btn-danger`, `btn-warn`, `btn-verified`,
`btn-light` / `btn-outline-light` (on gradients); sizes `btn-sm`, `btn-lg`,
`btn-block`, `btn-icon`. States: `:disabled`, `[aria-disabled=true]`,
`.is-loading` (spinner; or put `data-loading` on the `<form>`). Press scale +
ripple are automatic. Inline SVG icons inside a button are sized 18px.

**Forms** — global styling for text-like inputs, `select`, `textarea`,
checkbox/radio (`accent-color`), `input[type=file]` (dashed drop-zone look +
gradient picker button). Wrap fields in `.form-group` (`label`, `small` /
`.help-text` / `.field-note`). Errors: `aria-invalid="true"` +
`.field-error` (output of `render_field_error()` / validation.js) get red
border, tint and an "!" chip. `.otp-input` (large mono, spaced),
`.captcha-chip`, `.checkbox-row`, `.copy-field`, `.share-input`,
`.file-name-display`, `.filter-bar` / `.filter-form`. Password helpers
(`.pw-field`, `.pw-toggle`, `.pw-meter*`, `.pw-rules li.met`) are created by JS — keep them.

**Badges / pills / chips**
```html
<span class="badge-status badge-valid">active</span>   <!-- dot + uppercase -->
<span class="status-badge status-revoked">revoked</span>
```
Variants: valid/active/approved/issued/pass (green), tampered/revoked/rejected/
failed/error (red), expired/pending/warn (amber), superseded/info (blue),
invalid/unknown/not_found (neutral), `badge-brand`. `.pill` (soft accent),
`.role-chip`, `.chip` (+ `.active`, `chip-valid|tampered|revoked|expired|superseded|invalid`).

**Alerts / toasts**
```html
<div class="alert alert-success">Saved.</div>   <!-- alert-danger | alert-warning | alert-info -->
<div class="toast toast-success" role="status" hidden>Copied!</div>
```
From JS: `CertiVaultUI.toast('Copied', 'success' | 'error' | 'info', ms)`.

**Tables** — `<div class="table-wrap"><table class="table">…` (glass frame,
sticky header, hover rows; `.table-striped`, `.data-table`, `td.num`). Below
640px rows become stacked cards: give every `<td>` a `data-label="Column"`.

**Tabs** — link tabs `<nav class="tabs"><a class="tab active">…` or ARIA tabs
`<div class="tablist" role="tablist"><button class="tab" role="tab" aria-selected="true">`;
both render as a segmented control with a gradient active pill. Panels: `.tabpanel`.

**Stats**
```html
<div class="stat-grid">
  <div class="stat-card"><span class="stat-icon"><svg…/></span>
    <div class="stat-num" data-count-to="51">51</div><div class="stat-label">Total issued</div></div>
</div>
```

**Verdict seal** (verify / share pages) — pop-in, icon stroke draws, ring
pulses (VALID keeps pulsing; TAMPERED also shakes):
```html
<div class="verdict-wrap">
  <div class="verdict-seal verdict-seal-valid"><svg viewBox="0 0 24 24" …><path d="M5 13l4 4L19 7"/></svg> VALID</div>
  <p class="verdict-detail">All checks passed.</p>
</div>
```
Variants: `valid`, `tampered`, `expired`, `revoked`, `superseded`, `invalid`
(`not_found`/`unknown` alias invalid). Banner variant: `.verdict-card
.verdict-<v>` with `.verdict-icon`, `.verdict-label`, `.verdict-detail`.
Certificate details: `.diploma` (gradient frame) + `dl.cert-details`
(`.cert-details-title`), QR: `.qr-hero` / `.seal-frame`, `.danger-panel`,
`.timeline > li.current`, credential checks `.check-list .check-pass|fail|warn`.

**Stepper** (multi-step flows such as forgot → code → reset)
```html
<ol class="stepper">
  <li class="is-done">Email</li><li class="is-current" aria-current="step">Code</li><li>New password</li>
</ol>
```

**Empty state / skeleton**
```html
<div class="empty-state"><span class="empty-state-icon"><svg…/></span><h3>No certificates yet</h3>
  <p>Issued certificates appear here.</p><a class="btn btn-primary" href="…">Issue one</a></div>
<span class="skeleton skeleton-title"></span><span class="skeleton skeleton-text"></span>
```

**Auth** — legacy `.auth-wrap > .auth-card` (centred glass card with gradient
top edge; `.auth-brand`, `.brand-name`, `.auth-foot`) or the split layout:
```html
<div class="auth-split">
  <aside class="auth-aside"><h2>Welcome back</h2><p>…</p><ul><li>Benefit</li></ul>
    <svg class="auth-aside-art" aria-hidden="true">…</svg></aside>   <!-- hidden < 900px -->
  <div class="auth-main"><div class="auth-card">…form…</div></div>
</div>
```

**Landing** (`index.php`) — `.hero.hero-gradient` (+ `.hero-orbs`,
`.hero-grid-lines`, `.hero-grid`, `.hero-copy`, `.hero-panel`, `.quick-verify`,
`.hero-float`), `.stats-strip`, `.steps` (+ `.steps-line`, `.step-card`,
`.step-num`, `.step-icon`), `.feature-grid > .feature` (`.feature-icon`,
`.feature-link`), `.audience-grid > .audience-card`, `.faq details`, `.cta-band`, `.eyebrow`, `.text-gradient`.

**Header / footer** (`src/partials/header.php`, `footer.php`) — sticky glass
header that condenses (`.is-scrolled`), gradient wordmark, active link =
`.is-active` + `aria-current="page"` (computed from the script name),
`.role-chip`, account links (Change Password, Two-factor auth) as round
`.nav-icon-link` buttons next to Logout (label in `.nav-icon-label`, visible
in the drawer), round `#themeToggle` (sun/moon), `#navToggle` hamburger →
animated drawer. Footer: brand blurb + three link columns + cookie note.

## 5. Motion

| Hook | Effect | Notes |
|---|---|---|
| `data-reveal` (`="left"`, `"right"`, `"zoom"`) | fade/slide in on scroll | stagger with `data-reveal-delay="1…5"` (90 ms steps) |
| `data-count-to="191"` | counts up from 0 when visible | element text must already be the final value (no-JS); `data-count-suffix`, `data-count-duration` |
| `data-tilt` | 3D tilt + glare following the pointer | fine pointers only |
| `.btn` | ripple + press scale | automatic |
| `.verdict-seal`, `.alert`, `.toast`, `.tabpanel`, `.check-list .check` | entrance animations | automatic |

Hidden reveal states exist **only** after ui.js adds `html.js-reveal`, so
content is visible with JS off. `prefers-reduced-motion: reduce` disables all
of the above (no reveal, counters, tilt, ripple, blobs; animations collapse to 0.01 ms).

## 6. JS hooks (ui.js / theme.js)

`form[data-confirm="Question?"]`, `input[data-select-on-click]`,
`a[data-history-back]`, `input[type=file][data-filename-target="id"]`,
`#resendBtn[data-wait]`, `#validity_years` → expiry, `#copyShareBtn` /
`#shareLinkInput` / `#copiedToast`, password eye on every
`input[type=password]` (opt out `data-no-toggle`), `[data-copy="text"]` /
`[data-copy-target="id"]` (+ `data-copy-message`), `form[data-loading]`,
`[data-print]` (opens the print dialog), broken `<img>` → `.img-missing` +
`.img-missing-note` placeholder (automatic),
`window.CertiVaultUI.toast()`, `#themeToggle`, `#navToggle` + `#primaryNav`.

## 7. Utilities (replace inline styles)

| Need | Class |
|---|---|
| margins | `m-0`, `mt-0…7`, `mb-0…7`, `my-4/5`, `ml-1/2`, `mr-1/2`, `mx-auto` |
| padding | `p-0`, `p-3/4/5`, `py-2/3` |
| flex | `flex`, `inline-flex`, `flex-col`, `flex-wrap`, `flex-1`, `items-center/start/end`, `justify-center/between/end`, `gap-1…5` |
| text | `text-center/left/right`, `text-xs/sm/base/lg/xl`, `text-muted/ink/success/warn/danger/info`, `fw-500/600/700`, `mono`, `nowrap`, `break-all`, `wrap-anywhere`, `pre-wrap`, `lead`, `text-gradient`, `text-link` |
| size | `w-auto`, `w-full`, `maxw-xs` (150), `maxw-sm` (400), `maxw-md` (480), `maxw-lg` (600), `maxw-xl` (800) |
| lists | `list-indent`, `list-plain`, `pl-list` |
| misc | `hidden`, `visually-hidden` / `sr-only`, `block`, `inline-block`, `relative`, `rounded`, `border-top`, `img-thumb` |

Typical replacements: `style="text-align:center; margin-top:20px"` →
`class="text-center mt-5"`; `style="color:var(--muted); font-size:0.9em"` →
`class="text-muted text-sm"`; `style="margin-top:14px; border-left:4px solid var(--verified)"`
on a card → `class="card card-accent-valid mt-3"`; bar widths →
`el.style.setProperty('--bar', pct + '%')` on `.viz-bar` (reads `width: var(--bar)`).

## 8. Accessibility checklist

* Focus: 3px `--focus` outline on every focusable element (white inside gradients).
* Touch: every control ≥ 44px on coarse pointers; skip link first in `<body>`.
* Contrast: body text on glass ≥ 7:1, muted ≥ 6:1, white on gradients ≥ 5.3:1.
* Keep semantic markup (`main`, `nav`, headings in order, `dl` for key/value,
  `details/summary` for disclosure) and every existing `aria-*`/`role`.
