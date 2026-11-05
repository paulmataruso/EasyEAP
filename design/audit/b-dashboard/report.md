# Design Audit — http://localhost:5173/design.html#/c/b/dashboard

Viewports: 360 / 390 / 768 / 1024 / 1440 / 1920 px  ·  Heuristic pass (pair with `/design-review` for taste & flows).

**Findings:** 1 high · 4 medium · 0 low

## HIGH
- **focus-visible** — 1/25 sampled interactive elements show no visible focus indicator.  
  ↳ seen at: mobile-360, laptop-1024

## MEDIUM
- **tap-target** — 23 interactive targets < 44×44px on mobile.  
  ↳ seen at: mobile-360
- **contrast** — ~2/120 sampled text nodes below WCAG AA contrast (approximate).  
  ↳ seen at: mobile-360
- **headings** — No <h1> on the page.  
  ↳ seen at: mobile-390, tablet-768, desktop-1440
- **contrast** — ~1/120 sampled text nodes below WCAG AA contrast (approximate).  
  ↳ seen at: laptop-1024, wide-1920

## Screenshots

- mobile-360 (360×800): `screenshots/mobile-360.png`
- mobile-390 (390×844): `screenshots/mobile-390.png`
- tablet-768 (768×1024): `screenshots/tablet-768.png`
- laptop-1024 (1024×768): `screenshots/laptop-1024.png`
- desktop-1440 (1440×900): `screenshots/desktop-1440.png`
- wide-1920 (1920×1080): `screenshots/wide-1920.png`
