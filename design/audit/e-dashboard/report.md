# Design Audit — http://localhost:5173/design.html#/c/e/dashboard

Viewports: 360 / 390 / 768 / 1024 / 1440 / 1920 px  ·  Heuristic pass (pair with `/design-review` for taste & flows).

**Findings:** 2 high · 2 medium · 0 low

## HIGH
- **focus-visible** — 8/25 sampled interactive elements show no visible focus indicator.  
  ↳ seen at: mobile-360, mobile-390, tablet-768, laptop-1024
- **focus-visible** — 4/25 sampled interactive elements show no visible focus indicator.  
  ↳ seen at: desktop-1440, wide-1920

## MEDIUM
- **tap-target** — 35 interactive targets < 44×44px on mobile.  
  ↳ seen at: mobile-360, mobile-390
- **contrast** — ~9/120 sampled text nodes below WCAG AA contrast (approximate).  
  ↳ seen at: mobile-360, mobile-390, tablet-768, laptop-1024, desktop-1440, wide-1920

## Screenshots

- mobile-360 (360×800): `screenshots/mobile-360.png`
- mobile-390 (390×844): `screenshots/mobile-390.png`
- tablet-768 (768×1024): `screenshots/tablet-768.png`
- laptop-1024 (1024×768): `screenshots/laptop-1024.png`
- desktop-1440 (1440×900): `screenshots/desktop-1440.png`
- wide-1920 (1920×1080): `screenshots/wide-1920.png`
