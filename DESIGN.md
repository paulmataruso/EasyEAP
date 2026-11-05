---
name: EasyEAP
description: Multi-tenant MSP console and enrollment portal for EAP-TLS Wi-Fi, in smoked glass on a midnight ground.
colors:
  ground: "#0b0f1a"
  sidebar: "#0d1322"
  panel: "rgba(24, 32, 58, 0.7)"
  panel-solid: "#141b30"
  raised: "rgba(34, 43, 71, 0.8)"
  raised-solid: "#1d253e"
  overlay: "rgba(16, 22, 40, 0.86)"
  hover: "rgba(237, 234, 227, 0.045)"
  select: "rgba(226, 194, 117, 0.085)"
  line: "rgba(237, 234, 227, 0.085)"
  line-2: "rgba(237, 234, 227, 0.15)"
  line-3: "rgba(237, 234, 227, 0.24)"
  ink: "#edeae3"
  ink-2: "#b7b4ac"
  ink-3: "#94918a"
  gold: "#e2c275"
  gold-hi: "#ecd396"
  gold-ink: "#14100a"
  valid: "#2dd4bf"
  valid-ink: "#5fe3d2"
  warn: "#f5a524"
  warn-ink: "#f7b955"
  crit: "#f43f5e"
  crit-ink: "#ff7a8f"
  neutral: "#9aa3b5"
  vlan-blue: "#4194f9"
  vlan-violet: "#994ab0"
  vlan-teal: "#17a7b4"
  vlan-orange: "#c0401f"
  vlan-amber: "#ac913a"
  vlan-green: "#4f9a3c"
  vlan-rose: "#c64f86"
  vlan-slate: "#6f7c94"
  series-accept: "#1a9a8f"
  series-reject: "#f43f5e"
typography:
  display:
    fontFamily: "Hanken Grotesk Variable, Hanken Grotesk, ui-sans-serif, system-ui, sans-serif"
    fontSize: "27px"
    fontWeight: 650
    lineHeight: 1.15
    letterSpacing: "-0.022em"
    fontFeature: "'ss01' on"
  headline:
    fontFamily: "Hanken Grotesk Variable, Hanken Grotesk, ui-sans-serif, system-ui, sans-serif"
    fontSize: "16px"
    fontWeight: 640
    lineHeight: 1.3
    letterSpacing: "-0.01em"
  title:
    fontFamily: "Hanken Grotesk Variable, Hanken Grotesk, ui-sans-serif, system-ui, sans-serif"
    fontSize: "14px"
    fontWeight: 640
    lineHeight: 1.3
  body:
    fontFamily: "Hanken Grotesk Variable, Hanken Grotesk, ui-sans-serif, system-ui, sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.45
    fontFeature: "'ss01' on"
  body-sm:
    fontFamily: "Hanken Grotesk Variable, Hanken Grotesk, ui-sans-serif, system-ui, sans-serif"
    fontSize: "12.5px"
    fontWeight: 400
    lineHeight: 1.45
  label:
    fontFamily: "Hanken Grotesk Variable, Hanken Grotesk, ui-sans-serif, system-ui, sans-serif"
    fontSize: "12px"
    fontWeight: 500
    lineHeight: 1.45
  mono:
    fontFamily: "Red Hat Mono Variable, Red Hat Mono, ui-monospace, monospace"
    fontSize: "12.5px"
    fontWeight: 400
    letterSpacing: "0.01em"
    fontFeature: "'tnum' on"
  portal-display:
    fontFamily: "Hanken Grotesk Variable, Hanken Grotesk, ui-sans-serif, system-ui, sans-serif"
    fontSize: "28px"
    fontWeight: 650
    lineHeight: 1.2
    letterSpacing: "-0.02em"
  portal-body:
    fontFamily: "Hanken Grotesk Variable, Hanken Grotesk, ui-sans-serif, system-ui, sans-serif"
    fontSize: "15px"
    fontWeight: 400
    lineHeight: 1.55
rounded:
  swatch: "2.5px"
  key: "4px"
  chip: "5px"
  item: "6px"
  control: "7px"
  well: "8px"
  menu: "9px"
  panel: "10px"
  dialog: "12px"
  pill: "999px"
spacing:
  xs: "6px"
  sm: "8px"
  md: "12px"
  lg: "20px"
  xl: "24px"
  page-x: "32px"
  header-gap: "28px"
components:
  button-default:
    backgroundColor: "{colors.raised}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    padding: "0 12px"
    height: "32px"
  button-primary:
    backgroundColor: "{colors.gold}"
    textColor: "{colors.gold-ink}"
    rounded: "{rounded.control}"
    padding: "0 12px"
    height: "32px"
  button-primary-hover:
    backgroundColor: "{colors.gold-hi}"
    textColor: "{colors.gold-ink}"
  button-ghost:
    backgroundColor: "transparent"
    textColor: "{colors.ink-2}"
    rounded: "{rounded.control}"
    padding: "0 12px"
    height: "32px"
  button-ghost-hover:
    backgroundColor: "{colors.hover}"
    textColor: "{colors.ink}"
  button-danger:
    backgroundColor: "transparent"
    textColor: "{colors.crit-ink}"
    rounded: "{rounded.control}"
    padding: "0 12px"
    height: "32px"
  button-sm:
    height: "28px"
    padding: "0 10px"
  button-lg:
    height: "36px"
    padding: "0 15px"
  input:
    backgroundColor: "rgba(6, 9, 17, 0.45)"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    padding: "0 11px"
    height: "34px"
  chip:
    backgroundColor: "rgba(237, 234, 227, 0.06)"
    textColor: "{colors.ink-2}"
    typography: "{typography.label}"
    rounded: "{rounded.chip}"
    padding: "0 8px"
    height: "22px"
  chip-valid:
    backgroundColor: "rgba(45, 212, 191, 0.1)"
    textColor: "{colors.valid-ink}"
  chip-warn:
    backgroundColor: "rgba(245, 165, 36, 0.11)"
    textColor: "{colors.warn-ink}"
  chip-crit:
    backgroundColor: "rgba(244, 63, 94, 0.12)"
    textColor: "{colors.crit-ink}"
  chip-gold:
    backgroundColor: "rgba(226, 194, 117, 0.1)"
    textColor: "{colors.gold}"
  panel:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.ink}"
    rounded: "{rounded.panel}"
    padding: "20px"
  menu:
    backgroundColor: "{colors.overlay}"
    textColor: "{colors.ink}"
    rounded: "{rounded.menu}"
    padding: "5px"
  nav-item:
    backgroundColor: "transparent"
    textColor: "{colors.ink-2}"
    rounded: "{rounded.control}"
    padding: "0 10px"
    height: "32px"
  nav-item-active:
    backgroundColor: "{colors.select}"
    textColor: "{colors.ink}"
  dialog:
    textColor: "{colors.ink}"
    rounded: "{rounded.dialog}"
    width: "min(560px, calc(100vw - 32px))"
  portal-button-primary:
    backgroundColor: "{colors.gold}"
    textColor: "{colors.gold-ink}"
    rounded: "{rounded.panel}"
    padding: "0 20px"
    height: "48px"
  portal-input:
    backgroundColor: "rgba(6, 9, 17, 0.5)"
    textColor: "{colors.ink}"
    rounded: "{rounded.panel}"
    padding: "0 14px"
    height: "48px"
---

# Design System: EasyEAP

## Overview

**Creative North Star: "The Night Shift Ledger"**

EasyEAP is the console an MSP engineer keeps open while something is going wrong for a tenant: a midnight ground, panels of smoked glass, and bone-coloured type that stays readable at 13px for a whole shift. Every surface is a record of a decision. The house pattern is the ledger: a vertical sequence of gates, each marked pass, fail, not used or decides, ending in a verdict that names the exact outcome (Access-Accept to VLAN 120, or Access-Reject and why). The same ledger reads the same on the user record, in Test a user and in the policy preview.

Density is operational, not decorative. Tables run at 13px with 10px row padding, chips are 22px tall, buttons are 32px, and the page is a 12-column grid at desktop with 20px gutters. Colour carries state only: verdigris for valid and accepted, crimson for revoked and rejected, amber for expiring and warning, and gold for authority (the primary action, the current location, the deciding rule, the focus ring). Depth comes from translucency, a hairline bone border and a single 1px light along the top edge of each panel, whose colour is keyed to the risk of what the panel holds.

The enrollment portal is the same world, set larger and calmer for people who are not administrators: one 640px column, 15px body, 48px controls, a four-step progress bar and one authored entrance motion. It never introduces a new colour or font.

**Key Characteristics:**
- Midnight ground with two faint fixed radial glows (verdigris top right, gold bottom left).
- Smoked-glass panels with a hairline border and a risk-keyed top edge light (`data-risk`).
- Gold is authority: primary action, current nav item, focus ring, caret, selection, deciding ledger step.
- State colour is semantic only, always paired with an icon and a word.
- Tabular numerals everywhere numbers sit; validity remaining is right-aligned.
- Hanken Grotesk for everything readable, Red Hat Mono for serials, MACs, attributes and secrets.
- Sentence case throughout; no uppercase labels.

## Colors

A cold, near-black navy ground under warm bone ink, with four semantic hues and one metallic accent that means "you, acting with authority".

### Primary
- **Ledger Gold** (`gold`): the primary button, the active nav item's icon and tint, the focus ring, text caret, `accent-color` for checkboxes and radios, the selected radio card, the current step, the deciding mark in the ledger, and the tenant monogram. Hover lightens to **Gold Highlight** (`gold-hi`). Text on gold is **Lamp Black** (`gold-ink`), never white.

### Secondary (state)
- **Verdigris** (`valid`, ink `valid-ink`): valid certificates, Can connect, Accepted, Enforcing, a checked switch, completed steps. The `-ink` variant is for text on dark tinted fills.
- **Signal Amber** (`warn`, ink `warn-ink`): expiring, warning severity, stale but still enforced.
- **Revocation Crimson** (`crit`, ink `crit-ink`): revoked, expired, denied, rejected, critical severity, destructive buttons, field errors.
- **Slate Neutral** (`neutral`): informational severity, not enforceable yet, superseded, and the fallback VLAN swatch.

### Tertiary (entity and chart)
- **VLAN inks** (`vlan-blue`, `vlan-violet`, `vlan-teal`, `vlan-orange`, `vlan-amber`, `vlan-green`, `vlan-rose`, `vlan-slate`): identity colours stored on each VLAN. A VLAN wears its colour everywhere it appears (tag swatch, ledger verdict, usage bar), and the colour is never assigned by rank. New VLANs get the first unused colour in this order. The first five are the separable core; green, rose and slate are overflow and don't separate cleanly under colour-vision deficiency. So a VLAN colour never travels without its number.
- **Accept series** (`series-accept`) and **Reject series** (`series-reject`): the only two colours in the hourly authentication chart, validated against the panel surface for lightness, CVD separation and 3:1 contrast. Accept is deliberately deeper than Verdigris so the chart does not shout.

### Neutral
- **Midnight Ground** (`ground`): page background, under the fixed radial glows.
- **Sidebar Navy** (`sidebar`): the sidebar and mobile top bar, as a short vertical gradient.
- **Smoked Glass** (`panel`, opaque equivalent `panel-solid`): every panel. Use `panel-solid` where something must be opaque on top of the panel (sticky table heads, ledger markers sitting over the spine line).
- **Raised Glass** (`raised`, `raised-solid`): default buttons and the selected segment.
- **Overlay Glass** (`overlay`): menus, select lists and search results, always with backdrop blur.
- **Bone Ink** (`ink`, `ink-2`, `ink-3`): primary text; secondary text and ledes; labels, metadata and placeholders.
- **Hairlines** (`line`, `line-2`, `line-3`): row dividers and panel borders; control borders; control hover borders.
- **Hover and Select washes** (`hover`, `select`): row and ghost hover; selected row and active nav tint.
- **Well** (`rgba(6, 9, 17, α)`): the recessed dark fill inside a panel for inputs, code, callouts, secrets and attribute tables. Opacity ranges from 0.3 to 0.7, deeper for secrets.

### Named Rules
**The Gold Is Authority Rule.** Gold marks the action or location that belongs to the operator, and nothing else. It never signals state; a valid certificate is verdigris, not gold.

**The Colour Follows the Entity Rule.** A VLAN's colour is stored on the VLAN and travels with it. Charts never recolour by rank, and the label always names the VLAN as well.

**The Never Colour Alone Rule.** Every state chip, callout and health dot pairs its hue with an icon and a word (Active, Revoked, Can connect, Not enforceable yet).

## Typography

**Display Font:** Hanken Grotesk Variable (self-hosted via @fontsource-variable, falls back to ui-sans-serif, system-ui)
**Body Font:** Hanken Grotesk Variable
**Label/Mono Font:** Red Hat Mono Variable (self-hosted, falls back to ui-monospace)

**Character:** A clean, slightly humanist grotesk with stylistic set 1 on, used at intermediate variable weights (520, 560, 620, 640, 650) rather than the stock 500/600/700, so hierarchy reads through fine weight steps instead of size jumps. The mono is a calm technical face for anything a person must compare character by character.

### Hierarchy
- **Display** (650, 27px, 1.15, −0.022em, balanced): the page title, once per screen. It takes focus on route change.
- **Headline** (640, 16px, 1.3, −0.01em): panel and section titles. Dialog titles use the same face at 18px.
- **Title** (640, 14px, 1.3): sub-sections, empty-state titles.
- **Body** (400, 14px, 1.45): default. Table cells and controls run at 13px; ledes at 13.5px in `ink-2`, capped at 75ch.
- **Small** (400, 12.5px): metadata, hints, ledger detail lines, chart legends.
- **Label** (500, 12px, `ink-3`): field keys in description lists, table headers (540), nav group names, menu group names. Sentence case.
- **Mono** (400, 12.5px to 15px, +0.01em, tabular): serials, MAC addresses, RADIUS reply attributes, hostnames, one-time secrets (14px console, 18px portal).
- **Portal Display** (650, 24px mobile / 28px from 640px): the step title in the enrollment portal. Portal body is 15px at 1.55, ledes 15.5px, inputs 16px.

### Named Rules
**The Type Floor Rule.** Data never goes below 12px. 11px exists only for keyboard keys, the tenant monogram and the portal step number.

**The Tabular Rule.** Any number that can sit above another number (counts, days remaining, VLAN IDs, timestamps, chart axes) uses tabular numerals.

**The Sentence Case Rule.** Labels, headers and nav groups are sentence case in `ink-3`. There are no uppercase tracked labels anywhere in the product.

## Layout

The console is a fixed 264px sidebar beside a fluid main column capped at 1680px. Main padding steps 16px, 24px, 32px across the `sm` and `lg` breakpoints, with 24px (32px at `lg`) above the page header and 64px below the content. In the sidebar only the recent list and navigation scroll; the wordmark, search and account footer stay in place on short screens. Below 1024px the sidebar becomes a 300px left drawer (86vw max) behind a sticky top bar with a menu button, the logo mark, the tenant name and a search button.

Pages open with a page header (title, optional lede, actions right-aligned and wrapping) 28px above content. Screens compose on a 12-column grid with 20px gaps at `lg`; detail screens use a 5:6 split at `xl`. The dashboard is two independent 8/4 stacks (needs action, trend, recent events; then enforcement, failure reasons, VLAN usage, expiring certificates, services), so a short panel never stretches to match its neighbour. Below `lg` the stacks follow each other in that order: reading, focus and visual order always match, and CSS `order` is never used. Panels stack to one column below `lg`. Description lists are two columns from `sm`, three from `xl`, with 24px column and 12px row gaps.

The enrollment portal is a single 640px column with 16px side padding, a 60px top bar, and a card whose padding grows from 20px/18px to 28px/32px at 640px. Actions stack full-width on mobile and line up in a row from 640px. Description lists switch to a 190px key column from 640px.

## Elevation & Depth

Depth is translucency first and shadow second. Panels are 70% opaque navy over the glowing ground, separated by a hairline bone border, and lit by a single inset 1px highlight along the top edge. That edge light is the only place risk colour enters a container: neutral bone by default, verdigris, amber, crimson, gold or slate when the panel carries `data-risk`. Beneath that, each layer carries a long, soft, negative-spread drop shadow that reads as falloff rather than a lifted card. Overlays add backdrop blur.

### Shadow Vocabulary
- **Panel** (`inset 0 1px 0 var(--ee-edge), 0 18px 40px -24px rgba(0,0,0,0.7)`): every panel; the inset line is the risk edge.
- **Menu** (`0 24px 48px -16px rgba(0,0,0,0.75)` with `backdrop-filter: blur(14px) saturate(1.2)`): select lists, dropdowns, search results.
- **Dialog** (`inset 0 1px 0 var(--ee-edge), 0 40px 80px -24px rgba(0,0,0,0.85)`): modal dialogs and the command palette; risk-keyed like panels. Backdrop is `rgba(4,6,12,0.62)` with 3px blur.
- **Sheet** (`-30px 0 60px -30px rgba(0,0,0,0.8)`): the right-hand event sheet.
- **Tooltip** (`0 12px 28px -12px rgba(0,0,0,0.8)`): tooltips and chart tooltips.
- **Focus glow** (`0 0 0 3px rgba(226,194,117,0.18)`): text inputs on focus, with a gold border.

### Named Rules
**The Edge Light Rule.** Risk is spoken by a container's 1px top edge, never by a filled background or a thick side stripe. A panel holding a revoked certificate glows crimson along its top; its body stays smoked glass.

## Shapes

Gently rounded, tightening as elements get smaller: 12px dialogs, 10px panels and portal controls, 9px menus, 8px wells and radio cards, 7px console controls, 6px menu items and segments, 5px chips and tags, 4px keyboard keys, 2.5px VLAN swatches. Full pills appear only for the console stepper and the ledger's circular markers. Borders are always 1px hairlines; dashed borders are reserved for one-time secrets (gold, dashed) and empty states (`line-2`, dashed). Chart bars round only at their data end (4px) and stay square at the baseline.

## Components

### Buttons
Compact, quiet and unmistakable when it matters.
- **Shape:** gently rounded (7px), 32px tall, 12px horizontal padding, 13px at weight 560, 15px icons with a 7px gap. Small is 28px, large 36px, icon-only is square.
- **Default:** raised glass with a `line-2` border; hover darkens to a solid navy and the border steps to `line-3`.
- **Primary:** Ledger Gold with Lamp Black text at weight 620; hover to Gold Highlight. One per view.
- **Ghost:** transparent, `ink-2` text, hover wash. Used for close, back, view toggles and low-weight actions.
- **Danger:** transparent with crimson-ink text and a 45% crimson border; hover fills to 10% crimson. **Danger solid** (filled crimson, white text) is reserved for the final confirm of an irreversible act such as revocation.
- **Busy:** a spinning refresh icon is added before the label, the label stays, and the button disables and sets `aria-busy`.
- **Portal:** the same variants at 48px tall, 10px radius, 15.5px weight 600, 20px padding, and full-width on mobile.

### Chips
- **Style:** 22px tall, 5px radius, 12px weight 560, 13px leading icon, a 10 to 12% tint of the tone with the tone's `-ink` text and no border.
- **Tones:** valid, warn, crit, gold, neutral. Certificate status, outcome, access state and severity each map to a fixed tone and icon (Revoked is crit with a ban icon; Allowed · no certificate is gold).
- **Tags** (AD, Local, group names) are outlined in `line-2` with `ink-2` text, never tinted.

### Cards / Containers
- **Corner Style:** 10px.
- **Background:** Smoked Glass over the ground.
- **Shadow Strategy:** Panel shadow with the risk-keyed top edge (see Elevation & Depth).
- **Border:** 1px `line`.
- **Internal Padding:** 20px in the console; 20px/18px rising to 28px/32px in the portal card.
- **Callouts** sit inside panels: a well background, 8px radius, tone-coloured border and icon, title in weight 600 and body in `ink-2`.

### Inputs / Fields
- **Style:** a recessed well (`rgba(6,9,17,0.45)`), 1px `line-2` border, 7px radius, 34px tall, 13.5px text; placeholders in `ink-3`. Hover steps the border to `line-3`.
- **Focus:** gold border plus the 3px gold glow; no outline.
- **Error:** border to 70% crimson and a 12.5px crimson-ink message announced as an alert.
- **Field label:** 13px weight 600 above the control, "optional" in `ink-3`, hint in small `ink-3` below.
- **Segmented control, select, switch, radio card** share the well and `line-2` border. A checked switch is verdigris; a checked radio card is gold-bordered with a 7% gold wash.
- **Portal inputs** are 48px tall, 10px radius, 16px text.

### Navigation
- **Sidebar:** 264px, a navy gradient with a right hairline. At the top: wordmark with a ⌘K affordance, the tenant switcher (gold monogram, name, domain), and the search field with a `/` key hint. Then Recently viewed, then sentence-case groups (Investigate, Enroll, Configure, Govern, MSP) in 12px `ink-3`.
- **Items:** 32px, 7px radius, 13.5px weight 520 in `ink-2` with 16px `ink-3` icons. Hover adds the wash; the current page gets a 9% gold tint, `ink` text and a gold icon.
- **Mobile:** a sticky top bar and a left drawer that reuses the same sidebar content.

### Command Palette
Search-first entry to everything. Opens with ⌘K (or Ctrl+K) as a wide dialog anchored 12vh from the top. A borderless 15px input over a listbox of grouped results (group names as menu labels), a gold chip naming the current mode when an action such as Issue certificate is in progress, an enter glyph on the active row, and a footer of keyboard hints. `/` focuses the sidebar search at desktop or opens the drawer on mobile.

### Decision Ledger
The signature component. An ordered list on a 1px `line-2` spine: account gate, certificate gate, deny rules, allow rules in precedence, tenant default. Each step has a 22px circular marker (pass: verdigris border and check; fail: crimson border and cross; not used: hairline and dash; decides: gold border, gold wash and stamp), a 13.5px weight 500 title, a small `ink-2` detail and a right-aligned result word. The verdict row ends the spine with a filled marker (verdigris check or crimson ban), "Access-Accept to VLAN [tag]" or "Access-Reject" at 15px weight 600 and the plain-language reason. Unmatched and disabled rules collapse behind a disclosure, and the RFC 3580 reply attributes follow in a mono table set in a well.

### Validity Remaining
Days left on a certificate or CA, right-aligned, tabular, no wrap, with the end date in small `ink-3` beneath. It turns warn-ink or crit-ink as expiry approaches. A revoked certificate shows "Not valid" in `ink-3`, never a countdown.

### One-Time Secret
Mono text on the deepest well with a dashed gold border and select-all, a Copy button, a warn callout stating it will not be shown again, and an acknowledgement checkbox. The dialog cannot be dismissed until the secret is copied or acknowledged.

### Enrollment Progress
In the portal, four equal columns, each a 4px bar over a numbered 18px dot and label. Current is gold, done is verdigris with a check, upcoming is `line-2`. Dots hide below 480px.

## Do's and Don'ts

### Do:
- **Do** put risk on a panel's top edge with `data-risk` (ok, warn, crit, gold, neutral) and keep its body smoked glass.
- **Do** keep a single gold primary per view and reserve gold for operator authority, focus and the deciding step.
- **Do** pair every state colour with an icon and a word, using the fixed tone map in the chip family.
- **Do** show VLANs with their stored identity colour, ID in tabular semibold and name in `ink-2`, everywhere they appear.
- **Do** right-align validity remaining in tabular numerals, and say "Not valid" for revoked certificates.
- **Do** set serials, MACs, reply attributes and secrets in Red Hat Mono.
- **Do** keep console controls at 32 to 36px and portal controls at 44px minimum (48px for buttons and inputs).
- **Do** give every interactive element the 2px gold focus outline at 2px offset (inputs use the gold border and glow instead).
- **Do** use the decision ledger, unchanged, wherever an access decision is explained.
- **Do** honour `prefers-reduced-motion`: transitions and the portal's 320ms step entrance drop to zero.

### Don't:
- **Don't** use gold to mean valid, or verdigris to mean "click here".
- **Don't** fill a panel's background with a state colour or add a thick coloured side stripe; the risk edge is a 1px top light.
- **Don't** colour VLAN bars or swatches by rank or position.
- **Don't** set data below 12px, or use uppercase, letter-spaced labels.
- **Don't** add a third series colour to the authentication chart or reuse VLAN inks for non-VLAN data.
- **Don't** load fonts or assets from a CDN; fonts are self-hosted to satisfy the `font-src 'self'` policy.
- **Don't** introduce new colours or fonts in the enrollment portal; it scales the console's tokens up, it does not fork them.
