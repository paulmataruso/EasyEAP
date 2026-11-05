# Concept B — Modern Network Operations (UI/UX Pro Max)

Source: `design-system/easyeap-concept-b/MASTER.md`. Query "network operations monitoring real-time dashboard", density 9, variance 6, motion 4. Accepted: real-time ops pattern guidance (label telemetry live only with update time + stale state; pause/hide controls for tickers; static snapshot under reduced motion), dark palette with status colours; colour retry "network operations dark cyan" → cyan #22D3EE / #0891B2. Typography retry "technical monitoring dashboard condensed" → Barlow + Barlow Condensed accepted (Cinzel/Josefin rejected as luxury real-estate faces); JetBrains Mono for data.

- **Shell:** 56px icon rail (tooltips + flyout section menus); a persistent **live service strip** across the top (RADIUS req/min, reject rate, PKI/CRL, directory sync age, snapshot age) with update time and stale state; **tenant switcher = pinned-tenant tab strip** (NOC operators watch several tenants) + "all tenants" menu.
- **Dashboard:** dense 3-column ops board — left: live authentication stream (pause/resume, result filter); centre: auth rate per controller as small multiples + failure-reason breakdown; right: VLAN distribution + certificates expiring soonest.
- **Cards & glass:** flat charcoal panels, hairline borders, 6px radius; glass only on the service strip and overlays.
- **Type:** Barlow 13px UI, Barlow Condensed for figures and column headers, JetBrains Mono for serials/MACs.
- **Tables:** compact 32px rows, inline column filters, keyboard row navigation (j/k, Enter), sticky first column.
- **Forms/dialogs:** right-side slide-over drawers for details and edits; modal only for destructive confirmation.
- **Colour:** ground #0B0F14, panel #111821, hairline #1F2A37; text #E5EDF5 / #A9B6C6 / #7F8DA0; primary cyan #22D3EE; ok #34D399, warn #FBBF24, crit #F87171.
- **Signature move:** the service strip — every number carries its age and goes visibly stale.
