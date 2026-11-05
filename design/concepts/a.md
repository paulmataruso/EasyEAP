# Concept A — Dark Glass Enterprise (UI/UX Pro Max)

Source: `design-system/easyeap-concept-a/MASTER.md` (+ `pages/dashboard.md`). Query "enterprise security admin dashboard dark glassmorphism", density 7, variance 4, motion 3. Accepted: Glassmorphism style, slate palette with status-green accent, Fira Sans + Fira Code ("Dashboard Data" pairing), effects "backdrop blur 10–20px, 1px white/20 border, light reflection, z-depth". Rejected: the "Real-Time / Operations Landing" marketing section pattern (this is an app, not a landing page).

- **Shell:** full-height frosted left sidebar (≈248px) with the brief's groups (Overview / Identity / Certificates / Network / System), icons + labels, counts or status dots where useful; top bar with the **tenant switcher as a combobox** (tenant name + health dot + domain), global search, admin menu.
- **Dashboard:** a band of four KPI glass panels each with its 24h/30-day history; then 8/4 split: authentication success chart (hourly accept vs reject) + service health stack (RADIUS / PKI / Directory / Snapshot); then 6/6: recent authentications table and certificate activity timeline.
- **Cards & glass:** frosted panels (fill white 4–6%, blur 16px, 1px white/10 border, 1px top highlight), 12px radius; ground #0F172A with two very soft, controlled radial fields (indigo, teal) so the glass has something to refract — not vibrant.
- **Type:** Fira Sans (14px body, 600 headings); Fira Code only for serials, MACs, IPs, DNs.
- **Tables:** sticky glass header, 44px rows, status pills with icons, row actions on hover + overflow menu.
- **Forms/dialogs:** centered glass modal dialogs; multi-step actions as a stepper inside the modal.
- **Colour:** text #F8FAFC / #CBD5E1 / #94A3B8; accent/CTA #22C55E with dark text; info #38BDF8; warning #F59E0B; danger #EF4444.
- **Signature move:** "glass depth = scope" — platform (MSP) layer, tenant layer and record layer sit at three distinct glass depths, so you always know which scope an action affects.
