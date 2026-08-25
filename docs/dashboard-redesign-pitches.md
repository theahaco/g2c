# Nido account dashboard — 5 redesign pitches

Five independent design teams each pitched a full redesign of the **assets + recent activity** surface on the account home dashboard, plus future features. Each team ran as a lead-designer → design-critic pipeline (the critic stress-tested feasibility against Nido's real constraints). A design-director pass then ranked and synthesized them.

> Context the teams worked from: Nido is a warm, mainstream-consumer passkey wallet. Hard constraints — curated SEP-42 token list (no holdings-enumeration API), Soroban RPC `getEvents` ~7-day activity window, no fiat price oracle, on-chain passkey verification + relayer (`auth:xdr`).

> **Meta note:** several teams read the live worktree, which already contains the declutter PR (#103) — so a few reference `padding:14px 18px 6px` as "already patched." The director verified the base `.card` rule still ships **zero** padding (the components now add their own), and used that to settle the ranking.

---

## TL;DR — director's ranking

| Rank | Concept | Best for | Verdict |
|------|---------|----------|---------|
| 1 | **The Nest** | Mainstream consumer (default persona) | Only pitch whose *mechanism* IS the brand (warm cushions, no boxes). Almost pure CSS, row builders untouched. |
| 2 | **The Living Ledger** | Activity-first everyday sender | Most intellectually honest; best graftable ideas. "Balances = head of timeline" is the riskiest to keep truthful under `getEvents` gaps. |
| 3 | **The Ledger** | "Is my money okay?" reassurance user | Beautiful minimalism, but hides both lists behind a tap; structural rewrite (removes `.card-grid`) = highest risk at ≥1024. |
| 4 | **Pocket** | A Cash-App-style social-P2P future | Warmest instincts + richest roadmap, but unresolved "XLM shown twice," hides tokens in a horizontal rail. |
| 5 | **Nido Terminal** | Crypto-native power user (NOT default) | Sharpest engineering rigor, but an opt-in 2nd render path that betrays warm positioning; sparkline risks being misread as price. |

**Recommendation:** Build **The Nest**, graft in The Living Ledger's day-separators + honest 7-day horizon, fix the verified `--acc` sub-AA contrast bug in passing, and de-risk the ~5%-luminance cushion-contrast bet on real dim displays in week one.

---

## 1 — The Ledger  *(Radical Minimalism / Progressive Disclosure)*

> One quiet, capped reading column where balance, holdings, and recent events live as a single calm scroll that only unfolds when you reach for it.

**Philosophy.** A consumer opening a wallet wants one answer first — "is my money okay?" — not a two-column dashboard. Don't patch padding onto boxes that shouldn't compete; remove the boxes and let whitespace organize. Two cards become two borderless summary lines under the hero, each one tap from its full self.

**Layout.** Replace the `.card-grid` wrapper with a single capped column (448px mobile, 600px centered desktop, no grid ever); 28px rhythm between zones. **Zone 1** — balance hero kept as the *one* bordered surface. **Zone 2** — two transparent `.ledger-summary` rows: Assets shows a stacked-avatar cluster + "+N" chip; Activity shows a plain-language digest ("Sent 100 XLM · 2h ago"). Expanding either reveals the existing `.row` list in a `--paper-3` well. **Zone 3** — toggled panels below. Owns the load-bearing cost honestly: removing `.card-grid` forces rebuilding the desktop hero card, full-width spans, and panel auto-collapse.

**Key moves.** Delete both card frames (fix crowding by removing the border, not padding a box) · two expand-on-demand summary rows · plain-language Activity digest (needs a new relative-time helper) · holdings as stacked-avatar cluster · expanded rows in a `--paper-3` well · 28px rhythm, single column at every breakpoint.

```
MOBILE
│          Balance            │
│        1,240.50  XLM        │  ← 48px serif hero
│      ⬡ CDEF…8KQ2  ⧉         │
│      ◯ Send  ◯ Receive  ◯ Security
│ ◍◍◍  Assets       4 held  › │  ← borderless summary (no box)
│ ↓  Recent activity          │
│      Sent 100 XLM · 2h  ›   │  ← digest visible — no expand needed
```
```
DESKTOP — single capped 600px column, centered; expands in place, NEVER re-splits into two columns
┌──────────────────────────────────────────┐
│  Balance  1,240.50 XLM  [Send] [Receive]  │  ← the ONE box
│  ⬡ CDEF…8KQ2 ⧉   View on Stellar Expert   │
└──────────────────────────────────────────┘
  ◍◍◍  Assets                 4 held     ›
  ↓   Recent activity   Sent 100 XLM · 2h ›
```

**Future features.** Snapshot line ("4 tokens · nothing moved in 6 days") · Quiet mode (Activity self-recedes when 7d window empty) · Pinned assets (curate the collapsed cluster, localStorage) · Settled-send confirmation in the digest (stash relayer tx hash → short-poll `getEvents`) · Density preference Calm/Open, persisted.

**Risks.** Power users pay a tap each · collapsed digest becomes single source of truth for "did it go through?" (must fail-safe to absolute timestamp) · the "capped column" is a real structural rewrite, riskiest at ≥1024 · home reads as a different design language than Security panels · avatar cluster is weakest on cold load before icons resolve · two same-width rows can read as sparse.

**Effort.** M / M+ — row builders + loaders reused, but NOT purely subtractive (rebuild hero card, spans, panel collapse + new helpers).

---

## 2 — Nido Terminal  *(Data-Dense Portfolio Terminal)*

> An opt-in mode that fuses the two cards into one tight, sortable holdings ledger with a synchronized activity tape sharing a single right-aligned numeric spine. Density via alignment, never crowding.

**Philosophy.** The two-card layout spends the best real estate on ~5 assets / 5 events as 42px hero rows. A power user wants the whole portfolio in one downward glance. The fix is a strict baseline grid: one monospace tabular-figures numeric column shared by assets and activity, fixed row rhythm, sortable headers, exactly two rule weights. Ships as a `Cozy | Terminal` toggle; Cozy stays the default.

**Layout.** Do NOT touch base `.card` (its zero padding is relied on by other sub-cards). Replace the two `.grid-cell`s with ONE `.span-all` terminal surface in Terminal mode. Header strip with honest totals (only XLM is summed — others counted, no oracle). Assets table: `grid-template-columns: 22px 1fr 18ch 92px`, 22px icon chip, code + mono subtitle, a **net-flow sparkline** (balance-delta over the 7d window, explicitly never price), right-aligned tabular BALANCE spine, sortable headers. **Kills** the cross-asset weight/% bar (no value field, no oracle → would fabricate portfolio-share). Activity tape below shares the *exact* right edge — one continuous numeric spine.

**Key moves.** Don't re-fix padding (already patched in the cards) · fuse two cards, shared right-aligned numeric spine · KILL the weight bar (replace with sortable balance + labeled net-flow sparkline) · shrink 42px→22px atoms (density via smaller atoms, not tighter spacing) · tabular-nums monospace · sortable headers re-render in-memory array · fix the `.ricon.acc` bare `--acc` sub-AA contrast trap (use `--acc-ink`/`--good-ink`) · unverified = dot + literal "unverified" text.

```
DESKTOP — single full-width terminal card, one continuous numeric spine on the right
│ PORTFOLIO  7 held · 312,402.115 XLM     [ Cozy | TERMINAL ]      Explorer↗ │
│ CODE                7-DAY                     BALANCE ▾                     │
│ ◢ XLM  stellar.org  ╱╲╱╲╲   +120 Δ          312,402.1150000               │
│ ◢ USDC centre.io    ╲╱──╱    −40 Δ            1,204.5000000               │
│ • SHADY GDEF…9·unverified  ╲╲╲╲╲ +99 Δ           99.0000000               │
│───────────────────────────────────────────────────────────────────────── │
│ RECENT ACTIVITY · last 7 days                              View all 142 →  │
│ ↑ 2h  Sent to GABC…7Q9                                       −100.0000 XLM │  ← --acc-ink (AA)
│ ↓ 5h  Received from alice                                    +500.0000 XLM │  ← --good-ink
   BALANCE col and activity AMOUNT col share ONE right edge ────────────────┘
   7-DAY = net balance MOVEMENT (Δ), explicitly NOT price — there is no oracle.
```
*(Mobile drops the 7-DAY column at ~360px; spine preserved.)*

**Future features.** Net-flow sparklines (balance-delta, never price) · client-side sort + "verified only / moved this week" filter · keyboard nav + ⌘K launcher · watch-only address peek (any C-address, read-only) · copy 7-day tape + holdings as CSV (capped at the 7d window, labeled).

**Risks.** Density is a minority taste — the toggle is load-bearing; the day Terminal becomes default it betrays the brand · the sparkline WILL be read as gains/losses (biggest trust hazard) · a11y genuinely tight (22/11/10px + 6px dot — dot can't be the only unverified signal) · the shared right-edge is fragile across magnitudes/long codes · mobile drops the signature column · a second render path doubles maintenance.

**Effort.** M — reuses in-memory data + existing icon handlers; long poles = tabular alignment across magnitudes/mobile, AA contrast at smaller sizes, maintaining a 2nd render path.

---

## 3 — Pocket  *(Consumer Fintech, Mobile-First Warmth)*

> Your money, your people, your moves. Assets are tappable coin tiles; activity is a chatty, day-grouped feed you scroll like a chat thread.

**Philosophy.** The crowding isn't "two cards," it's "two ledgers a non-crypto person reads like spreadsheets." Keep one warm top-to-bottom story: balance, three fat verbs, a short coin-tile rail, then a human feed. Honest caveat baked in: the feed is NOT all "you sent Alice" — `ActivityItem.kind` is one of six; many rows are account-management events that stay plain-but-friendly (never forced first-person).

**Layout.** Replace the grid with one generously-padded vertical flow (mobile) / 2-col split (desktop). Unify the page gutter to ONE 20px token. **Balance hero** kept (no fabricated USD). **Three fat 60–64px buttons** reusing `.btn`: Send / Receive / Scan-or-Security. **Wallet shelf** — horizontal-scroll rail of 128×96 coin tiles reusing the `.asset-initial` chip; unverified tiles drop the shadow, get an amber `.chip.warn` + short contract id (never a self-reported domain). XLM stays as a de-emphasized first tile. **Activity feed** — borderless day-grouped timeline reusing existing `.row` anatomy; payment titles composed ("You sent 100 XLM") from existing classify output; admin rows stay literal; relative time with absolute kept as tooltip.

**Key moves.** Kill the dual-card grid → one warm story · one 20px gutter token · unify split action UI into three fat buttons · assets as a coin-tile rail · compose payment titles (thin layer, don't touch admin rows) · relative time + absolute tooltip · day-group feed, skip dividers when ≤2 items · demote explorer/view-all to quiet text + ghost button · distinct unverified tile.

```
MOBILE
│        1,240.50 XLM         │  48px Fraunces
│  [⬆ Send][⬇ Receive][▣ Scan]│  3 fat .btn (*gated→Security)
│ Your money            3 ●   │
│ ┌─────┐┌─────┐┌────────╮    │  horiz scroll →
│ │ XLM ││ USDC││ + Add  ┊    │  XLM tile de-emph (=hero)
│ │1,240││ 5.00││  token ┊    │
│ Recent activity             │
│ ── Today ─────────────────  │
│ ⬆ You sent 100 XLM   −100   │  payment: chatty
│ ⬇ You received 5 USDC +5.00 │  teal +, --good
│ ── Yesterday ─────────────  │
│ • Updated account keys   ·  │  ADMIN row: plain (no fake 1st-person)
│ [   View full history ↗   ] │
```

**Future features.** Scan-to-pay QR (the headline everyday verb) · tap-a-tile drill-down `.sheet` (component exists) · last-7-days recap strip (counts + per-asset deltas, never fiat) · recent-people shelf from counterparties (registry reverse-maps to `.nido` names) · Add-token by paste/scan (curated-list escape hatch; stays unverified).

**Risks.** Horizontal rail hides off-screen tokens · "chatty feed" is weaker than it sounds (many admin rows) · relative time loses precision on touch (no hover) · XLM appears twice by construction · bare paper reduces "serious ledger" trust · three fat buttons assume Scan ships (else it's the old action set reshaped) · the "fix padding" framing is partly already done.

**Effort.** M — mostly markup/CSS reusing existing tokens; new = coin-tile component, day-group/sparse feed logic, XLM-duplication decision, payment-title compose layer.

---

## 4 — The Living Ledger  *(Unified Timeline / Activity-First)*  — runner-up

> One scrolling timeline of your Nido's life, with balances as a pinned, breathing header instead of a competing card.

**Philosophy.** The two lists tell the same story twice: balances are the running total of the activity above them. Reject the split. Current state (balances) pins at the top as a header; below it, the one stream of events that produced it. Solve crowding by DELETING one card — there's no second card to fight the first.

**Layout.** Remove both `.card` cells + the two-column split; one full-width `.span-all` ledger. **Part A — Balances header:** NOT a `.card` — a band on `--paper-2` closed by a single bottom hairline (continuation of the hero, not a box). XLM stays the hero; other assets become compact balance chips (new ~6-line renderer reusing only the `.asset-initial`/`.asset-icon` pattern — `assetRowHtml` is the *wrong* primitive, it emits a full `.row`). **Part B — Timeline:** one continuous `.row` list with lightweight day separators, a pinned "you are here · current balance" marker, and direction-keyed amount colors (one small edit to `activityRowHtml`). Ends in a designed `.empty` horizon: "That's the last 7 days → full history on Stellar Expert."

**Key moves.** Delete both card boxes → one borderless `.span-all` ledger · demote assets to a ~72px balance-chip header (XLM stays hero) · color-key amounts + "you are here" marker · day separators as `--mut` eyebrows with no divider (leans on `.row:first-child{border-top:none}`) · sticky single "Activity" label · replace BOTH trailing links with one honest 7-day horizon footer · unify loading/empty (scope empty to activity since XLM is always held) · unverified = quiet `--warn` dot.

```
DESKTOP — one centered ~620px ledger column (no side-by-side split)
│  [U] USDC 42.00  [E] EURC 10.00  [?] TKN 5.0•      On explorer →  │  chip band (no box)
│  ──────────────────────────────────────────────────────────────  │  hairline
│  ACTIVITY  (sticky)                                               │
│  ·· current balance — you are here                                │
│  Today                                                            │
│  (↓ in)  Received   from C9F2…1A   2h ago     +100 XLM            │  good-ink
│  (↑ out) Sent       to alice.nido  5h ago     −12 USDC            │  ink
│  Yesterday                                                        │
│  (•)     Added a signer  passkey   18h ago        —               │
│        ┌──── dashed .empty horizon ────┐                          │
│        │ That's the last 7 days.       │                          │
│        │ [ Full history on Expert ↗ ]  │                          │
└────────────────────────────────────────────────────────────────────┘
```

**Future features.** Per-asset "as-of" running trail / checkbook register (walks `getEvents` deltas back from the live SAC read — honest hazard: a dropped event poisons every value below the gap, so render only the topmost contiguous reconciling run) · fold low-signal admin runs ("Security & settings · 3 changes") · counterparty labels via the registry (free reverse-map) · pull-to-refresh as "fast-forward to live head" · tap a row → asset-denominated shareable receipt (no-oracle is a feature: stays truthful).

**Risks.** Asset-watchers lose the tidy table (chips hide issuer/domain) · "View all →" deletion ships users off-brand to the explorer for >7d (keep the in-app `/account/activity/` too) · the 7-day horizon is now *advertised*, may read as "this wallet forgets" · the "you are here" marker implies a completeness `getEvents` can't guarantee (needs "live as of HH:MM") · single-column abandons desktop density · heavier client-side composition on the brittle injected-HTML path · the unverified dot may under-warn.

**Effort.** M — markup/CSS reorg + moderate contained JS; reuses loaders, `.row/.chip/.empty/.skeleton`; new = chip-band renderer + day-grouped renderer + one-line direction-color edit.

---

## 5 — The Nest  *(Card-Free Spatial / Brand-Forward)*  — **WINNER**

> Assets rest as warm cushioned objects nested in one continuous paper habitat; activity runs as a quiet twig-timeline down the floor. No boxes, no fences — separation by tone and air alone.

**Philosophy.** The remaining crowding is a BOX problem: two bordered, radiused, shadowed cells read as generic "two stat cards," and inside each, hairline dividers fence every row into a tight ledger. The Nest removes the cages: the whole region becomes one continuous `--paper` surface where Assets are warm cushioned objects and Activity is a quiet thread on the floor. Ownable, illustration-ready, impossible to mistake for a stat-card wallet.

**Layout.** Replace the two `.card` cells with one uncarded `.nest-floor` on continuous `--paper` — NO border, radius, or shadow; separation purely spatial. **Assets ("In your nest"):** held assets become `.perch` items reusing `assetRowHtml` **verbatim** (only `.row`→`.perch` class + CSS change) — tinted `--paper-3` rounded lozenges, 8px apart; CODE in `--disp` serif, domain in mono beneath, balance right-aligned tabular. Unverified gets a `--warn-soft` **amber** cushion (NOT white `--paper-2`, which reads cleaner-not-cautious on cream) + inline `.chip.warn`. XLM stays the hero, not a perch. **Activity ("Lately"):** `.trace` items reusing `activityRowHtml` verbatim, NO per-row hairline — separated by 18px air + ONE `--line-soft` thread running vertically through the icon column (a connecting twig). Desktop ≥1024 overrides the symmetric grid to asymmetric `1.4fr 1fr` sharing one paper floor with a single bounded spine.

**Key moves.** Delete the two card boxes (warmth + kill the "two stat cards" read) · assets as `--paper-3` cushions (density reads as abundance) · unverified = amber cushion + chip (preserves the anti-spoof invariant via tone) · row hairline → 18px air + one icon-column thread · CODE in serif, balance stays mono tabular (explicit `tabular-nums`) · one earned line: the ≥1024 column spine, bounded to the shorter column · demote both escape hatches to quiet trailing ghosts.

```
MOBILE  (no border IRL — edge of paper)
│  IN YOUR NEST   see all →   │  ← section-label + ghost link
│ ╭───────────────────────╮   │  --paper-3 cushion, NO border
│ │ (U) USDC          812. │   │     CODE in --disp serif 16px
│ │     centre.io          │   │     domain --mono 12px --mut
│ ╰───────────────────────╯   │
│ ▓───────────────────────▓   │  --warn-soft AMBER cushion = caution
│ ▓ (X) XYZ [unverified]  ▓   │     + inline .chip.warn
│ ▓     CXYZ…9F2          ▓   │
│  LATELY        view all →   │
│  │                          │  ← single --line-soft thread
│ (↓) Received 100 XLM  +100 │     through icon column,
│  │  Jun 16, 2:14 PM         │     18px air, NO row borders
│ (↑) Sent 25 USDC      −25  │
│  ⋮ older twigs rest on Stellar Expert ↗   ← thread fades at ~7d horizon
```
```
DESKTOP — assets ~58% cushions | activity ~42% timeline, one paper floor, ONE bounded spine
│  IN YOUR NEST        see all →   ¦   LATELY        view all →   │
│ ╭── USDC  812.40 ──╮              ¦  (↓) Received 100 XLM   +100 │
│ ╭── AQUA  5,000  ──╮              ¦  (↑) Sent 25 USDC      −25  │
│ ▓── XYZ [unverified] 0.40 ──▓     ¦  (•) Approved spend          │
│   grid-template-columns: 1.4fr 1fr  ¦  ⋮ older on Expert ↗      │
```

**Future features.** Twig-timeline horizon (fade the thread → "older twigs rest on Stellar Expert ↗") · empty-nest illustration states (replaces the dashed `.empty` box that contradicts the card-free philosophy) · settling animation (cushions drop into place, gated by `prefers-reduced-motion`) · curated-coverage perch nudge ("Is this yours? Tokens we recognize show a verified domain") · pin-to-nest drag reorder (localStorage; needs keyboard a11y fallback).

**Risks.** The central bet: `--paper` #FFF8F0 vs `--paper-3` #FBEFE0 differ by only ~5% luminance — cushions may vanish on dim/sunlit screens (test on real devices week one) · borderless removes the "tappable group" affordance (needs designed hover/active) · keep the desktop hero box in v1 (un-boxing it is a separate riskier experiment) · serif balances jitter on long values (keep mono + explicit `tabular-nums`) · the vertical thread may read as decoration · cushions are less dense for 15–20-token whales · the bounded two-column spine is fragile under lopsided content.

**Effort.** M — almost entirely CSS in the two components' `is:global` blocks; `assetRowHtml`/`activityRowHtml`, loaders, and `rowHtml.ts` untouched.

---

## Director's synthesis

**Recommendation — pursue The Nest**, because Nido is explicitly a warm, mainstream-consumer passkey wallet, *not* a dev/power tool. Of the five, only the Nest's core mechanism — borderless cushions + airy twig-timeline, separation by tone and air — is a literal expression of that brand rather than a layout that merely tolerates it. It's also lowest-risk to build (row builders verbatim, keeps `.card-grid`) and its one factual error (claiming the padding was "already patched") cuts in its favor: deleting the box fixes the still-present base-`.card` crowding at its root regardless.

**Grafts onto the winner:**
1. **Day-group separators** (from Living Ledger) — quiet `--mut` eyebrows, no divider of their own; the single best activity-side idea, drops cleanly onto the twig-timeline.
2. **Honest 7-day horizon footer** (Living Ledger / Nest) — turn the `getEvents` retention limit into intentional design. BUT keep the in-app `/account/activity/` "View all →" *and* add the horizon note (don't ship users off-brand to the explorer for everything >7d).
3. **Relative time + absolute tooltip** (Pocket / Ledger) — friendlier default, preserves the forensic record. Needs a small relative-time helper (`activityRowHtml` renders absolute only today).
4. **Fix the `--acc` contrast bug** (Terminal) — `.ricon.acc` uses bare `--acc`, flagged sub-AA by the project's own audit. Any redesign touching direction glyphs must switch out/contract → `--acc-ink`, in → `--good-ink`. Fix in passing regardless of which design wins.
5. **Unify the two empty states** (Living Ledger) — since native XLM is always held, the honest empty is "no recent ACTIVITY in 7 days," never "no assets."

**Roadmap themes worth pursuing regardless of which redesign wins:**
- **Per-asset drill-down** (tile/cushion/row → detail sheet, filtered by `item.asset`; reuses the existing `.sheet`). Each detail view needs a "no recent activity for this token" state (held-but-idle tokens).
- **Counterparty / "recent people" humanization** — exploit `item.counterparty` + the already-imported registry resolver to reverse-map C-addresses → `.nido` names for free. Bounds: ~7d of people without localStorage; raw addresses need a contacts store that doesn't exist yet.
- **Truthful 7-day recap / snapshot line** — counts + per-asset deltas only, **never** a fabricated USD figure (`money.ts` refuses fiat, no oracle).
- **Local personalization without a backend** — pinned/reordered assets in localStorage (per-device); drag needs a keyboard a11y fallback.
- **Curated-list escape hatch** — "Add token" by paste/scan via a single SAC Balance probe; any added token stays unverified-flagged (anti-spoofing).
- **Honest send-confirmation loop** — stash the relayer tx hash, short-poll `getEvents` on home load; mandatory timeout fallback to "Submitted — check explorer" given RPC indexing lag.
