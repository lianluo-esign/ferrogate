# SOC 2 Type II Audit: Scoping Recommendation

Follow-up from [#165](https://github.com/lianluo-esign/ferrogate/issues/165), which
documented FerroGate's existing security controls (see
[`security-controls.md`](security-controls.md)) but explicitly stopped short of
pursuing a third-party attestation. This page records the recommendation asked
for by [#174](https://github.com/lianluo-esign/ferrogate/issues/174): audit
path, rough cost/timeline, vendor options, and the evidence/tooling gaps that
would need to close before an audit could realistically start. It is a
recommendation for a go/no-go decision, not a commitment to pursue certification.

## Recommended path: Type I readiness, then Type II

- **Type I** (design-only, point-in-time): confirms the *design* of controls is
  adequate as of a single date. Typical audit fee **$5K–$20K** for a small
  SaaS company, often preceded by a **$5K–$15K** readiness/gap assessment.
- **Type II** (operating effectiveness over an observation window, typically
  3–6 months for a first audit): confirms controls actually *operated* as
  designed over that window. Typical audit fee **$12K–$30K** for a small/mid
  company on top of Type I readiness spend.
- **All-in first-year budget**: realistically **$20K–$60K** including audit
  fees, readiness support, compliance tooling, and legal review of customer-
  facing contract language — before counting internal engineering time spent
  producing evidence.
- Year two costs typically drop **30–50%** once policies, tooling, and
  evidence-collection habits are established and only the annual re-audit and
  tooling subscription remain.

Going straight to Type II without a separate Type I engagement is viable if a
customer doesn't specifically require a Type I report first and controls are
already operating consistently enough to capture evidence reliably over the
window — worth confirming directly with whichever auditor is engaged, since
some will bundle a lightweight readiness pass into the Type II engagement.

Sources: [Drata](https://drata.com/learn/soc-2/cost),
[Sprinto](https://sprinto.com/blog/soc-2-audit-cost/),
[Thoropass](https://www.thoropass.com/blog/soc-2-audit-cost-a-guide),
[Skedda](https://www.skedda.com/insights/soc-2-type-2).

## In-house vs. compliance-automation vendor

Several competitors surveyed in the original commercial gap analysis (Bifrost,
Portkey, TrueFoundry, API7) appear to run their published Trust Center pages
through a compliance-automation platform rather than manual evidence
collection. The three mainstream options:

| Vendor | Est. year-one cost | Best fit |
| --- | --- | --- |
| **Vanta** | ~$30K–$50K incl. first audit; ~$10K–$15K platform base | Fastest setup, most first-time-SOC-2 startups default here; access reviews are a paid add-on |
| **Drata** | ~$25K–$50K incl. $10K–$25K implementation fee | Engineering-heavy teams that want evidence-collection depth and unlimited seats |
| **Secureframe** | $7.5K+ (scales with framework count) | Teams that want a more guided, advisory-inclusive experience over raw integration breadth |

Below ~50 employees and a single-framework (SOC 2 only) scope, budget
alternatives (Sprinto, Scrut, ComplyJet) usually beat all three on price at the
cost of narrower integration/auditor-network coverage.

**Recommendation**: engage one of Vanta/Drata/Secureframe rather than running
evidence collection by hand — at FerroGate's current team size, the ~150–300
hours of manual evidence work these platforms replace is a bigger cost than the
platform fee itself. Vanta is the default pick unless whoever owns this wants
Drata's deeper evidence customization; Secureframe is worth a look only if
advisory hand-holding is valued over integration breadth.

Sources: [Drata](https://drata.com/learn/compare/secureframe-vs-vanta-vs-drata),
[Secureframe](https://truvocyber.com/blog/soc-2-audit-guide-drata-vanta),
[Sector Post](https://www.thesectorpost.com/compliance/soc2/best-vendors).

## Gaps in `security-controls.md` that need evidence/tooling before an audit starts

A SOC 2 audit tests **operating evidence**, not just the presence of a control.
Cross-referencing today's [`security-controls.md`](security-controls.md)
against the Trust Services Criteria (Security is mandatory; Availability,
Confidentiality, Processing Integrity, Privacy are elected per engagement),
the following are gaps an auditor would flag before/during a Type II
observation window — none of these exist anywhere in the repo today:

- **Incident-response runbook.** No written IR policy, severity classification,
  or on-call escalation path exists in this repo. `SECURITY.md` documents the
  *inbound* vulnerability-disclosure process but not an internal incident
  playbook (detection → containment → notification → postmortem). Needed for
  CC7 (System Operations) evidence.
- **Access-review cadence.** RBAC ([#162](https://github.com/lianluo-esign/ferrogate/issues/162))
  and SCIM deprovisioning ([#161](https://github.com/lianluo-esign/ferrogate/issues/161))
  give the *mechanism* to grant/revoke access, but there is no documented
  periodic review process (e.g. quarterly attestation that current
  role/binding grants are still appropriate) or audit trail of such reviews.
  Needed for CC6 (Logical Access).
- **Background-check / onboarding-offboarding policy** for anyone with
  production access (repo, cloud console, Supabase project, secrets). Nothing
  in this repo addresses personnel security at all — this is an HR/ops
  artifact, not a code change.
- **Change-management evidence trail.** CI enforcement
  (`.github/workflows/rust-quality.yml`) gives automated evidence for code
  quality gates, but there's no documented policy tying PR review + CI green
  + deploy approval together as a formal change-management control an auditor
  can point to.
- **Vendor/subprocessor risk register.** Supabase, the LLM providers proxied
  through FerroGate, and any payment processor (see
  [#169](https://github.com/lianluo-esign/ferrogate/issues/169)) are all
  subprocessors once FerroGate is sold as a hosted product. No subprocessor
  list or vendor-risk-assessment process exists yet.
- **Business continuity / disaster recovery plan.** Cluster deployment
  (`docs/cluster-deployment.md`) covers *how* to run FerroGate resiliently,
  but there's no written BC/DR plan with defined RTO/RPO targets and a tested
  recovery procedure — auditors expect the plan and evidence it was exercised,
  not just resilient architecture.
- **Formal risk-assessment process.** No documented, recurring
  (e.g. annual) risk assessment exists; `security-controls.md` is a
  point-in-time capability inventory, not a risk register with likelihood/
  impact scoring reviewed on a cadence.

None of the above requires new FerroGate *code* — they're organizational/
policy artifacts a compliance-automation vendor typically templates and helps
populate. The gap is real but shouldn't be read as "the product isn't secure
enough"; it's "the paperwork proving operation over time doesn't exist yet,"
which is exactly what a Type II observation window is for.

## Recommendation

1. **Go** — but start with Vanta (or Drata) readiness onboarding rather than
   engaging an auditor directly; the platform's control-mapping wizard will
   surface the exact evidence gaps above against FerroGate's actual
   infrastructure, which is more precise than guessing from this doc alone.
2. Budget **$20K–$40K** for a first Type I → Type II path within 6–9 months,
   contingent on closing the incident-response, access-review, and BC/DR
   policy gaps first — these are cheap (documentation + process, not
   engineering) and block the audit clock from starting otherwise.
3. Revisit GDPR/HIPAA-specific attestations only after SOC 2 Type II is in
   hand — SOC 2 is the baseline every competitor surveyed already holds, and
   the other frameworks are additive asks from a narrower set of prospects.
4. If greenlit, this issue should be superseded by a scoped implementation
   epic with concrete milestones (vendor selected, readiness assessment
   complete, Type I report issued, Type II observation window start/end,
   Type II report issued), per #174's acceptance criteria.
