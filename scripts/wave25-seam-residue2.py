#!/usr/bin/env python3
"""Wave-25 seam pass, RESIDUE 2 — the last three rows, each against its REAL seam.

The inherited `wave25-seam-residue.py` (a copy of wave 23's) mutates `CP-C13` by
leaving the `/version` route REGISTERED and only changing the document it
answers. That is not CP-C13; it is `CP-C13b`, the strictly narrower sub-seam
`MOUNT-SEAMS.md` already records as knowingly unproven — so its GREEN was correct
and expected, not a finding. Re-run against the registration itself (`MUT-1`,
anchor gone) it is RED.

`CP-T3` and `MCP-T8` failed the generic driver for a related reason: the correct
mutation for a toml row is `MUT-4`, *the whole stanza removed*. Commenting one
line of a `[[d1_databases]]` table leaves a partially-valid stanza that changes
nothing a Worker can observe.

Protocol is identical to the other two drivers: sha256 -> apply -> grep the
marker back off disk REQUIRING THE ORIGINAL TEXT ABSENT -> run only the tests the
row names -> restore -> require byte-identity.
"""

import hashlib, json, os, re, shutil, subprocess
ROOT="/home/dev/ferrogate-ts"; BAK="/tmp/wave25-residue2"; os.makedirs(BAK,exist_ok=True); M="MUTW25"
MUT=[
 ("CP-C13","apps/control-plane/src/index.ts",
  'app.get("/version", (c) =>\n  c.json({\n    api: PUBLIC_API_MAJOR,\n    operations: EXPECTED_CONTROL_PLANE_OPERATION_COUNT,\n    registered: CONTROL_PLANE_OPERATIONS.length,\n    groups: CONTROL_PLANE_GROUPS.length,\n  }),\n);',
  f'/* {M}_CP_C13 the /version REGISTRATION itself is removed (MUT-1, anchor gone) */',
  "the /version route is never registered on the exported control-plane app"),
 ("CP-T3","apps/control-plane/wrangler.toml",
  '[[d1_databases]]\nbinding = "DB"\ndatabase_name = "ferrogate-control"\ndatabase_id = "PLACEHOLDER_SET_AT_DEPLOY_TIME"\nmigrations_dir = "../../sql/d1-ts/control"',
  f'# {M}_CP_T3 the whole [[d1_databases]] stanza is removed (MUT-4)',
  "the control plane declares NO D1 database at all"),
 ("MCP-T8","apps/mcp/wrangler.toml",
  '[[d1_databases]]\nbinding = "DB"\ndatabase_name = "ferrogate-control"',
  f'# {M}_MCP_T8 the [[d1_databases]] header + binding are removed (MUT-4)\n[__mutw25_removed_d1]\nbinding_removed = "DB"',
  "apps/mcp declares no DB binding, so durable auth/approvals cannot resolve"),
]
def sha(p):
  return hashlib.sha256(open(p,'rb').read()).hexdigest()
res=[]
for rid,rel,old,new,note in MUT:
  p=os.path.join(ROOT,rel); t=open(p,encoding='utf-8').read(); n=t.count(old)
  if n!=1:
    print(f"{rid} NOT-UNIQUE ({n})"); res.append(dict(id=rid,status="NOT-UNIQUE",occurrences=n)); continue
  before=sha(p); shutil.copy2(p,os.path.join(BAK,rid+".bak"))
  open(p,'w',encoding='utf-8').write(t.replace(old,new,1))
  d=open(p,encoding='utf-8').read(); marker=f"{M}_{rid.replace('-','_')}"
  if marker not in d or old in d:
    shutil.copy2(os.path.join(BAK,rid+".bak"),p); print(f"{rid} MUTATION-DID-NOT-LAND"); res.append(dict(id=rid,status="MUTATION-DID-NOT-LAND")); continue
  pr=subprocess.run(["bun","scripts/seam-proof.mjs","--id",rid,"--run"],cwd=ROOT,capture_output=True,text=True,timeout=2400)
  o=pr.stdout+pr.stderr; m=re.search(rf"^{re.escape(rid)}\s+(GREEN|RED|NO-GATE|NO-FILE)\s",o,re.M)
  gate=m.group(1) if m else "UNKNOWN"
  shutil.copy2(os.path.join(BAK,rid+".bak"),p); r=sha(p)==before
  st="RED" if gate=="RED" else ("GREEN-UNPROVEN" if gate=="GREEN" else gate)
  res.append(dict(id=rid,file=rel,status=st,behaviour=note,restored_byte_identical=r))
  print(f"{rid:9s} {st:15s} restored={r}  — {note}")
json.dump(res,open("/tmp/wave25-residue2-results.json","w"),indent=1)
