#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import json, sys
p = sys.argv[1] if len(sys.argv) > 1 else '.run.json'
d = json.load(open(p))
c = d['columns']
print(f"FEATURE={c['feature']} AGENT={c['agent']} PERF={c['perf']} SCORE={c['score']} working={c['working']}")
print(f"passed {d['counts']['passed']}/{d['counts']['registered']} of manifest {d['counts']['manifest_total']}")
for k, v in d['counts']['by_group'].items():
    print(f"  {k:<9} {v['passed']}/{v['total']}")
perf = d.get('perf')
if perf:
    print("perf workloads:")
    for w in perf['workloads']:
        print(f"   {w['name']:<6} p50={w['p50_ms']} ms p99={w['p99_ms']} points={w['points']} {w.get('error','')}")
    print(f"   points_total={perf['points_total']} perf_p50_us={perf['perf_p50_us']} calibrated={perf['calibrated']}")
fails = [r for r in d['checks'] if not r['ok']]
if fails:
    print(f"\n{len(fails)} failing:")
    for r in fails[:40]:
        print(f"  {r['id']:<32} {r['detail'][:100]}")
