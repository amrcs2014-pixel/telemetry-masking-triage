"""Paper A: build triage bundles from AIT-ADS alerts.

A bundle = alerts of one scenario in [anchor-30 s, anchor+90 s], grouped into at most 8 lines
(same rule + same identifiers -> one line with a count), in time order. Anchors:
  * attack: per (scenario, stage) up to N_ATT anchors spread over that stage's attack alerts;
  * benign: per scenario N_BEN anchors outside all attack windows, round-robin over rules.
Ground truth per bundle: verdict (escalate if any attack alert), stage (majority stage of the
attack alerts), involved hosts (attacker IP if present + hosts that logged attack alerts),
containment target (attacker if present, else the first victim host, 'none' if benign) and an
entity inventory with types and attributes (zone, monitored asset, attacker).
Output: data/a_bundles.json
"""
import json, random, re, collections
from datetime import datetime, timezone
from pathlib import Path
import pandas as pd
from a_entities import tag, valid_ip, ip_zone

D = Path(__file__).resolve().parents[1] / 'data'
N_ATT, N_BEN, MAXL, RAWMAX = 5, 20, 8, 160
SEED = 19


def render(r):
    t = datetime.fromtimestamp(r.ts, timezone.utc).strftime('%m-%d %H:%M:%S')
    host = r.host or r.agent_ip
    raw = r.raw if len(r.raw) <= RAWMAX else r.raw[:RAWMAX] + '...'
    return f"{t} | {r.ids} | {r.rule} | host={host} | {raw}"


def main():
    df = pd.read_pickle(D / 'a_alerts.pkl')
    meta = json.load(open(D / 'a_meta.json'))
    rng = random.Random(SEED)
    bundles = []
    for sc, d in df.groupby('scenario', sort=False):
        d = d.sort_values('ts').reset_index(drop=True)
        ts = d.ts.values
        attacker = meta[sc]['attacker']
        agents = set(d.agent_ip) - {''}
        host2ip = {}
        for h, a in zip(d.host, d.agent_ip):
            if h and a and h not in host2ip:
                host2ip[h] = a
        known_hosts = sorted({h for h in d.host if h} | {h for hs in d.hosts for h in hs if '.' not in h})
        known_users = sorted({u for us in d.users for u in us})
        org = collections.Counter(h.split('.', 1)[1] for hs in d.hosts for h in hs if sc in h and '.' in h)
        org_dom = org.most_common(1)[0][0] if org else sc
        anchors = []
        for stage, g in d[d.attack].groupby('stage'):
            idx = g.index.values
            k = min(N_ATT, len(idx))
            pick = [idx[int(i * len(idx) / k)] for i in range(k)]
            anchors += [(i, 'attack') for i in pick]
        ben = d[(d.step == '')]
        by_rule = {r: list(g.index.values) for r, g in ben.groupby('rule')}
        rules = list(by_rule); rng.shuffle(rules)
        picked = []
        while len(picked) < N_BEN and rules:
            for r in list(rules):
                if not by_rule[r]:
                    rules.remove(r); continue
                picked.append(by_rule[r].pop(rng.randrange(len(by_rule[r]))))
                if len(picked) >= N_BEN:
                    break
        anchors += [(i, 'benign') for i in picked]
        for ai, kind in anchors:
            t0 = ts[ai]
            lo, hi = ts.searchsorted(t0 - 30), ts.searchsorted(t0 + 90, 'right')
            w = d.iloc[lo:hi]
            groups = collections.OrderedDict()
            for j, r in w.iterrows():
                key = (r.rule, tuple(r.raw_ips), tuple(r.users), r.host)
                groups.setdefault(key, []).append(j)
            anchor_key = next(k for k, v in groups.items() if ai in v)
            keys = sorted(groups, key=lambda k: abs(ts[groups[k][0]] - t0))
            keys = [anchor_key] + [k for k in keys if k != anchor_key]
            keys = sorted(keys[:MAXL], key=lambda k: ts[groups[k][0]])
            lines, att, stages, victims = [], 0, collections.Counter(), []
            for k in keys:
                js = groups[k]; r = d.loc[js[0]]
                s = render(r) + (f' (x{len(js)})' if len(js) > 1 else '')
                lines.append(s)
                a = [d.loc[j] for j in js if d.loc[j].attack]
                if a:
                    att += len(a); stages.update(x.stage for x in a)
                    v = r.agent_ip if r.agent_ip else host2ip.get(r.host, '')
                    if v and v != attacker and v not in victims:
                        victims.append(v)
            text = '\n'.join(lines)
            spans = tag(text, known_hosts, known_users)
            ents = {}
            for s, e, t, v in spans:
                if t == 'ip':
                    canon = v; zone = ip_zone(v); mon = v in agents
                elif t == 'host':
                    canon = host2ip.get(v, 'host:' + v); zone = 'internal'; mon = v in host2ip
                elif t == 'domain':
                    canon = 'dom:' + v.lower(); zone = 'internal' if v.lower().endswith(org_dom) else 'external'; mon = False
                else:
                    canon = t + ':' + v; zone = 'internal'; mon = False
                ents.setdefault(v, dict(type=t, canon=canon, zone=zone, monitored=bool(mon),
                                        attacker=(canon == attacker)))
            present = {x['canon'] for x in ents.values()}
            verdict = 'escalate' if att else 'close'
            stage = stages.most_common(1)[0][0] if att else 'benign'
            involved = ([attacker] if (att and attacker in present) else []) + [v for v in victims if v in present]
            contain = (attacker if attacker in present else (involved[0] if involved else 'none')) if att else 'none'
            bundles.append(dict(id=f'{sc}-{len(bundles):04d}', scenario=sc, anchor_kind=kind, text=text,
                                n_lines=len(lines), n_alerts=int(sum(len(groups[k]) for k in keys)),
                                verdict=verdict, stage=stage, involved=involved, contain=contain,
                                attacker=attacker, org_domain=org_dom, entities=ents,
                                known_hosts=known_hosts, known_users=known_users))
        print(sc, 'bundles', sum(b['scenario'] == sc for b in bundles), flush=True)
    seen, out = set(), []
    for b in bundles:  # drop exact duplicate windows
        if b['text'] in seen:
            continue
        seen.add(b['text']); out.append(b)
    json.dump(out, open(D / 'a_bundles.json', 'w'), indent=0)
    c = collections.Counter((b['verdict'], b['stage']) for b in out)
    print(len(out), 'bundles'); [print(' ', k, v) for k, v in sorted(c.items())]
    print('mean lines', sum(b['n_lines'] for b in out) / len(out),
          'mean chars', sum(len(b['text']) for b in out) / len(out))
    print('benign-anchor bundles that contain attack alerts:', sum(b['anchor_kind'] == 'benign' and b['verdict'] == 'escalate' for b in out))


if __name__ == '__main__':
    main()
