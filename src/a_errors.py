"""Paper A: what the analyst chose to contain on attack bundles, per model and scheme.
Categories: attacker (correct when the attacker is visible), victim (a host that logged attack alerts),
other host (an identifier in the bundle that is neither), unresolved (string not mapping to any host),
none; 'other_external' counts the 'other host' choices that are internet hosts. Output: results/a_errors.json
"""
import json, glob, collections
from pathlib import Path
from a_score import resolver, TYPELAB

W = Path(__file__).resolve().parents[1]
D, R = W / 'data', W / 'results'


def main():
    B = {b['id']: b for b in json.load(open(D / 'a_bundles.json'))}
    maps = json.load(open(D / 'a_maps.json'))
    out = collections.defaultdict(collections.Counter)
    for f in sorted(glob.glob(str(R / 'a_gen' / '*.jsonl'))):
        for l in open(f, encoding='utf-8'):
            x = json.loads(l)
            b = B[x['bundle']]
            if b['verdict'] != 'escalate' or b['attacker'] not in {e['canon'] for e in b['entities'].values()}:
                continue  # only bundles in which the attacker is visible
            try:
                c = str(json.loads(x['text']).get('contain', 'none')).strip()
            except Exception:
                c = 'none'
            if c.lower() in ('none', '', 'null', 'n/a'):
                cat = 'none'
            else:
                smap = {k: (None if TYPELAB.fullmatch(k) else v) for k, v in maps[x['id']].items()}
                h = resolver(b, smap)(c)
                victims = set(b['involved']) - {b['attacker']}
                cat = ('unresolved' if h is None else 'attacker' if h == b['attacker'] else
                       'victim' if h in victims else 'other host')
            out[f"{x['model']}|{x['scheme']}"][cat] += 1
            if cat == 'other host' and any(e['canon'] == h and e['zone'] == 'external' for e in b['entities'].values()):
                out[f"{x['model']}|{x['scheme']}"]['other_external'] += 1  # subset of 'other host'
    res = {k: dict(v, n=sum(c for kk, c in v.items() if kk != 'other_external')) for k, v in sorted(out.items())}
    json.dump(res, open(R / 'a_errors.json', 'w'), indent=1)
    for k, v in res.items():
        n = v['n']
        print(f"{k:22s} n={n:3d} " + ' '.join(f"{c} {v.get(c, 0) / n:.2f}" for c in
                                                ('attacker', 'victim', 'other host', 'unresolved', 'none')))


if __name__ == '__main__':
    main()
