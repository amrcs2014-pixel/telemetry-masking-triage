"""Paper A: utility scoring of the analyst outputs.

Per (model, scheme, bundle):
  T1 verdict correct (escalate/close); T2 stage correct (8 classes incl. benign);
  T3 involved-host set F1 (host level: every listed identifier is mapped back through the scheme's
     surrogate map to the original string and its canonical host; unresolvable items count as false
     positives; benign bundles score 1 if nothing is listed);
  T4 containment correct (canonical host == ground truth; 'none' for benign).
Aggregates per (model, scheme): T1 macro-F1, MCC, attack recall, benign FPR; T2 macro-F1; T3 mean F1 on
attack bundles; T4 accuracy on attack bundles. Paired tests against S0 on identical bundles: McNemar
(T1, T4 correctness), paired bootstrap (T2 macro-F1, T3 F1); Holm correction within each metric and family (main ladder, ablation, S6-vs-S4/S3).
Output: results/a_scores.jsonl (per item), results/a_eval.json.
"""
import json, re, glob, math, random
from collections import defaultdict
from pathlib import Path
import numpy as np
from sklearn.metrics import f1_score, matthews_corrcoef
from statsmodels.stats.contingency_tables import mcnemar
from statsmodels.stats.multitest import multipletests

W = Path(__file__).resolve().parents[1]
D, R = W / 'data', W / 'results'
STAGES = ['reconnaissance', 'web_scanning', 'web_exploitation', 'password_cracking', 'remote_shell',
          'privilege_escalation', 'exfiltration', 'benign']
PORT = re.compile(r'(?<=[\w\]])[:/]\d{1,5}$')


def norm(s):
    s = str(s).strip().strip('"\'`<>()[]{} ,;').strip()
    if s.startswith('[') is False and s.endswith(']') and '[' in s:
        s = s[:s.index('[')]
    return PORT.sub('', s)


def resolver(bundle, smap):
    ents = bundle['entities']
    low = {k.lower(): v for k, v in smap.items()}

    def canon(x):
        if x is None:
            return None
        e = ents.get(x)
        return e['canon'] if e else None

    def res(s):
        s0 = str(s).strip()
        for cand in (s0, norm(s0)):
            if cand in smap:
                return canon(smap[cand])
            if cand.lower() in low:
                return canon(low[cand.lower()])
            if cand in ents:  # a real identifier that survived masking (or S0)
                return ents[cand]['canon']
        return None
    return res


TYPELAB = re.compile(r'\[[A-Z_]+\]')


def score_item(b, smap, out):
    smap = {k: (None if TYPELAB.fullmatch(k) else v) for k, v in smap.items()}  # a type label denotes no host
    res = resolver(b, smap)
    g_att = b['verdict'] == 'escalate'
    r = dict(t1=int(out.get('verdict') == b['verdict']), t2=int(out.get('stage') == b['stage']),
             pred_verdict=out.get('verdict'), pred_stage=out.get('stage'))
    pred = [res(x) for x in out.get('involved', []) or []]
    gt = set(b['involved'])
    if not g_att:
        r['t3'] = float(len(pred) == 0)
    else:
        ps = set(p for p in pred if p)
        n_unres = sum(1 for p in pred if p is None)
        tp = len(ps & gt); fp = len(ps - gt) + n_unres; fn = len(gt - ps)
        r['t3'] = 2 * tp / (2 * tp + fp + fn) if (tp + fp + fn) else 1.0
        r['t3_unresolved'] = n_unres
    c = str(out.get('contain', 'none')).strip()
    if c.lower() in ('none', '', 'null', 'n/a'):
        r['t4'] = int(b['contain'] == 'none')
    else:
        r['t4'] = int(res(c) == b['contain'] and b['contain'] != 'none')
    return r


def macro(y, p, labels):
    return f1_score(y, p, labels=labels, average='macro', zero_division=0)


def boot_diff(fn, a_items, b_items, n=2000, seed=19):
    rng = random.Random(seed); k = len(a_items); diffs = []
    for _ in range(n):
        idx = [rng.randrange(k) for _ in range(k)]
        diffs.append(fn([b_items[i] for i in idx]) - fn([a_items[i] for i in idx]))
    diffs.sort()
    d0 = fn(b_items) - fn(a_items)
    # two-sided sign-proportion p-value with the +1 correction, so it is never 0
    p = 2 * min((sum(d <= 0 for d in diffs) + 1) / (n + 1), (sum(d >= 0 for d in diffs) + 1) / (n + 1))
    return d0, diffs[int(0.025 * n)], diffs[int(0.975 * n)], min(1.0, p)


def main():
    B = {b['id']: b for b in json.load(open(D / 'a_bundles.json'))}
    maps = json.load(open(D / 'a_maps.json'))
    items = defaultdict(dict)  # (model, scheme) -> bundle -> scores
    bad = defaultdict(int)
    with open(R / 'a_scores.jsonl', 'w') as fo:
        for f in sorted(glob.glob(str(R / 'a_gen' / '*.jsonl'))):
            for l in open(f, encoding='utf-8'):
                x = json.loads(l)
                if 'error' in x:
                    continue
                try:
                    out = json.loads(x['text'])
                except Exception:
                    bad[(x['model'], x['scheme'])] += 1; out = {}
                s = score_item(B[x['bundle']], maps[x['id']], out)
                s.update(model=x['model'], scheme=x['scheme'], bundle=x['bundle'])
                items[(x['model'], x['scheme'])][x['bundle']] = s
                fo.write(json.dumps(s) + '\n')
    agg, tests = {}, []
    models = sorted({m for m, _ in items})
    for (m, s), it in sorted(items.items()):
        ids = sorted(it)
        yv = [B[i]['verdict'] for i in ids]; pv = [it[i]['pred_verdict'] or 'close' for i in ids]
        ys = [B[i]['stage'] for i in ids]; pst = [it[i]['pred_stage'] or 'benign' for i in ids]
        att = [i for i in ids if B[i]['verdict'] == 'escalate']; ben = [i for i in ids if B[i]['verdict'] == 'close']
        agg[f'{m}|{s}'] = dict(
            n=len(ids), parse_fail=bad[(m, s)],
            t1_macro_f1=macro(yv, pv, ['escalate', 'close']),
            t1_mcc=matthews_corrcoef([v == 'escalate' for v in yv], [v == 'escalate' for v in pv]),
            recall=np.mean([it[i]['pred_verdict'] == 'escalate' for i in att]) if att else None,
            fpr=np.mean([it[i]['pred_verdict'] == 'escalate' for i in ben]) if ben else None,
            t2_macro_f1=macro(ys, pst, STAGES),
            t2_acc_attack=np.mean([it[i]['t2'] for i in att]) if att else None,
            t3_f1_attack=np.mean([it[i]['t3'] for i in att]) if att else None,
            t3_unresolved=np.mean([it[i].get('t3_unresolved', 0) for i in att]) if att else None,
            t4_acc_attack=np.mean([it[i]['t4'] for i in att]) if att else None,
            t4_acc_benign=np.mean([it[i]['t4'] for i in ben]) if ben else None)
    # paired tests on identical bundles: main ladder and ablation vs S0, and S6 vs S4 / S3 directly
    MAIN, ABL = ['S1', 'S2', 'S3', 'S4', 'S5', 'S6'], ['Rip', 'Rname', 'Ruser']
    comps = [('S0', s, 'main') for s in MAIN] + [('S0', s, 'ablation') for s in ABL] +             [('S4', 'S6', 'direct'), ('S3', 'S6', 'direct')] + [('S0', 'S0n', 'control')] + \
            [('S0n', s, 'main_n') for s in MAIN]
    rng = np.random.default_rng(23)
    for m in models:
        for ref, s, fam in comps:
            base, it = items.get((m, ref)), items.get((m, s))
            if not base or not it:
                continue
            ids = sorted(set(base) & set(it))
            att = [i for i in ids if B[i]['verdict'] == 'escalate']
            for key, sub in (('t1', ids), ('t4', att)):
                a = np.array([base[i][key] for i in sub]); b = np.array([it[i][key] for i in sub])
                tab = [[int(((a == 1) & (b == 1)).sum()), int(((a == 1) & (b == 0)).sum())],
                       [int(((a == 0) & (b == 1)).sum()), int(((a == 0) & (b == 0)).sum())]]
                p = mcnemar(tab, exact=True).pvalue
                idx = rng.integers(0, len(sub), (2000, len(sub)))
                bd = np.sort((b[idx] - a[idx]).mean(1))
                tests.append(dict(model=m, ref=ref, scheme=s, family=fam, metric=key, n=len(sub), base=a.mean(),
                                  value=b.mean(), diff=b.mean() - a.mean(), lo=bd[50], hi=bd[1949], p=p))
            fa = [base[i] for i in att]; fb = [it[i] for i in att]
            d, lo, hi, p = boot_diff(lambda xs: float(np.mean([x['t3'] for x in xs])), fa, fb)
            tests.append(dict(model=m, ref=ref, scheme=s, family=fam, metric='t3', n=len(att),
                              base=np.mean([x['t3'] for x in fa]), value=np.mean([x['t3'] for x in fb]),
                              diff=d, lo=lo, hi=hi, p=p))
            if fam == 'direct':
                continue
            fa = [(B[i]['stage'], base[i]['pred_stage'] or 'benign') for i in ids]
            fb = [(B[i]['stage'], it[i]['pred_stage'] or 'benign') for i in ids]
            mf = lambda xs: macro([x[0] for x in xs], [x[1] for x in xs], STAGES)
            d, lo, hi, p = boot_diff(mf, fa, fb, n=1000)
            tests.append(dict(model=m, ref=ref, scheme=s, family=fam, metric='t2', n=len(ids), base=mf(fa),
                              value=mf(fb), diff=d, lo=lo, hi=hi, p=p))
            # MCC difference of the verdict (descriptive interval)
            ya = np.array([B[i]['verdict'] == 'escalate' for i in ids])
            pa = np.array([(base[i]['pred_verdict'] or 'close') == 'escalate' for i in ids])
            pb = np.array([(it[i]['pred_verdict'] or 'close') == 'escalate' for i in ids])
            mcc = lambda y, p: matthews_corrcoef(y, p) if len(set(p)) > 1 and len(set(y)) > 1 else 0.0
            md = []
            for _ in range(500):
                k = rng.integers(0, len(ids), len(ids))
                md.append(mcc(ya[k], pb[k]) - mcc(ya[k], pa[k]))
            md.sort()
            tests.append(dict(model=m, ref=ref, scheme=s, family=fam + '_desc', metric='t1_mcc', n=len(ids),
                              base=mcc(ya, pa), value=mcc(ya, pb), diff=mcc(ya, pb) - mcc(ya, pa),
                              lo=md[12], hi=md[487], p=1.0))
    # Holm within each (family, metric): the main ladder, the ablation and the direct comparisons separately
    for fam in ('main', 'ablation', 'direct', 'control', 'main_n'):
        for metric in ('t1', 't2', 't3', 't4'):
            sub = [t for t in tests if t['metric'] == metric and t['family'] == fam]
            if sub:
                rej, padj, *_ = multipletests([t['p'] for t in sub], method='holm')
                for t, pa in zip(sub, padj):
                    t['p_holm'] = pa
    json.dump(dict(agg=agg, tests=tests), open(R / 'a_eval.json', 'w'), indent=1, default=float)
    for k, v in agg.items():
        print(f"{k:22s} n={v['n']:3d} T1 F1 {v['t1_macro_f1']:.3f} rec {v['recall']:.2f} fpr {v['fpr']:.2f} "
              f"T2 F1 {v['t2_macro_f1']:.3f} T3 {v['t3_f1_attack']:.3f} (unres {v['t3_unresolved']:.2f}) "
              f"T4 {v['t4_acc_attack']:.3f}/{v['t4_acc_benign']:.2f} parse_fail {v['parse_fail']}")


if __name__ == '__main__':
    main()
