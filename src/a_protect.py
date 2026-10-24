"""Paper A: what each masking scheme still exposes (no LLM involved; experimenter-controlled ground truth).

P0 residual identifiers: identifiers known from *structured* alert fields of the scenario (agent IPs,
   log-source hostnames, account names, HTTP hostnames, attacker IP) that still appear verbatim in the
   masked text - an audit of the tagger that is independent of its regexes.
P1 context disclosure: for every masked mention of an IP or host, a logistic-regression adversary that
   sees only the surrounding words (+ the surrogate's visible shape) predicts three attributes of the
   real entity: internet vs internal, monitored host (log source) vs not, attacker host vs not.
   Leave-one-scenario-out; balanced accuracy and AUROC vs chance.
P2 linkability: for pairs of mentions from different bundles of the same scenario, can a linker tell
   whether they denote the same real entity? Score = surrogate string equality + cosine similarity of
   the mention contexts; AUROC over sampled pairs (equal numbers of same / different pairs).
Output: results/a_protect.json
"""
import json, random, re, collections
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score, balanced_accuracy_score
from a_mask import mask, mask_positions, SCHEMES

W = Path(__file__).resolve().parents[1]
D, R = W / 'data', W / 'results'
RNG = random.Random(19)
TOK = re.compile(r"[A-Za-z_][A-Za-z_]+|\d+|->|=|\[|\]")


def shape(sur, scheme):
    """What the surrogate itself reveals (visible to any reader of the masked text)."""
    if scheme == 'S0':
        return 'IPV4_' + ('PRIV' if re.match(r'^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)', sur) else 'PUB') \
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', sur) else 'NAME'
    if scheme in ('S4', 'S6') and re.match(r'^\d+\.\d+\.\d+\.\d+$', sur):
        return 'IPV4_' + ('PRIV' if re.match(r'^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)', sur) else 'PUB')
    if scheme == 'S5':
        return sur.rsplit('_', 1)[0]
    return re.sub(r'[_\[\]].*', '', sur.strip('[]'))


def mentions(B):
    """One record per masked IP/host mention: scheme, bundle, scenario, surrogate, context, true attributes."""
    out = []
    for b in B:
        for s in SCHEMES:
            masked, pos = mask_positions(b, s)
            starts = [0] + [k + 1 for k, ch in enumerate(masked) if ch == '\n']
            for (a, e, t, v, sur) in pos:
                ent = b['entities'].get(v)
                if t not in ('ip', 'host') or not ent:
                    continue
                ls = max(x for x in starts if x <= a)
                le = masked.find('\n', e); le = len(masked) if le < 0 else le
                left, right = masked[max(ls, a - 120):a], masked[e:min(le, e + 120)]
                ctx = (' '.join('L_' + w for w in TOK.findall(left)[-12:]) + ' ' +
                       ' '.join('R_' + w for w in TOK.findall(right)[:12]))
                out.append(dict(scheme=s, bundle=b['id'], scenario=b['scenario'], sur=sur, orig=v, canon=ent['canon'],
                                ctx=ctx + ' SHAPE_' + shape(sur, s), external=int(ent['zone'] == 'external'),
                                monitored=int(ent['monitored']), attacker=int(ent['attacker'])))
    return pd.DataFrame(out)


def residual(B, alerts_meta):
    res = collections.defaultdict(lambda: [0, 0])
    for b in B:
        inv = alerts_meta[b['scenario']]
        for s in SCHEMES:
            t = mask(b, s)[0]
            for kind, vals in inv.items():
                for v in vals:
                    if len(v) < 4:
                        continue
                    if re.search(r'(?<![\w.-])' + re.escape(v) + r'(?![\w-]|\.\w)', t):
                        res[(s, kind)][0] += 1
                res[(s, kind)][1] += 1
    return {f'{s}|{k}': dict(hits=v[0], checks=v[1]) for (s, k), v in res.items()}


def cluster_ci(y, p, groups, n=500, seed=29):
    """95% interval of the AUROC, resampling whole clusters (bundles) with replacement."""
    rng = np.random.default_rng(seed); y, p, groups = np.asarray(y), np.asarray(p), np.asarray(groups)
    ug = np.unique(groups); idx = {g: np.where(groups == g)[0] for g in ug}; vals = []
    for _ in range(n):
        k = np.concatenate([idx[g] for g in rng.choice(ug, len(ug))])
        if len(set(y[k])) > 1:
            vals.append(roc_auc_score(y[k], p[k]))
    return float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5))


def p1(M):
    out = {}
    for s in SCHEMES:
        d = M[M.scheme == s].reset_index(drop=True)
        for attr in ('external', 'monitored', 'attacker'):
            ys, ps, gs = [], [], []
            for sc in sorted(d.scenario.unique()):
                tr, te = d[d.scenario != sc], d[d.scenario == sc]
                if tr[attr].nunique() < 2 or len(te) == 0:
                    continue
                vec = TfidfVectorizer(token_pattern=r'\S+', min_df=2, sublinear_tf=True)
                Xtr = vec.fit_transform(tr.ctx); Xte = vec.transform(te.ctx)
                clf = LogisticRegression(max_iter=2000, C=1.0, class_weight='balanced').fit(Xtr, tr[attr])
                ys += list(te[attr]); ps += list(clf.predict_proba(Xte)[:, 1]); gs += list(te.bundle)
            ys, ps = np.array(ys), np.array(ps)
            out[f'{s}|{attr}'] = dict(n=len(ys), base_rate=float(ys.mean()),
                                      auroc=float(roc_auc_score(ys, ps)) if len(set(ys)) > 1 else None,
                                      bal_acc=float(balanced_accuracy_score(ys, ps > 0.5)),
                                      ci=cluster_ci(ys, ps, gs) if len(set(ys)) > 1 else None)
    return out


def p2(M, n_pairs=4000):
    out = {}
    for s in SCHEMES:
        d = M[M.scheme == s].reset_index(drop=True)
        vec = TfidfVectorizer(token_pattern=r'\S+', min_df=2).fit(d.ctx)
        X = vec.transform(d.ctx)
        by_sc = {sc: g.index.values for sc, g in d.groupby('scenario')}
        same, diff = [], []
        tries = 0
        while (len(same) < n_pairs or len(diff) < n_pairs) and tries < 400000:
            tries += 1
            sc = RNG.choice(list(by_sc)); idx = by_sc[sc]
            i, j = RNG.choice(idx), RNG.choice(idx)
            if d.bundle[i] == d.bundle[j]:
                continue
            if d.canon[i] == d.canon[j]:
                if len(same) < n_pairs:
                    same.append((i, j))
            elif len(diff) < n_pairs:
                diff.append((i, j))
        pairs = same + diff; y = [1] * len(same) + [0] * len(diff)
        sc_eq = np.array([float(d.sur[i] == d.sur[j]) for i, j in pairs])
        cos = np.array([float(X[i].multiply(X[j]).sum()) for i, j in pairs])
        out[s] = dict(n_same=len(same), n_diff=len(diff),
                      auroc_equality=float(roc_auc_score(y, sc_eq + 1e-6 * cos)),
                      auroc_context=float(roc_auc_score(y, cos)),
                      auroc_combined=float(roc_auc_score(y, 2 * sc_eq + cos)),
                      ci_combined=cluster_ci(y, 2 * sc_eq + cos, [d.bundle[i] for i, j in pairs]),
                      share_equal_same=float(sc_eq[:len(same)].mean()), share_equal_diff=float(sc_eq[len(same):].mean()))
    return out


def main():
    B = json.load(open(D / 'a_bundles.json'))
    df = pd.read_pickle(D / 'a_alerts.pkl')
    meta = json.load(open(D / 'a_meta.json'))
    inv = {}
    for sc, d in df.groupby('scenario'):
        inv[sc] = dict(agent_ip=sorted(set(d.agent_ip) - {''}), hostname=sorted(set(d.host) - {''}),
                       account=sorted({u for us in d.users for u in us}),
                       http_host=sorted({h for hs in d.hosts for h in hs if '.' in h}), attacker=[meta[sc]['attacker']])
    del df
    out = dict(residual=residual(B, inv))
    M = mentions(B)
    M.to_csv(R / 'a_mentions.csv.gz', index=False, compression='gzip')
    out['n_mentions'] = {s: int((M.scheme == s).sum()) for s in SCHEMES}
    out['p1'] = p1(M)
    out['p2'] = p2(M)
    json.dump(out, open(R / 'a_protect.json', 'w'), indent=1)
    for k, v in out['residual'].items():
        if v['hits']:
            print('residual', k, v)
    for k, v in out['p1'].items():
        print('P1', k, {a: (round(b, 3) if isinstance(b, float) else b) for a, b in v.items()})
    for k, v in out['p2'].items():
        print('P2', k, {a: (round(b, 3) if isinstance(b, float) else b) for a, b in v.items()})


if __name__ == '__main__':
    main()
