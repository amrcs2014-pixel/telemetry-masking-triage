"""Paper A: numbers (LaTeX macros), tables and figures from results/a_eval.json and a_protect.json.
Writes outputs/numbers_A.tex, outputs/tab_*.tex, outputs/a_fig_*.pdf.
"""
import json, math, re, collections
from pathlib import Path
import numpy as np
import matplotlib
matplotlib.use('Agg')
matplotlib.rcParams['pdf.fonttype'] = 42  # embed TrueType, not Type 3, fonts in PDF figures
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

W = Path(__file__).resolve().parents[1]
D, R, P = W / 'data', W / 'results', W / 'outputs'  # generated tables, macros and figures
SCH = ['S0', 'S1', 'S2', 'S3', 'S4', 'S5', 'S6']
SNAME = {'S0n': 'notice', 'S0': 'none', 'S1': 'redact', 'S2': 'random', 'S3': 'consistent', 'S4': 'global (Crypto-PAn)', 'S5': 'role', 'S6': 'per-bundle Crypto-PAn'}
MODELS = ['qwen2.5-1.5b', 'qwen2.5-3b', 'llama3.2-3b', 'qwen3-4b', 'qwen2.5-7b']
MNAME = {'qwen2.5-1.5b': 'Qwen2.5-1.5B', 'qwen2.5-3b': 'Qwen2.5-3B', 'llama3.2-3b': 'Llama-3.2-3B',
         'qwen3-4b': 'Qwen3-4B', 'qwen2.5-7b': 'Qwen2.5-7B'}
COL = {'qwen2.5-1.5b': '#9ecae1', 'qwen2.5-3b': '#3182bd', 'llama3.2-3b': '#e6550d', 'qwen3-4b': '#31a354',
       'qwen2.5-7b': '#08306b'}
MKEY = {'qwen2.5-1.5b': 'QwenSmall', 'qwen2.5-3b': 'QwenThree', 'llama3.2-3b': 'LlamaThree', 'qwen3-4b': 'QwenFour',
        'qwen2.5-7b': 'QwenSeven'}
SKEY = {'S0': 'Szero', 'S1': 'Sone', 'S2': 'Stwo', 'S3': 'Sthree', 'S4': 'Sfour', 'S5': 'Sfive', 'S6': 'Ssix'}
SKEYX = dict(SKEY, Rip='Rip', Rname='Rname', Ruser='Ruser', S0n='Szeron')
STAGES = ['reconnaissance', 'web_scanning', 'web_exploitation', 'password_cracking', 'remote_shell',
          'privilege_escalation', 'exfiltration', 'benign']
plt.rcParams.update({'font.size': 8, 'font.family': 'DejaVu Sans', 'axes.spines.top': False, 'axes.spines.right': False})


def mac(name, val):
    name = re.sub(r'[^A-Za-z]', '', name)
    return f'\\newcommand{{\\{name}}}{{{val}}}\n'


def num(x, d=2):
    return '--' if x is None or (isinstance(x, float) and np.isnan(x)) else f'{x:.{d}f}'


def word(i):
    return 'ABCDEFGHIJ'[i]


def main():
    P.mkdir(exist_ok=True)
    B = json.load(open(D / 'a_bundles.json'))
    ev = json.load(open(R / 'a_eval.json'))
    pr = json.load(open(R / 'a_protect.json'))
    agg, alltests = ev['agg'], ev['tests']
    tests = [t for t in alltests if t.get('family') in ('main', 'ablation', 'control')]
    models = [m for m in MODELS if any(k.startswith(m + '|') for k in agg)]
    out = []
    att = [b for b in B if b['verdict'] == 'escalate']
    out += [mac('NBundles', len(B)), mac('NBundlesAttack', len(att)), mac('NBundlesBenign', len(B) - len(att)),
            mac('NLinesMean', f"{np.mean([b['n_lines'] for b in B]):.1f}"), mac('NPrompts', f'{len(B) * len(SCH):,}'),
            mac('NAnswers', f"{sum(v['n'] for v in agg.values()):,}"), mac('NSubset', 150), mac('NPairs', '4,000'),
            mac('NAlertsTotal', '2.66 million'), mac('NModels', len(models))]
    for m in models:
        for s in SCH + ['S0n']:
            v = agg.get(f'{m}|{s}')
            if not v:
                continue
            k = MKEY[m] + SKEYX[s]
            for met, mk in (('t1_mcc', 'Mcc'), ('t1_macro_f1', 'Tone'), ('recall', 'Rec'), ('fpr', 'Fpr'),
                            ('t2_macro_f1', 'Ttwo'), ('t3_f1_attack', 'Tthree'), ('t4_acc_attack', 'Tfour')):
                out.append(mac(k + mk, num(v[met])))
    # protection macros
    for s in SCH:
        sk = SKEY[s]
        for a in ('external', 'monitored', 'attacker'):
            v = pr['p1'].get(f'{s}|{a}')
            if v:
                out.append(mac(f'Pone{sk}{a}', num(v['auroc'])))
        v = pr['p2'].get(s)
        if v:
            out.append(mac(f'Ptwo{sk}', num(v['auroc_combined'])))
    t12 = [t for t in tests if t['metric'] in ('t1', 't2') and t['family'] == 'main']
    t1m = [t for t in tests if t['metric'] == 't1' and t['family'] == 'main']
    mccd = [t for t in alltests if t['metric'] == 't1_mcc' and t['family'] == 'main_desc']
    pts = lambda x: '0' if round(100 * x) == 0 else f"{100 * x:+.0f}".replace('-', '$-$')
    out += [mac('NTestsTonetwo', len(t12)), mac('MinPTonetwo', f"{min(t['p_holm'] for t in t12):.2f}"),
            mac('NTestsMain', len([t for t in tests if t['family'] == 'main'])),
            mac('MaxCIToneAcc', f"{math.ceil(100 * max(max(abs(t['lo']), abs(t['hi'])) for t in t1m))}"),
            mac('MaxDiffToneAcc', f"{100 * max(abs(t['diff']) for t in t1m):.0f}"),
            mac('MaxDiffToneMcc', f"{max(abs(t['diff']) for t in mccd):.2f}"),
            mac('NMccCIZero', f"{sum(t['lo'] <= 0 <= t['hi'] for t in mccd)}"), mac('NMccTests', len(mccd)),
            mac('NToneCIExcl', sum(not (t['lo'] <= 0 <= t['hi']) for t in t1m)), mac('NToneTests', len(t1m)),
            mac('NSchemesRun', len({k.split('|')[1] for k in agg if k.split('|')[1] in SCH}))]
    # per-test macros: difference in points and Holm p for T3/T4 (main ladder and ablation)
    fp = lambda p: ('<0.001' if p < 0.001 else f'{p:.3f}' if p < 0.1 else f'{p:.2f}')
    for t in tests:
        if t['metric'] in ('t3', 't4') and t['model'] in MKEY:
            k = MKEY[t['model']] + SKEYX[t['scheme']] + ('Tthree' if t['metric'] == 't3' else 'Tfour')
            out += [mac('D' + k, pts(t['diff'])), mac('P' + k, fp(t['p_holm'])),
                    mac('CI' + k, f"[{pts(t['lo'])}, {pts(t['hi'])}]")]
    # direct comparisons S6 vs S4 and S6 vs S3
    dire = [t for t in alltests if t.get('family') == 'direct']
    for t in dire:
        k = MKEY[t['model']] + ('Sfour' if t['ref'] == 'S4' else 'Sthree') + ('Tthree' if t['metric'] == 't3' else 'Tfour' if t['metric'] == 't4' else 'Tone')
        out += [mac('Dsix' + k, pts(t['diff'])), mac('Psix' + k, fp(t['p_holm']))]
    ctl = [t for t in alltests if t.get('family') == 'control']
    if ctl:
        for t in ctl:
            k = MKEY[t['model']] + {'t1': 'Tone', 't2': 'Ttwo', 't3': 'Tthree', 't4': 'Tfour'}[t['metric']]
            out += [mac('DCtrl' + k, pts(t['diff'])), mac('PCtrl' + k, fp(t['p_holm']))]
        out += [mac('NCtrl', len(ctl)), mac('NCtrlSig', sum(t['p_holm'] < 0.05 for t in ctl)),
                mac('MinPCtrl', fp(min(t['p_holm'] for t in ctl))),
                mac('MaxCtrlToneAcc', f"{100 * max(abs(t['diff']) for t in ctl if t['metric'] == 't1'):.0f}"),
                mac('NCtrlModels', len({t['model'] for t in ctl}))]
        mn = [t for t in alltests if t.get('family') == 'main_n']
        for t in mn:
            if t['metric'] in ('t3', 't4'):
                k = MKEY[t['model']] + SKEY[t['scheme']] + ('Tthree' if t['metric'] == 't3' else 'Tfour')
                out += [mac('DN' + k, pts(t['diff'])), mac('PN' + k, fp(t['p_holm']))]
        t4m = [t for t in alltests if t.get('family') == 'main' and t['metric'] == 't4' and t['scheme'] != 'S1'
               and t['p_holm'] < 0.05]
        t4n = {(t['model'], t['scheme']) for t in mn if t['metric'] == 't4' and t['p_holm'] < 0.05}
        out += [mac('NToursigMain', len(t4m)), mac('NToursigKept', sum((t['model'], t['scheme']) in t4n for t in t4m)),
                mac('NHostLost', len([1 for t in alltests if t.get('family') == 'main' and t['metric'] in ('t3', 't4')
                                      and t['scheme'] != 'S1' and t['p_holm'] < 0.05]) -
                    sum(1 for t in alltests if t.get('family') == 'main' and t['metric'] in ('t3', 't4') and t['scheme'] != 'S1'
                        and t['p_holm'] < 0.05 and any(u['model'] == t['model'] and u['scheme'] == t['scheme'] and
                                                         u['metric'] == t['metric'] and u['p_holm'] < 0.05 for u in mn)))]
        m12 = [t for t in mn if t['metric'] in ('t1', 't2')]
        hostm = {(t['model'], t['scheme'], t['metric']) for t in alltests if t.get('family') == 'main'
                 and t['metric'] in ('t3', 't4') and t['scheme'] != 'S1' and t['p_holm'] < 0.05}
        hostn = {(t['model'], t['scheme'], t['metric']) for t in mn
                 if t['metric'] in ('t3', 't4') and t['scheme'] != 'S1' and t['p_holm'] < 0.05}
        out += [mac('NTestsTonetwoN', len(m12)), mac('MinPTonetwoN', f"{min(t['p_holm'] for t in m12):.2f}"),
                mac('NSigTonetwoN', sum(t['p_holm'] < 0.05 for t in m12)),
                mac('NHostSigMain', len(hostm)), mac('NHostSigBoth', len(hostm & hostn)), mac('NHostSigN', len(hostn))]
    out.append(mac('NDirectSig', sum(t['p_holm'] < 0.05 for t in dire if t['metric'] in ('t3', 't4'))))
    d4 = [t for t in dire if t['ref'] == 'S4' and t['metric'] in ('t3', 't4')]
    out += [mac('NDirFour', len(d4)), mac('NDirFourSig', sum(t['p_holm'] < 0.05 for t in d4)),
            mac('MaxDirFour', f"{100 * max(abs(t['diff']) for t in d4):.0f}")]
    out.append(mac('NDirect', sum(t['metric'] in ('t3', 't4') for t in dire)))
    er = json.load(open(R / 'a_errors.json'))  # containment choices, % of attack bundles with a visible attacker
    for k, v in er.items():
        m, s = k.split('|')
        if m in MKEY and s in SKEYX:
            for c, ck in (('attacker', 'Att'), ('victim', 'Vic'), ('other host', 'Oth'), ('other_external', 'Ext')):
                out.append(mac(f'Ch{ck}{MKEY[m]}{SKEYX[s]}', f"{100 * v.get(c, 0) / v['n']:.0f}"))
    att = [pr['p1'][f'{s}|attacker']['auroc'] for s in SCH if s != 'S0']
    out += [mac('PoneAttMin', num(min(att))), mac('PoneAttMax', num(max(att)))]
    for s in SCH:
        ci = pr['p2'][s].get('ci_combined')
        if ci:
            out.append(mac(f'PtwoCI{SKEY[s]}', f'[{ci[0]:.2f}, {ci[1]:.2f}]'))
    res_hits = sum(v['hits'] for k, v in pr['residual'].items() if not k.startswith('S0'))
    out.append(mac('PzeroHits', sum(v['hits'] for k, v in pr['residual'].items() if k.startswith('S1'))))
    (P / 'numbers_A.tex').write_text(''.join(out), encoding='utf-8')
    tables(B, agg, tests, pr, models)
    figs(B, agg, tests, pr, models)
    diffs_fig([x for x in alltests if x.get('family') == 'main_n'], models, 'S0n', 'a_fig_diffs_n.pdf')
    print('report A done;', len(out), 'macros; models', models)


def ablation_table(agg, tests):
    """Type-specific redaction (Qwen2.5-3B, 150-bundle subset) against S0 on the same bundles."""
    m = 'qwen2.5-3b'
    rows = []
    for s, name in (('Rip', 'IP addresses only'), ('Rname', 'host and domain names only'), ('Ruser', 'accounts and e-mail only')):
        if f'{m}|{s}' not in agg:
            continue
        cells = []
        for met in ('t1', 't2', 't3', 't4'):
            t = next((x for x in tests if x['model'] == m and x['scheme'] == s and x['metric'] == met), None)
            if t is None:
                cells.append('--'); continue
            star = '$^{*}$' if t.get('p_holm', 1) < 0.05 else ''
            cells.append(f"{t['value']:.2f} ({t['diff']:+.2f}){star}".replace('-', '$-$'))
        rows.append(f'{name} & ' + ' & '.join(cells) + '\\\\')
    if not rows:
        return
    base = [next((x for x in tests if x['model'] == m and x['scheme'] == 'Rip' and x['metric'] == met), {}).get('base')
            for met in ('t1', 't2', 't3', 't4')]
    (P / 'tab_ablation.tex').write_text(
        '\\begin{table}[t]\\centering\\caption{Which identifier type the analyst needs: Qwen2.5-3B on the 150-bundle subset with '
        'only one identifier type redacted (others as logged). Values and difference from the unmasked bundles (S0: ' +
        ', '.join(f'{b:.2f}' if b is not None else '--' for b in base) + ' for T1 accuracy, T2 macro-F1, T3 F1, T4 accuracy); '
        '$^{*}$: Holm-adjusted $p<0.05$.}\\label{tab:a_ablation}\n\\small\\begin{tabular}{lrrrr}\\toprule Redacted & '
        'T1 accuracy & T2 macro-F1 & T3 F1 & T4 accuracy\\\\\\midrule\n' + '\n'.join(rows) +
        '\n\\bottomrule\\end{tabular}\\end{table}\n', encoding='utf-8')


def tables(B, agg, tests, pr, models):
    ablation_table(agg, tests)
    # data table
    c = collections.Counter(b['stage'] for b in B)
    sc = collections.Counter(b['scenario'] for b in B)
    rows = ''.join(f"{s.replace('_', ' ')} & {c[s]} \\\\\n" for s in STAGES)
    (P / 'tab_data.tex').write_text(
        '\\begin{table}[t]\\centering\\caption{Alert bundles per stage (ground truth from the AIT-ADS attack-step windows). '
        f'Eight scenarios contribute {min(sc.values())}--{max(sc.values())} bundles each.}}\\label{{tab:a_data}}\n'
        '\\small\\begin{tabular}{lr}\\toprule Stage & Bundles\\\\\\midrule\n' + rows +
        f'\\midrule Total & {len(B)}\\\\\\bottomrule\\end{{tabular}}\\end{{table}}\n', encoding='utf-8')
    # main results table
    lines = []
    for m in models:
        for i, s in enumerate(['S0', 'S0n'] + SCH[1:]):
            v = agg.get(f'{m}|{s}')
            if not v:
                continue
            sig = {}
            for t in tests:
                if t['model'] == m and t['scheme'] == s:
                    sig[t['metric']] = '$^{*}$' if t.get('p_holm', 1) < 0.05 else ''
            lines.append(f"{MNAME[m] if i == 0 else ''} & {s} {SNAME[s].split(' ')[0]} & {v['n']} & {num(v['t1_mcc'])}{sig.get('t1', '')} & "
                         f"{num(v['recall'])} & {num(v['fpr'])} & {num(v['t2_macro_f1'])}{sig.get('t2', '')} & "
                         f"{num(v['t3_f1_attack'])}{sig.get('t3', '')} & {num(v['t4_acc_attack'])}{sig.get('t4', '')} \\\\")
        lines.append('\\midrule')
    (P / 'tab_results.tex').write_text(
        '\\begin{table}[p]\\centering\\caption{Analyst utility per model and masking scheme. T1: Matthews correlation of the '
        'triage verdict, attack recall and benign false-positive rate; T2: stage macro-F1 (8 classes); T3: involved-host F1 on '
        'attack bundles; T4: containment accuracy on attack bundles. $^{*}$: different from S0 on the same bundles after Holm '
        'correction ($p<0.05$). S0n: the unmasked bundles with a neutral privacy notice (control for the notice; McNemar on per-bundle correctness for T1/T4, paired bootstrap for T2/T3; Holm within each task over the main ladder). Qwen3-4B and Qwen2.5-7B: stratified subset of 150 bundles (129 attack, 21 benign), so their FPR and MCC rest on 21 benign bundles and are not comparable with the full-set rows.}\\label{tab:a_results}\n'
        '\\small\\begin{tabular}{llrrrrrrr}\\toprule Model & Scheme & $n$ & T1 MCC & Recall & FPR & T2 F1 & T3 F1 & T4 acc\\\\\\midrule\n'
        + '\n'.join(lines[:-1]) + '\n\\bottomrule\\end{tabular}\\end{table}\n', encoding='utf-8')
    # protection table
    rows = []
    for s in SCH:
        p1 = [pr['p1'].get(f'{s}|{a}', {}).get('auroc') for a in ('external', 'monitored', 'attacker')]
        ci1 = pr['p1'].get(f'{s}|attacker', {}).get('ci')
        p2 = pr['p2'].get(s, {}); ci2 = p2.get('ci_combined')
        sh = lambda ci: f"\\,{{\\scriptsize[{ci[0]:.2f}, {ci[1]:.2f}]}}" if ci else ''
        hits = sum(v['hits'] for k, v in pr['residual'].items() if k.startswith(s + '|'))
        rows.append(f"{s} {SNAME[s]} & {hits if s != 'S0' else '--'} & {num(p1[0])} & {num(p1[1])} & {num(p1[2])}{sh(ci1)} & "
                    f"{num(p2.get('auroc_combined'))}{sh(ci2)} & {num(p2.get('share_equal_same'))} & {num(p2.get('share_equal_diff'))} \\\\")
    (P / 'tab_protect.tex').write_text(
        '\\begin{table}[t]\\centering\\caption{What each scheme still exposes. P0: identifiers from the structured alert fields '
        'found verbatim in the masked bundles (all 351 bundles). P1: AUROC of an adversary that sees only the context and the surrogate\'s form (leave-one-scenario-out) '
        'that infers whether a masked host is on the internet, is a monitored host or is the attacker (base rates '
        f"{pr['p1']['S0|external']['base_rate']:.2f}, {pr['p1']['S0|monitored']['base_rate']:.2f}, "
        f"{pr['p1']['S0|attacker']['base_rate']:.2f}). P2: AUROC of a linker that decides whether two mentions in different "
        'bundles denote the same host, and the shares of same-host and of different-host pairs with identical surrogates. '
        'Brackets: 95\\,\\% intervals from a bootstrap over bundles.}\\label{tab:a_protect}\n'
        '\\small\\setlength{\\tabcolsep}{3.5pt}\\begin{tabular}{lrrrllrr}\\toprule & P0 & \\multicolumn{3}{c}{P1 attribute AUROC} & \\multicolumn{3}{c}{P2 linkability}\\\\\n'
        '\\cmidrule(lr){3-5}\\cmidrule(lr){6-8} Scheme & residual & internet & monitored & attacker & AUROC & =\\,same & =\\,diff.\\\\\\midrule\n'
        + '\n'.join(rows) + '\n\\bottomrule\\end{tabular}\\end{table}\n', encoding='utf-8')


def diffs_fig(tests, models, ref, fname):
    """Paired differences from the reference condition: T3 F1 with bootstrap CIs, T4 accuracy with CIs."""
    fig, axs = plt.subplots(1, 2, figsize=(7.2, 2.6), sharey=True)
    for ax, met, t in ((axs[0], 't3', f'T3 F1 difference vs {ref}'), (axs[1], 't4', f'T4 accuracy difference vs {ref}')):
        for j, m in enumerate(models):
            for i, s in enumerate(SCH[1:]):
                tt = [x for x in tests if x['model'] == m and x['scheme'] == s and x['metric'] == met and x.get('ref', 'S0') == ref]
                if not tt:
                    continue
                tt = tt[0]; y = i * (len(models) + 1) + j
                ax.plot([tt['diff']], [y], 'o', ms=3, color=COL[m], label=MNAME[m] if i == 0 else None)
                if 'lo' in tt:
                    ax.plot([tt['lo'], tt['hi']], [y, y], color=COL[m], lw=1)
        ax.axvline(0, color='k', lw=0.6); ax.set_title(t, fontsize=8)
        ax.set_yticks([i * (len(models) + 1) + (len(models) - 1) / 2 for i in range(len(SCH) - 1)]); ax.set_yticklabels(SCH[1:])
        ax.invert_yaxis(); ax.grid(axis='x', lw=0.3, alpha=0.5)
    if ref != 'S0':
        axs[0].legend(fontsize=6, frameon=False, loc='upper left')
    fig.tight_layout(); fig.savefig(P / fname); plt.close(fig)


def figs(B, agg, tests, pr, models):
    # Fig: utility per task across schemes, one line per model
    mets = [('t1_mcc', 'T1 triage (MCC)'), ('t2_macro_f1', 'T2 stage (macro-F1)'),
            ('t3_f1_attack', 'T3 involved hosts (F1)'), ('t4_acc_attack', 'T4 containment (accuracy)')]
    fig, axs = plt.subplots(1, 4, figsize=(7.2, 2.3))
    for ax, (k, t) in zip(axs, mets):
        for m in models:
            ys = [agg.get(f'{m}|{s}', {}).get(k) for s in SCH]
            ax.plot(range(len(SCH)), [np.nan if y is None else y for y in ys], marker='o', ms=3, lw=1.2, color=COL[m], label=MNAME[m])
        ax.set_xticks(range(len(SCH))); ax.set_xticklabels(SCH); ax.set_title(t, fontsize=8); ax.set_ylim(bottom=0)
        ax.grid(axis='y', lw=0.3, alpha=0.5)
    axs[0].legend(fontsize=6, frameon=False, loc='lower left')
    fig.tight_layout(); fig.savefig(P / 'a_fig_utility.pdf'); plt.close(fig)
    # Fig: protection
    fig, axs = plt.subplots(1, 2, figsize=(7.2, 2.4), gridspec_kw={'width_ratios': [1.4, 1]})
    attrs = [('external', 'internet'), ('monitored', 'monitored host'), ('attacker', 'attacker')]
    x = np.arange(len(SCH)); w = 0.26
    for i, (a, lab) in enumerate(attrs):
        axs[0].bar(x + (i - 1) * w, [pr['p1'][f'{s}|{a}']['auroc'] for s in SCH], w, label=lab,
                   color=['#bdbdbd', '#636363', '#d95f0e'][i])
    axs[0].axhline(0.5, color='k', lw=0.6, ls=':'); axs[0].set_xticks(x); axs[0].set_xticklabels(SCH)
    axs[0].set_ylim(0.4, 1.02); axs[0].set_ylabel('AUROC'); axs[0].set_title('P1 attribute disclosure from context', fontsize=8)
    axs[0].legend(fontsize=6, frameon=False, ncol=3, loc='lower center')
    axs[1].bar(x, [pr['p2'][s]['auroc_combined'] for s in SCH], 0.6, color=['#08519c' if s in ('S0', 'S4') else '#9ecae1' for s in SCH])
    axs[1].axhline(0.5, color='k', lw=0.6, ls=':'); axs[1].set_xticks(x); axs[1].set_xticklabels(SCH)
    axs[1].set_ylim(0.4, 1.0); axs[1].set_title('P2 linkability across bundles', fontsize=8)
    fig.tight_layout(); fig.savefig(P / 'a_fig_protect.pdf'); plt.close(fig)
    # Fig: frontier (mean over models of T3 and T4 vs linkability)
    fig, axs = plt.subplots(1, 2, figsize=(7.2, 2.6))
    for ax, (k, t) in zip(axs, [('t3_f1_attack', 'T3 involved hosts (F1)'), ('t4_acc_attack', 'T4 containment (accuracy)')]):
        for m in models:
            xs = [pr['p2'][s]['auroc_combined'] for s in SCH]
            ys = [agg.get(f'{m}|{s}', {}).get(k, np.nan) for s in SCH]
            ax.scatter(xs, ys, s=12, color=COL[m], label=MNAME[m], zorder=3)
        for s in SCH:
            ys = [agg.get(f'{m}|{s}', {}).get(k) for m in models]
            ys = [y for y in ys if y is not None]
            if ys:
                ax.annotate(s, (pr['p2'][s]['auroc_combined'], np.mean(ys)), fontsize=7, xytext=(4, 2), textcoords='offset points')
        ax.set_xlabel('P2 linkability AUROC (lower = more private)'); ax.set_ylabel(t); ax.grid(lw=0.3, alpha=0.5)
    axs[0].legend(fontsize=6, frameon=False)
    fig.tight_layout(); fig.savefig(P / 'a_fig_frontier.pdf'); plt.close(fig)
    diffs_fig(tests, models, 'S0', 'a_fig_diffs.pdf')
    errors_fig(models)
    method_fig()


def errors_fig(models):
    """What the analyst contained on attack bundles with a visible attacker (results/a_errors.json)."""
    try:
        er = json.load(open(R / 'a_errors.json'))
    except Exception:
        return
    cats = [('attacker', '#31a354'), ('victim', '#fdae6b'), ('other host', '#e6550d'), ('unresolved', '#bdbdbd'), ('none', '#f0f0f0')]
    show = ['S0', 'S2', 'S3', 'S4', 'S5', 'S6']
    ms = [m for m in models if m != 'llama3.2-3b']
    fig, axs = plt.subplots(1, len(ms), figsize=(7.2, 2.4), sharey=True)
    axs = np.atleast_1d(axs)
    for ax, m in zip(axs, ms):
        bottom = np.zeros(len(show))
        for c, col in cats:
            vals = np.array([er.get(f'{m}|{s}', {}).get(c, 0) / max(er.get(f'{m}|{s}', {}).get('n', 1), 1) for s in show])
            ax.bar(range(len(show)), vals, bottom=bottom, color=col, edgecolor='#666666', lw=0.3, label=c)
            bottom += vals
        ax.set_xticks(range(len(show))); ax.set_xticklabels(show, fontsize=7); ax.set_title(MNAME[m], fontsize=8)
    axs[0].set_ylabel('share of attack bundles')
    axs[-1].legend(fontsize=6, frameon=False, loc='upper left', bbox_to_anchor=(1.0, 1.0))
    fig.tight_layout(); fig.savefig(P / 'a_fig_errors.pdf'); plt.close(fig)


def method_fig():
    fig, ax = plt.subplots(figsize=(7.2, 2.2)); ax.axis('off'); ax.set_xlim(0, 100); ax.set_ylim(0, 30)
    def box(x, y, w, h, t, c):
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle='round,pad=0.3', fc=c, ec='#555555', lw=0.6))
        ax.text(x + w / 2, y + h / 2, t, ha='center', va='center', fontsize=6.5)
    def arr(x1, y1, x2, y2):
        ax.annotate('', xy=(x2, y2), xytext=(x1, y1), arrowprops=dict(arrowstyle='->', lw=0.7, color='#333333'))
    box(1, 17, 15, 10, 'AIT-ADS alerts\n8 scenarios\nSuricata, Wazuh, AMiner', '#f0f0f0')
    box(21, 17, 15, 10, 'Ground truth\nstep windows,\nattacker host', '#f0f0f0')
    box(41, 17, 15, 10, 'Alert bundles\n(2 min, <=8 lines)\nverdict, stage,\nhosts, target', '#deebf7')
    box(61, 17, 15, 10, 'Tagger\nIP, host, domain,\nuser, e-mail', '#deebf7')
    box(81, 17, 17, 10, 'Masking ladder\nS0 none ... S6 per-bundle\n+ surrogate map', '#fee6ce')
    box(61, 2, 17, 10, 'Local analyst LLM\n(1.5B-7B, 4-bit)\nJSON: T1-T4', '#e5f5e0')
    box(81, 2, 17, 10, 'Map back and score\nutility vs S0\n(paired tests)', '#e5f5e0')
    box(31, 2, 25, 10, 'Protection audit (no LLM)\nP0 residual identifiers\nP1 attribute disclosure\nP2 linkability', '#fde0dd')
    arr(16, 22, 21, 22); arr(36, 22, 41, 22); arr(56, 22, 61, 22); arr(76, 22, 81, 22)
    arr(89, 17, 72, 12); arr(78, 7, 81, 7); arr(85, 17, 50, 12)
    fig.savefig(P / 'a_fig_method.pdf', bbox_inches='tight'); plt.close(fig)


if __name__ == '__main__':
    main()
