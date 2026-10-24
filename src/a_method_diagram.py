"""Paper A: detailed methodology diagram (PNG 300 dpi + PDF) -> outputs/a_fig_method_detailed.*"""
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Rectangle, FancyArrowPatch, Circle

W = Path(__file__).resolve().parents[1]
OUT = W / 'outputs'
OUT.mkdir(exist_ok=True)
plt.rcParams.update({'font.family': 'DejaVu Sans', 'font.size': 9})

C = dict(data='#2b6cb0', proc='#2c7a7b', mask='#6b46c1', out='#c05621', eval='#4a5568',
         soc_bg='#f0f7f4', out_bg='#fff5eb', ev_bg='#f4f5f7', ink='#1a202c', mute='#4a5568')

fig = plt.figure(figsize=(16, 9.4))
ax = fig.add_axes([0, 0, 1, 1]); ax.set_xlim(0, 100); ax.set_ylim(-3.2, 59); ax.axis('off')


def zone(x0, x1, color, label, sub):
    ax.add_patch(Rectangle((x0, 1.0), x1 - x0, 53.2, facecolor=color, edgecolor='none', zorder=0))
    ax.text((x0 + x1) / 2, 55.3, label, ha='center', va='center', fontsize=11.5, weight='bold', color=C['ink'])
    ax.text((x0 + x1) / 2, 53.2, sub, ha='center', va='center', fontsize=8.6, color=C['mute'], style='italic')


def box(x, y, w, h, n, title, lines, col, fs=8.6, title_fs=10.2):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle='round,pad=0.25,rounding_size=0.8',
                                facecolor='white', edgecolor=col, linewidth=1.6, zorder=2))
    ax.add_patch(FancyBboxPatch((x, y + h - 3.4), w, 3.4, boxstyle='round,pad=0.25,rounding_size=0.8',
                                facecolor=col, edgecolor=col, linewidth=1.6, zorder=3))
    if n:
        ax.add_patch(Circle((x + 1.9, y + h - 1.7), 1.25, facecolor='white', edgecolor='none', zorder=4))
        ax.text(x + 1.9, y + h - 1.75, n, ha='center', va='center', fontsize=9, weight='bold', color=col, zorder=5)
    ax.text(x + (3.7 if n else w / 2), y + h - 1.75, title, ha='left' if n else 'center', va='center',
            fontsize=title_fs, weight='bold', color='white', zorder=5)
    yy = y + h - 4.7
    for ln in lines:
        if isinstance(ln, tuple):
            txt, kw = ln
        else:
            txt, kw = ln, {}
        ax.text(x + 1.0, yy, txt, ha='left', va='top', fontsize=kw.get('fs', fs), color=kw.get('c', C['ink']),
                weight=kw.get('w', 'normal'), family=kw.get('fam', 'DejaVu Sans'), zorder=5)
        yy -= kw.get('dy', 1.85)


def arrow(p, q, col=C['ink'], ls='-', lw=1.5, rad=0.0, text=None, toff=(0, 0.9), tcol=None, tfs=8.2):
    a = FancyArrowPatch(p, q, arrowstyle='-|>', mutation_scale=13, color=col, lw=lw, linestyle=ls,
                        connectionstyle=f'arc3,rad={rad}', zorder=6)
    ax.add_patch(a)
    if text:
        ax.text((p[0] + q[0]) / 2 + toff[0], (p[1] + q[1]) / 2 + toff[1], text, ha='center', va='bottom',
                fontsize=tfs, color=tcol or col, style='italic', zorder=7,
                bbox=dict(facecolor='white', edgecolor='none', pad=0.6, alpha=0.9))


# ---------------- zones
zone(0.6, 61.6, C['soc_bg'], 'Inside the SOC (trusted)', 'data, keys and surrogate maps never leave')
zone(63.4, 82.2, C['out_bg'], 'Outside the SOC', 'model provider, its operators, anyone holding its logs')
zone(84.0, 99.4, C['ev_bg'], 'Evaluation', 'paired against the unmasked baseline')
ax.plot([62.5, 62.5], [1.0, 54.2], color=C['out'], lw=2.2, ls=(0, (6, 3)), zorder=1)
ax.text(62.5, 30.5, 'SOC boundary: only S(b) crosses', rotation=90, ha='center', va='center',
        fontsize=8.6, color=C['out'], weight='bold',
        bbox=dict(facecolor='white', edgecolor='none', pad=1.0))

# ---------------- inside SOC
box(1.6, 34.5, 17.2, 17.0, '1', 'AIT Alert Data Set', [
    '8 emulated enterprise testbeds', 'Suricata · Wazuh · AMiner', '2.66 M alerts (CC BY 4.0)',
    'multi-step attack chain:', ('scans → web scan → webshell →', {'fs': 8.0, 'c': C['mute']}),
    ('cracking → shell → priv-esc → exfil', {'fs': 8.0, 'c': C['mute']})], C['data'])
box(1.6, 2.3, 17.2, 30.0, '2', 'Ground truth', [
    ('Attack label for an alert:', {'w': 'bold'}), 'inside an attack-step window', 'AND mentions the attacker',
    'OR rule fires < 2/day outside', ('', {'dy': 1.0}),
    ('Attacker address:', {'w': 'bold'}), 'dominates dirb / wpscan lines', '= inner address of the',
    'VPN gateway (monitored server)', ('', {'dy': 1.0}),
    ('Per bundle:', {'w': 'bold'}), 'y1 verdict · y2 stage (7 + benign)', 'H involved hosts · c containment'],
    C['data'])
box(21.0, 34.5, 17.6, 17.0, '3', 'Alert bundles', [
    'anchor alert, window −30 s … +90 s', 'identical alerts grouped (× count)', '≤ 8 lines, raw text ≤ 160 chars',
    ('351 bundles', {'w': 'bold'}), '192 attack · 159 benign', '7 attack stages + benign'], C['proc'])
box(21.0, 13.5, 17.6, 18.8, '4', 'Identifier tagger', [
    'IPv4 · host · domain · user · e-mail', 'regex + structured Wazuh fields', 'system accounts kept (root, www-data)',
    ('P0 consistency check:', {'w': 'bold'}), 'structured-field inventory', 'searched in every masked bundle',
    ('→ 1 residual name in 2 bundles', {'c': C['mute']})], C['proc'])

# masking ladder
mx, my, mw, mh = 40.6, 13.5, 20.2, 38.0
box(mx, my, mw, mh, '5', 'Masking ladder  S(b)', [], C['mask'])
rows = [('S0', 'none', '192.168.230.122'), ('S1', 'redact', '[IP]'), ('S2', 'random', 'IP_3694'),
        ('S3', 'consistent', 'IP_2'), ('S4', 'global Crypto-PAn', '39.96.239.6'), ('S5', 'role', 'INT_HOST_1'),
        ('S6', 'per-bundle C-PAn', '49.161.102.122')]
yy = my + mh - 5.6
for i, (s, name, ex) in enumerate(rows):
    if i % 2 == 0:
        ax.add_patch(Rectangle((mx + 0.4, yy - 1.55), mw - 0.8, 3.1, facecolor='#f3effb', edgecolor='none', zorder=3))
    ax.text(mx + 1.0, yy, s, fontsize=9, weight='bold', color=C['mask'], va='center', zorder=5)
    ax.text(mx + 3.6, yy, name, fontsize=8.4, va='center', color=C['ink'], zorder=5)
    ax.text(mx + mw - 0.8, yy, ex, fontsize=8.0, va='center', ha='right', family='DejaVu Sans Mono', color=C['ink'], zorder=5)
    yy -= 3.15
ax.text(mx + 1.0, yy - 0.2, 'links ✓: S3–S6   roles kept: S5   global key: S4', fontsize=7.8, color=C['mute'], va='center', zorder=5)
ax.text(mx + 1.0, yy - 2.5, 'Ablation (one type redacted):', fontsize=8.4, weight='bold', va='center', zorder=5)
ax.text(mx + 1.0, yy - 4.6, 'R_ip · R_name · R_user  (Qwen2.5-3B)', fontsize=8.2, va='center', zorder=5)

# surrogate map
ax.add_patch(FancyBboxPatch((40.6, 2.3), 20.2, 8.6, boxstyle='round,pad=0.25,rounding_size=0.8',
                            facecolor='#faf5ff', edgecolor=C['mask'], linewidth=1.4, linestyle='--', zorder=2))
ax.text(50.7, 8.6, 'Surrogate map  μ(b,S)  +  secret key', ha='center', fontsize=9.2, weight='bold', color=C['mask'], zorder=5)
ax.text(50.7, 5.9, 'kept in the SOC; maps answers back', ha='center', fontsize=8.2, color=C['ink'], zorder=5)
ax.text(50.7, 3.7, '(S6 key = HMAC(master, bundle id))', ha='center', fontsize=7.8, color=C['mute'], zorder=5)

# ---------------- outside SOC
box(64.2, 29.5, 17.2, 22.0, '6', 'LLM analysts', [
    ('receives S(b) + privacy notice', {'c': C['out'], 'w': 'bold'}), ('local 4-bit · greedy · JSON grammar', {'c': C['mute']}), 'Qwen2.5-1.5B · 3B · 7B', 'Llama-3.2-3B · Qwen3-4B',
    ('', {'dy': 0.8}),
    ('Answers four tasks:', {'w': 'bold'}), 'T1 verdict (escalate/close)', 'T2 attack stage',
    'T3 involved hosts', 'T4 host to contain'], C['out'])
box(64.2, 2.3, 17.2, 24.8, '7', 'Recipient adversary', [
    ('sees only S(b); no LLM', {'c': C['out'], 'w': 'bold'}), ('P1 attribute disclosure', {'w': 'bold'}),
    'logistic regression on ±12 context', 'tokens + surrogate form', 'leave-one-scenario-out', '→ internet? monitored? attacker?', ('P2 linkability', {'w': 'bold'}), 'same host in two bundles?',
    'surrogate equality + context cosine', '4,000 same + 4,000 different pairs'], C['out'])

# ---------------- evaluation
box(85.0, 29.5, 13.6, 22.0, '8', 'Map back & score', [
    'answers → μ → real hosts', 'unresolved strings = FP', ('', {'dy': 0.8}),
    ('Paired vs S0', {'w': 'bold'}), '(identical bundles)', 'T1/T4: exact McNemar', 'T2/T3: paired bootstrap',
    'Holm in 3 families', '95 % intervals'], C['eval'])
box(85.0, 2.3, 13.6, 24.8, '9', 'Trade-off', [
    ('utility (T3, T4)', {'w': 'bold'}), 'vs', ('linkability (P2)', {'w': 'bold'}), '+ attribute', 'disclosure (P1)',
    ('', {'dy': 0.8}), ('→ scheme × analyst', {'c': C['mute']}), ('   recommendation', {'c': C['mute']})], C['eval'])

# ---------------- arrows
arrow((18.8, 43.0), (21.0, 43.0))
arrow((10.2, 34.5), (10.2, 32.3))
ax.plot([18.8, 19.9, 19.9], [24.0, 24.0, 37.5], color=C['ink'], lw=1.5, zorder=6)
arrow((19.9, 37.5), (21.0, 37.5))
ax.text(19.9, 30.5, 'labels', rotation=90, ha='center', va='center', fontsize=7.8, style='italic', color=C['ink'], zorder=7, bbox=dict(facecolor=C['soc_bg'], edgecolor='none', pad=0.3))
arrow((29.8, 34.5), (29.8, 32.3))
arrow((38.6, 23.0), (40.6, 23.0))
arrow((50.7, 13.5), (50.7, 10.9), col=C['mask'], text=None)
arrow((60.8, 46.0), (64.2, 46.0), col=C['out'], lw=2.2)
arrow((60.8, 15.0), (64.2, 15.0), col=C['out'], lw=2.2)
arrow((81.4, 40.0), (85.0, 40.0), col=C['eval'], lw=1.8, text='JSON', toff=(0, 1.0))
arrow((81.4, 12.0), (85.0, 12.0), col=C['eval'], lw=1.8, text='AUROC', toff=(0, 1.0))
arrow((91.8, 29.5), (91.8, 27.1), col=C['eval'], lw=1.8)
# surrogate map back to scoring (runs below the outside zone, never through it)
ax.plot([50.7, 50.7], [2.3, -1.6], color=C['mask'], lw=1.5, ls='--', zorder=6)
ax.plot([50.7, 83.3], [-1.6, -1.6], color=C['mask'], lw=1.5, ls='--', zorder=6)
ax.plot([83.3, 83.3], [-1.6, 33.0], color=C['mask'], lw=1.5, ls='--', zorder=6)
ax.annotate('', xy=(85.0, 33.0), xytext=(83.3, 33.0),
            arrowprops=dict(arrowstyle='-|>', color=C['mask'], lw=1.5, mutation_scale=12))
ax.text(67.0, -2.7, 'μ goes to scoring only; it is never sent across the boundary', ha='center', va='center',
        fontsize=8.2, color=C['mask'], style='italic', zorder=7)

fig.savefig(OUT / 'a_fig_method_detailed.png', dpi=300)
fig.savefig(OUT / 'a_fig_method_detailed.pdf')
print('written', OUT / 'a_fig_method_detailed.png')
