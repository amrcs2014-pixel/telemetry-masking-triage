"""Paper A Figure 1 (layout supplied by the author): SOC trust boundary, masking ladder, utility and protection paths.
Writes outputs/a_fig1_overview.pdf (vector) and .png (300 dpi)."""
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
matplotlib.rcParams['pdf.fonttype'] = 42  # embed TrueType, not Type 3, fonts in PDF figures
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle

W = Path(__file__).resolve().parents[1]
OUT = W / 'outputs'
OUT.mkdir(exist_ok=True)
plt.rcParams.update({'font.family': 'DejaVu Sans', 'mathtext.fontset': 'dejavusans'})
INK, BLUE, RED, GREEN = '#111111', '#1f3b73', '#c8102e', '#2e7d32'

fig = plt.figure(figsize=(16, 8.6))
ax = fig.add_axes([0, 0, 1, 1]); ax.set_xlim(0, 100); ax.set_ylim(0, 54); ax.axis('off')


def rbox(x, y, w, h, fc, ec, lw=1.8, ls='-', r=1.2, z=1):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle=f'round,pad=0,rounding_size={r}', facecolor=fc,
                                edgecolor=ec, linewidth=lw, linestyle=ls, zorder=z))


def arr(p, q, col=INK, lw=2.6, ms=20, z=6):
    ax.add_patch(FancyArrowPatch(p, q, arrowstyle='-|>', mutation_scale=ms, color=col, lw=lw, zorder=z))


# ---------------- SOC trust boundary (top)
rbox(1.5, 22.0, 97.0, 30.8, '#e6effa', BLUE, lw=1.6, ls=(0, (4, 2.5)), r=1.6)
ax.text(50, 50.6, r'$\bf{SOC\ TRUST\ BOUNDARY}$ (on-premises controller domain: retains raw data, key $k$ and surrogate map $\mu$)',
        ha='center', va='center', fontsize=15, color=INK)

stages = [(9.0, 'AIT-ADS\ntelemetry', '(8 scenarios,\nSuricata,\nWazuh, AMiner)'),
          (23.0, 'Ground-truth\nlabelling', '(verdict $y_1$,\nstage $y_2$, hosts\n$H$, target $c$)'),
          (37.0, 'Alert\nbundles', '(351 bundles,\n2-min window)'),
          (49.5, 'Identifier\ntagger', '(IP, host,\ndomain, user,\ne-mail)')]
for x, t, s in stages:
    ax.text(x, 40.4, t, ha='center', va='bottom', fontsize=15, weight='bold', color=INK, linespacing=1.15)
    ax.text(x, 39.6, s, ha='center', va='top', fontsize=13, color=INK, linespacing=1.25)
for x0, x1 in [(14.6, 17.4), (28.7, 31.5), (41.9, 44.7), (54.4, 57.0)]:
    arr((x0, 39.4), (x1, 39.4), lw=3.0, ms=24)

# masking ladder table
tx, ty, tw, th = 57.3, 29.4, 40.4, 19.0
ax.add_patch(Rectangle((tx, ty), tw, th, facecolor='white', edgecolor=BLUE, lw=1.8, zorder=2))
ax.add_patch(Rectangle((tx, ty + th - 3.0), tw, 3.0, facecolor='#dbe7f7', edgecolor=BLUE, lw=1.8, zorder=3))
ax.text(tx + tw / 2, ty + th - 1.5, 'Masking ladder and real surrogate examples', ha='center', va='center',
        fontsize=14.5, weight='bold', color=INK, zorder=4)
rows = [('S0 none', '192.168.230.122:34642', '172.19.130.68:80'),
        ('S1 redact', '[IP]:34642', '[IP]:80'),
        ('S2 random', 'IP_3694:34642', 'IP_e77a:80'),
        ('S3 consistent', 'IP_2:34642', 'IP_3:80'),
        ('S4 global Crypto-PAn', '39.96.239.6:34642', '80.111.181.196:80'),
        ('S5 role', 'INT_HOST_1:34642', 'INT_SRV_2:80'),
        ('S6 per-bundle Crypto-PAn', '49.161.102.122:34642', '85.108.29.188:80')]
rh = (th - 3.0) / len(rows)
for i, (name, a, b) in enumerate(rows):
    y = ty + th - 3.0 - (i + 0.5) * rh
    if i:
        ax.plot([tx, tx + tw], [y + rh / 2, y + rh / 2], color='#8aa1c1', lw=0.8, zorder=3)
    ax.text(tx + 0.6, y, name, ha='left', va='center', fontsize=11.8, color=INK, zorder=4)
    ax.text(tx + 26.3, y, a, ha='right', va='center', fontsize=11.2, family='DejaVu Sans Mono', color=INK, zorder=4)
    ax.text(tx + 26.8, y, '->', ha='left', va='center', fontsize=11.2, family='DejaVu Sans Mono', color=INK, zorder=4)
    ax.text(tx + 29.0, y, b, ha='left', va='center', fontsize=11.2, family='DejaVu Sans Mono', color=INK, zorder=4)

# secret store and back-mapping (both inside the SOC)
rbox(4.0, 23.3, 17.5, 5.0, '#e6effa', BLUE, lw=2.0, r=0.8, z=3)
ax.text(12.75, 25.8, r'$\bf{SOC\ secret\ store}$' + '\n' + r'(key $k$ and map $\mu_{b,S}$)', ha='center', va='center',
        fontsize=13.5, color=INK, zorder=4, linespacing=1.3)
rbox(63.0, 23.3, 33.5, 5.0, '#e6effa', BLUE, lw=2.0, r=0.8, z=3)
ax.text(79.75, 25.8, r'$\bf{Back\text{-}mapping\ and\ paired\ utility}$' + '\n' + r'$\bf{scoring\ vs\ S0}$ (McNemar and bootstrap)',
        ha='center', va='center', fontsize=13.5, color=INK, zorder=4, linespacing=1.3)
ax.add_patch(FancyArrowPatch((21.5, 24.6), (63.0, 24.6), arrowstyle='-|>', mutation_scale=18, color=BLUE, lw=1.8,
                             linestyle=(0, (5, 3)), zorder=5))
ax.text(42.3, 25.4, r'$\mu_{b,S}$ maps answers back (never leaves the SOC)', ha='center', va='bottom', fontsize=11.5,
        style='italic', color=BLUE, zorder=5)

# ---------------- boundary line
ax.plot([0, 100], [19.2, 19.2], color=RED, lw=3.2, ls=(0, (6, 4)), zorder=1)

# masked bundle crossing the boundary, splitting to both paths
ax.plot([47.0, 47.0], [22.0, 14.8], color=INK, lw=3.0, zorder=5)
ax.text(46.2, 19.2, 'Masked bundle $S(b)$ + privacy notice', ha='right', va='center', fontsize=14.5, weight='bold',
        color=INK, zorder=7, bbox=dict(facecolor='white', edgecolor='none', pad=1.5), linespacing=1.25)
ax.plot([26.0, 26.0, 47.0, 70.0, 70.0], [13.8, 14.8, 14.8, 14.8, 13.8], color=INK, lw=3.0, zorder=5)
arr((26.0, 14.0), (26.0, 12.6), lw=3.0, ms=22)
arr((70.0, 14.0), (70.0, 12.6), lw=3.0, ms=22)

# JSON answer back up into the SOC
arr((85.0, 12.6), (85.0, 23.3), lw=3.0, ms=24)
ax.text(85.8, 19.2, 'JSON answer $A(S(b))$', ha='left', va='center', fontsize=14.5, weight='bold', color=INK,
        zorder=7, bbox=dict(facecolor='white', edgecolor='none', pad=1.5), linespacing=1.25)

# ---------------- external domain (bottom)
rbox(1.5, 0.8, 97.0, 15.6, '#f4f4f4', INK, lw=2.0, r=1.6, z=0)
ax.text(50, 2.4, 'EXTERNAL / UNTRUSTED RECIPIENT DOMAIN', ha='center', va='center', fontsize=15, weight='bold', color=INK)
rbox(9.0, 4.4, 34.0, 8.2, '#fbd5d5', RED, lw=2.2, r=0.8, z=3)
ax.text(26.0, 8.5, r'$\bf{Protection\ audit\ path\ (no\ LLM):}$' + '\n' + r'$\bf{P0}$ residual identifiers' + '\n' +
        r'$\bf{P1}$ attribute disclosure (AUROC)' + '\n' + r'$\bf{P2}$ cross-bundle linkability (AUROC)',
        ha='center', va='center', fontsize=13.5, color=INK, zorder=4, linespacing=1.3)
rbox(53.0, 4.4, 34.0, 8.2, '#dcefd8', GREEN, lw=2.2, r=0.8, z=3)
ax.text(70.0, 8.5, r'$\bf{Utility\ path\ (local\ analyst\ LLMs,\ 1.5\text{-}7B,\ 4\text{-}bit):}$' + '\n' +
        r'JSON output: $\bf{T1}$ verdict, $\bf{T2}$ stage,' + '\n' + r'$\bf{T3}$ involved hosts, $\bf{T4}$ containment',
        ha='center', va='center', fontsize=13.5, color=INK, zorder=4, linespacing=1.35)

fig.savefig(OUT / 'a_fig1_overview.pdf')
fig.savefig(OUT / 'a_fig1_overview.png', dpi=300)
print('written', OUT / 'a_fig1_overview.pdf')
