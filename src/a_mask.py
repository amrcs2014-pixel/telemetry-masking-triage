"""Paper A: masking schemes applied to a bundle's text.

S0 none           identifiers shown as logged
S1 redact         every identifier replaced by its type label ([IP], [HOST], [DOMAIN], [USER], [EMAIL])
S2 random         a fresh random token per occurrence (IP_7f3a, ...), so mentions cannot be linked
S3 consistent     one token per distinct identifier within the bundle (IP_1, HOST_1, USER_1, ...)
S4 global         deterministic across the whole corpus: Crypto-PAn (prefix-preserving) for IPv4,
                  keyed-hash tokens for names (HOST_3f9a2c ...); same entity -> same token everywhere
S5 role           per-bundle tokens that keep only the zone and asset class
                  (INT_SRV_1 = internal monitored host, INT_HOST_2, EXT_HOST_1, ORG_DOMAIN_1, EXT_DOMAIN_1, USER_1)

mask(bundle, scheme) -> (text, surrogate->original map, spans)
"""
import hashlib, hmac, random
from yacryptopan import CryptoPAn
from a_entities import tag

SCHEMES = ['S0', 'S1', 'S2', 'S3', 'S4', 'S5', 'S6']
NAMES = {'S0': 'none', 'S1': 'redact', 'S2': 'random', 'S3': 'consistent', 'S4': 'global', 'S5': 'role',
         'S6': 'per-bundle format-preserving'}
# ablation: redact one identifier type only (everything else as logged)
ABLATION = {'Rip': {'ip'}, 'Rname': {'host', 'domain'}, 'Ruser': {'user', 'email'}}
_KEY = b'p1920-masking-key-not-secret-0001'
_CPAN = CryptoPAn(hashlib.sha256(_KEY).digest())
LABEL = {'ip': 'IP', 'host': 'HOST', 'domain': 'DOMAIN', 'user': 'USER', 'email': 'EMAIL'}


def _h(t, v):
    return hmac.new(_KEY, f'{t}:{v}'.encode(), hashlib.sha256).hexdigest()[:6]


def role_label(t, ent):
    if t == 'ip' or t == 'host':
        z = 'INT' if ent['zone'] == 'internal' else 'EXT'
        return f"{z}_{'SRV' if ent['monitored'] else 'HOST'}"
    if t == 'domain':
        return 'ORG_DOMAIN' if ent['zone'] == 'internal' else 'EXT_DOMAIN'
    return LABEL[t]


def mask(bundle, scheme, seed=0):
    t, smap, spans, _ = _mask(bundle, scheme, seed)
    return t, smap, spans


def mask_positions(bundle, scheme, seed=0):
    """Masked text + (start, end, type, original, surrogate) of every tagged span in the masked text."""
    t, _, _, pos = _mask(bundle, scheme, seed)
    return t, pos


def _mask(bundle, scheme, seed=0):
    text = bundle['text']
    spans = tag(text, bundle['known_hosts'], bundle['known_users'])
    if scheme == 'S0':
        return text, {v: v for *_, v in spans}, spans, [(s, e, t, v, v) for s, e, t, v in spans]
    ents = bundle['entities']
    pos, olen = [], 0
    rng = random.Random(f"{bundle['id']}-{seed}")
    counters, per_bundle, smap = {}, {}, {}
    out, last, bcp = [], 0, None
    for s, e, t, v in spans:
        ent = ents.get(v, {'zone': 'internal', 'monitored': False})
        if scheme in ABLATION and t not in ABLATION[scheme]:
            pos.append((olen + s - last, olen + s - last + len(v), t, v, v))
            continue  # left as logged; it is copied with the surrounding text
        if scheme == 'S1' or scheme in ABLATION:
            sur = f'[{LABEL[t]}]'
        elif scheme == 'S2':
            while True:
                sur = f'{LABEL[t]}_{rng.getrandbits(16):04x}'
                if sur not in smap:
                    break
        elif scheme == 'S3' or scheme == 'S5':
            lab = LABEL[t] if scheme == 'S3' else role_label(t, ent)
            if v not in per_bundle:
                counters[lab] = counters.get(lab, 0) + 1
                per_bundle[v] = f'{lab}_{counters[lab]}'
            sur = per_bundle[v]
        elif scheme == 'S4':
            sur = _CPAN.anonymize(v) if t == 'ip' else f'{LABEL[t]}_{_h(t, v)}'
        elif scheme == 'S6':  # S4's format with a key drawn per bundle: realistic, prefix-preserving, not linkable
            if bcp is None:
                bk = hmac.new(_KEY, ('bundle:' + bundle['id']).encode(), hashlib.sha256).digest()
                bcp = CryptoPAn(bk)
            sur = bcp.anonymize(v) if t == 'ip' else f"{LABEL[t]}_{_h(t, bundle['id'] + ':' + v)}"
        else:
            raise ValueError(scheme)
        smap.setdefault(sur, None if (scheme == 'S1' or scheme in ABLATION) else v)  # a type label denotes no host
        out.append(text[last:s]); olen += s - last
        pos.append((olen, olen + len(sur), t, v, sur))
        out.append(sur); olen += len(sur); last = e
    out.append(text[last:])
    return ''.join(out), smap, spans, pos


if __name__ == '__main__':
    import json, sys
    from pathlib import Path
    B = json.load(open(Path(__file__).resolve().parents[1] / 'data' / 'a_bundles.json'))
    b = B[int(sys.argv[1]) if len(sys.argv) > 1 else 75]
    for sc in SCHEMES:
        t, m, _ = mask(b, sc)
        print(f'===== {sc} ({NAMES[sc]})'); print(t.splitlines()[2][:300])
