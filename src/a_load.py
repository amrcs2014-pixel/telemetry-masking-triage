"""Paper A: parse AIT-ADS alerts (Wazuh + AMiner) of all scenarios into one table with
attack-step labels and the structured entities each alert carries.

Label rule (per scenario):
  * attacker host = IP with the most raw-log mentions inside the dirb/wpscan windows;
  * an alert is attack-related if it lies inside an attack-step window AND
      (it mentions the attacker IP, OR its rule fires rarely outside the windows
       (< RARE_PER_DAY times per day), i.e. it is not routine background noise).
Output: data/a_alerts.pkl (pandas DataFrame) + data/a_meta.json
"""
import json, csv, re, collections, ipaddress, pickle
from datetime import datetime
from pathlib import Path
import pandas as pd

D = Path(__file__).resolve().parents[1] / 'data'
SCEN = ['russellmitchell', 'santos', 'shaw', 'wardbeck', 'fox', 'harrison', 'wheeler', 'wilson']
RARE_PER_DAY = 2.0
IPRE = re.compile(r'(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])')
STEP2STAGE = {'network_scans': 'reconnaissance', 'service_scans': 'reconnaissance', 'dirb': 'web_scanning',
              'wpscan': 'web_scanning', 'webshell': 'web_exploitation', 'cracking': 'password_cracking',
              'reverse_shell': 'remote_shell', 'privilege_escalation': 'privilege_escalation',
              'service_stop': 'service_disruption', 'dnsteal': 'exfiltration'}


def ts_of(s):
    return datetime.fromisoformat(s.replace('Z', '+00:00')).timestamp()


def valid_ip(x):
    try:
        ipaddress.IPv4Address(x); return True
    except ValueError:
        return False


def wazuh_row(o):
    d = o.get('data', {}) or {}
    pre = o.get('predecoder', {}) or {}
    desc = o.get('rule', {}).get('description', '')
    loc = o.get('location', '')
    ids = 'suricata' if ('suricata' in loc or 'Suricata' in desc or o.get('decoder', {}).get('name') in ('json', 'snort')) else 'wazuh'
    users = set()
    for k in ('dstuser', 'srcuser', 'user'):
        v = d.get(k)
        if isinstance(v, str) and v and v not in ('root',):
            users.add(v.split(':')[-1])
    http = d.get('http', {}) if isinstance(d.get('http'), dict) else {}
    hosts = set()
    if pre.get('hostname'): hosts.add(pre['hostname'])
    if http.get('hostname'): hosts.add(http['hostname'])
    raw = o.get('full_log') or ''
    if not raw and d.get('alert'):  # eve.json alert without fast.log line
        a = d['alert']
        raw = (f"[{a.get('signature_id','')}] {a.get('signature','')} [Classification: {a.get('category','')}] "
               f"{{{d.get('proto','')}}} {d.get('src_ip','')}:{d.get('src_port','')} -> {d.get('dest_ip','')}:{d.get('dest_port','')}")
        if http.get('hostname'):
            raw += f" host={http.get('hostname')} url={http.get('url','')}"
    return dict(ids=ids, rule=desc, level=int(o.get('rule', {}).get('level', 0) or 0),
                agent_ip=o.get('agent', {}).get('ip', ''), host=pre.get('hostname', ''),
                users=sorted(users), hosts=sorted(hosts), raw=raw, loc=loc)


def aminer_row(o):
    ld = o.get('LogData', {})
    raw = ' || '.join(ld.get('RawLogData', [])[:2])
    ac = o.get('AnalysisComponent', {})
    # syslog "Mon DD HH:MM:SS host program[pid]: ..." ; some lines carry no hostname
    m = re.match(r'^\w{3}\s+\d+\s[\d:]+\s([\w.-]+)\s+[\w./-]+(?:\[\d+\])?:', raw)
    return dict(ids='aminer', rule=f"AMiner: {ac.get('AnalysisComponentName','').replace('AMiner: ','')} ({ac.get('AnalysisComponentType','')})",
                level=0, agent_ip=o.get('AMiner', {}).get('ID', ''), host=m.group(1) if m else '',
                users=[], hosts=[m.group(1)] if m else [], raw=raw, loc=','.join(ld.get('LogResources', [])))


def load(sc, labels):
    W = [(r['attack'], float(r['start']), float(r['end'])) for r in labels if r['scenario'] == sc]
    def step_of(t):
        for a, s, e in W:
            if s <= t <= e: return a
        return ''
    rows = []
    for l in open(D / 'ait' / f'{sc}_wazuh.json', encoding='utf-8'):
        o = json.loads(l); r = wazuh_row(o); r['ts'] = ts_of(o['@timestamp']); rows.append(r)
    for l in open(D / 'ait' / f'{sc}_aminer.json', encoding='utf-8'):
        o = json.loads(l); r = aminer_row(o)
        t = o.get('LogData', {}).get('DetectionTimestamp') or o.get('LogData', {}).get('Timestamps') or [0]
        r['ts'] = float(t[0]); rows.append(r)
    df = pd.DataFrame(rows)
    df['scenario'] = sc
    df['step'] = [step_of(t) for t in df.ts]
    df['ips'] = [sorted({x for x in IPRE.findall(r) if valid_ip(x)} | ({a} if a else set()))
                 for r, a in zip(df.raw, df.agent_ip)]
    df['raw_ips'] = [sorted({x for x in IPRE.findall(r) if valid_ip(x)}) for r in df.raw]
    # attacker host
    # the attacker host is itself monitored (it carries a Wazuh agent), so no agent exclusion:
    # it is the IP mentioned in raw log lines most often inside the dirb + wpscan windows
    web = df[df.step.isin(['dirb', 'wpscan'])]
    cnt = collections.Counter(ip for ips in web.raw_ips for ip in ips)
    attacker = max((n, ip) for ip, n in cnt.items())[1]
    # rule background rates
    span_days = (df.ts.max() - df.ts.min()) / 86400
    out = df[df.step == '']
    out_days = max(span_days - sum(e - s for _, s, e in W) / 86400, 0.1)
    rate = (out.groupby('rule').size() / out_days).to_dict()
    df['mentions_attacker'] = [attacker in ips for ips in df.raw_ips]
    df['rare'] = [rate.get(r, 0.0) < RARE_PER_DAY for r in df.rule]
    df['attack'] = (df.step != '') & (df.mentions_attacker | df.rare)
    df['stage'] = [STEP2STAGE[s] if (a and s) else 'benign' for s, a in zip(df.step, df.attack)]
    return df, dict(attacker=attacker, span_days=round(span_days, 2), n=len(df),
                    n_attack=int(df.attack.sum()), steps=[w[0] for w in W])


if __name__ == '__main__':
    labels = list(csv.DictReader(open(D / 'labels.csv')))
    parts, meta = [], {}
    for sc in SCEN:
        df, m = load(sc, labels)
        parts.append(df); meta[sc] = m
        by = df[df.attack].groupby('step').size().to_dict()
        print(sc, m, by, flush=True)
    allf = pd.concat(parts, ignore_index=True)
    allf.to_pickle(D / 'a_alerts.pkl')
    json.dump(meta, open(D / 'a_meta.json', 'w'), indent=1)
    print('total', len(allf), 'attack', int(allf.attack.sum()))
