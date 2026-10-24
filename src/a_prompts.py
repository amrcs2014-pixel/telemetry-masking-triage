"""Paper A: build the analyst prompts for every (bundle, masking scheme) -> data/a_prompts.jsonl
(plus the surrogate maps needed for scoring -> data/a_maps.json). Precomputing keeps the GPU
runner free of non-stdlib dependencies.
"""
import json
from pathlib import Path
from a_mask import mask, SCHEMES, ABLATION

D = Path(__file__).resolve().parents[1] / 'data'
STAGES = ['reconnaissance', 'web_scanning', 'web_exploitation', 'password_cracking', 'remote_shell',
          'privilege_escalation', 'exfiltration', 'benign']

SYSTEM = (
    "You are a tier-1 SOC analyst assistant. You receive a bundle of security alerts (Suricata, Wazuh, "
    "AMiner) collected within about two minutes from one organisation's network. Each line shows: time | "
    "sensor | rule | host that logged it | raw log or alert text, with a repeat count (xN) when identical "
    "alerts were grouped.\n"
    "Decide:\n"
    "1. verdict: \"escalate\" if the bundle shows malicious activity that needs investigation, \"close\" if it "
    "is routine or benign noise.\n"
    "2. stage: the attack stage it most likely shows, one of: reconnaissance (network or service scans), "
    "web_scanning (directory or CMS scanning of a web server), web_exploitation (exploiting a web "
    "application, e.g. a webshell upload), password_cracking (guessing or cracking credentials), "
    "remote_shell (a reverse or remote shell), privilege_escalation (gaining root or another user's rights "
    "on a host), exfiltration (data leaving the network, e.g. over DNS), or benign.\n"
    "3. involved: the identifiers of the hosts that take part in the attack (the attacker and the targeted "
    "hosts), written exactly as they appear in the alerts, without ports. Empty list if there is no attack.\n"
    "4. contain: the single identifier that should be blocked or isolated first, exactly as it appears in "
    "the alerts, or \"none\".\n"
    "Answer with a single-line JSON object only."
)
NOTICE = {
    'S0': '',
    'S1': "Privacy notice: identifiers in these alerts were redacted and replaced by their type, e.g. [IP], "
          "[HOST], [DOMAIN], [USER].",
    'S2': "Privacy notice: identifiers in these alerts were replaced by random placeholders such as IP_7f3a or "
          "USER_19c2. Every occurrence received its own placeholder, so two placeholders may refer to the same "
          "identifier.",
    'S3': "Privacy notice: identifiers in these alerts were replaced by placeholders such as IP_1, HOST_2, "
          "DOMAIN_1 or USER_1. Within this bundle the same identifier always has the same placeholder.",
    'S4': "Privacy notice: IP addresses in these alerts were pseudonymised with a prefix-preserving mapping "
          "(addresses that share a subnet still share a subnet). Host names, domains and user names were "
          "replaced by placeholders such as HOST_3f9a2c. The same identifier always has the same pseudonym.",
    'S5': "Privacy notice: identifiers in these alerts were replaced by placeholders that keep only their kind: "
          "INT_ = inside the organisation's network, EXT_ = on the internet, SRV = a monitored server, HOST = "
          "another host, ORG_DOMAIN / EXT_DOMAIN = organisation or external domain, USER = a user account. "
          "Within this bundle the same identifier always has the same placeholder.",
    'S6': "Privacy notice: IP addresses in these alerts were pseudonymised with a prefix-preserving mapping "
          "(addresses that share a subnet still share a subnet). Host names, domains and user names were "
          "replaced by placeholders such as HOST_3f9a2c. Within this bundle the same identifier always has the same "
          "pseudonym; pseudonyms are drawn afresh for every bundle.",
    'S0n': "Privacy notice: these alerts are shared under the organisation's data-handling policy. IP addresses, "
           "host names, domains and user names appear exactly as they were logged; nothing was replaced, "
           "redacted or pseudonymised.",
    'Rip': "Privacy notice: IP addresses in these alerts were redacted and replaced by [IP].",
    'Rname': "Privacy notice: host names and domain names in these alerts were redacted and replaced by [HOST] and [DOMAIN].",
    'Ruser': "Privacy notice: user account names and e-mail addresses in these alerts were redacted and replaced by [USER] "
             "and [EMAIL].",
}
CONTROL = {'S0n': 'S0'}  # notice-matched control: S0 text with a neutral notice
SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["escalate", "close"]},
        "stage": {"type": "string", "enum": STAGES},
        "involved": {"type": "array", "items": {"type": "string", "maxLength": 60}, "maxItems": 6},
        "contain": {"type": "string", "maxLength": 60},
    },
    "required": ["verdict", "stage", "involved", "contain"],
}


def user_msg(text, scheme):
    n = NOTICE[scheme]
    return (n + "\n\n" if n else "") + "Alerts:\n" + text + "\n\nReturn JSON with keys verdict, stage, involved, contain."


def main():
    B = json.load(open(D / 'a_bundles.json'))
    maps = {}
    with open(D / 'a_prompts.jsonl', 'w', encoding='utf-8') as f:
        for b in B:
            for s in SCHEMES + list(ABLATION) + list(CONTROL):
                t, m, _ = mask(b, CONTROL.get(s, s))
                f.write(json.dumps(dict(id=f"{b['id']}|{s}", bundle=b['id'], scheme=s,
                                        messages=[{"role": "system", "content": SYSTEM},
                                                  {"role": "user", "content": user_msg(t, s)}])) + '\n')
                maps[f"{b['id']}|{s}"] = m
    json.dump(maps, open(D / 'a_maps.json', 'w'))
    json.dump(SCHEMA, open(D / 'a_schema.json', 'w'))
    print(len(B) * (len(SCHEMES) + len(ABLATION) + len(CONTROL)), 'prompts')


if __name__ == '__main__':
    main()
