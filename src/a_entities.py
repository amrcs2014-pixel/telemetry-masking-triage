"""Paper A: entity tagger for rendered alert lines.

Entity types: ip, email, domain, host, user. System accounts (root, www-data, ...) are kept
visible on purpose: they are not personal identifiers and carry triage meaning.
`tag(text, known)` returns non-overlapping spans (start, end, type, value); `known` holds the
scenario's hostnames and usernames taken from structured alert fields.
"""
import re, ipaddress

SYSTEM_USERS = {'root', 'www-data', 'www', 'data', 'nobody', 'daemon', 'mail', 'postfix', 'dovecot', 'sshd',
                'systemd', 'syslog', 'bin', 'sys', 'admin', 'user', 'unknown', 'news', 'backup', 'ubuntu'}
TLDS = ('com|net|org|io|de|at|cloud|biz|info|eu|edu|gov|uk|co|us|local|lan|internal|ru|cn|jp|fr|it|nl|'
        'me|ly|tv|app|dev|xyz|online|site|top|be|ch|es|pl|se|no|fi|dk|cz|gr|tr|in|br|au|ca|gl|to|ai|nz|za|'
        'kr|tw|hk|sg|ir|ua|mx|ar|cl|pt|ie|ro|hu|sk|lt|lv|ee|si|hr|rs|bg|is|lu|li|mobi|pro|tech|space|store|'
        'live|news|cc|ws|fm|am|gg|ms|arpa')
RE_EMAIL = re.compile(r'[\w.+-]+@[\w-]+(?:\.[\w-]+)+')
RE_IP = re.compile(r'(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.]*\d)')
RE_DOM = re.compile(r'(?<![\w/.@-])((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:' + TLDS + r'))(?![\w-])', re.I)
RE_DOM_SLASH = re.compile(r'(?<=/)((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:' + TLDS + r'))(?![\w-])', re.I)
RE_SYSLOG_HOST =re.compile(r'(?:^|\|\s)(?:\w{3}\s+\d+\s[\d:]+\s)([\w.-]+)\s')
RE_HOSTFIELD = re.compile(r'host=([\w.-]+)')
USER_PATTERNS = [re.compile(p) for p in (
    r'user=<([^>\s]+)>', r'\buser[= ]([A-Za-z][\w.-]{1,30})', r'for user ([A-Za-z][\w.-]{1,30})',
    r'FAILED LOGIN for ([A-Za-z][\w.-]{1,30})', r'[Ii]nvalid user ([A-Za-z][\w.-]{1,30})',
    r'Accepted \w+ for ([A-Za-z][\w.-]{1,30}) from', r'Failed password for (?:invalid user )?([A-Za-z][\w.-]{1,30}) from',
    r'sudo:\s+([A-Za-z][\w.-]{1,30}) :', r'logname=([A-Za-z][\w.-]{1,30})', r'ruser=([A-Za-z][\w.-]{1,30})',
    r'www-data:([A-Za-z][\w.-]{1,30})')]


def valid_ip(x):
    try:
        ipaddress.IPv4Address(x); return True
    except ValueError:
        return False


def ip_zone(x):
    try:
        return 'internal' if ipaddress.IPv4Address(x).is_private else 'external'
    except ValueError:
        return 'external'


def tag(text, known_hosts=(), known_users=()):
    spans = []

    def add(s, e, t, v):
        for (a, b, *_) in spans:
            if s < b and a < e:
                return
        spans.append((s, e, t, v))

    for m in RE_EMAIL.finditer(text):
        add(m.start(), m.end(), 'email', m.group(0))
    for m in RE_IP.finditer(text):
        if valid_ip(m.group(1)):
            add(m.start(1), m.end(1), 'ip', m.group(1))
    for rx in USER_PATTERNS:  # users before domains: "andrea.moss" is a user, not a domain
        for m in rx.finditer(text):
            v = m.group(1)
            if v.lower() in SYSTEM_USERS:
                continue
            add(m.start(1), m.end(1), 'user', v)
    for u in known_users:
        if len(u) < 3 or u.lower() in SYSTEM_USERS:
            continue
        for m in re.finditer(r'(?<![\w.-])' + re.escape(u) + r'(?![\w-]|\.\w)', text):
            add(m.start(), m.end(), 'user', u)
    for m in RE_DOM.finditer(text):
        v = m.group(1)
        if re.fullmatch(r'[\d.]+', v):
            continue
        add(m.start(1), m.end(1), 'domain', v)
    # domains inside URLs (scheme://host) and file paths (/var/www/intranet.example.com/...): a preceding
    # slash is allowed only for names with at least two dots, so log files such as /var/log/mail.info stay
    for m in RE_DOM_SLASH.finditer(text):
        v = m.group(1)
        if v.count('.') >= 2 or text[max(0, m.start(1) - 3):m.start(1)] == '://':
            add(m.start(1), m.end(1), 'domain', v)
    for rx in (RE_SYSLOG_HOST, RE_HOSTFIELD):
        for m in rx.finditer(text):
            v = m.group(1)
            if valid_ip(v) or v in ('-',):
                continue
            add(m.start(1), m.end(1), 'host', v)
    for h in known_hosts:
        if len(h) < 4 or h in SYSTEM_USERS:
            continue
        for m in re.finditer(r'(?<![\w./-])' + re.escape(h) + r'(?![\w-]|\.\w)', text):
            add(m.start(), m.end(), 'host', h)
    return sorted(spans)
