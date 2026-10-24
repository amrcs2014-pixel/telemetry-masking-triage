"""Paper A GPU queue (stdlib only, so it runs under Task Scheduler).

Units = (model, scheme). Outputs: results/a_gen/<model>__<scheme>.jsonl, resumable by prompt id.
Usage: python a_run.py [unit-filter] [max_bundles]
"""
import json, os, subprocess, sys, time
from pathlib import Path
import llm

W = Path(__file__).resolve().parents[1]
D, R, LOG = W / 'data', W / 'results' / 'a_gen', W / 'logs'
# GGUF files (Q4_K_M) are expected in MODEL_DIR (default: ./models); see README for sources and SHA-256
_M = os.environ.get('MODEL_DIR', str(W / 'models')) + os.sep
MODELS = {  # name: (gguf, slots, ctx/slot, extra request params)
    'qwen2.5-1.5b': (_M + r'qwen2.5-1.5b-instruct-q4_k_m.gguf', 6, 3072, {}),
    'qwen2.5-3b': (_M + r'qwen2.5-3b-instruct-q4_k_m.gguf', 4, 3072, {}),
    'llama3.2-3b': (_M + r'llama-3.2-3b-instruct-q4_k_m.gguf', 4, 3072, {}),
    'qwen3-4b': (_M + r'Qwen3-4B-Q4_K_M.gguf', 3, 3072, {'chat_template_kwargs': {'enable_thinking': False}}),
    'qwen2.5-7b': (_M + r'qwen2.5-7b-instruct-q4_k_m-00001-of-00002.gguf', 2, 3072, {}),
}
SCHEMES = ['S0', 'S1', 'S2', 'S3', 'S4', 'S5']
# full grid (351 bundles) for the three core models; the two larger models on a stratified 150-bundle subset
SUBSET_MODELS, MAXSUB = {'qwen3-4b', 'qwen2.5-7b'}, 150
ABL = ['Rip', 'Rname', 'Ruser']   # type-specific redaction ablation, Qwen2.5-3B on the same 150-bundle subset
# order (re-prioritised at 15:35): completed units are skipped on resume
QUEUE = [(m, s) for m in ['qwen2.5-3b', 'llama3.2-3b', 'qwen2.5-1.5b'] for s in SCHEMES] + \
        [('qwen3-4b', s) for s in SCHEMES] + [('qwen2.5-7b', 'S0')]
QUEUE += [(m, 'S6') for m in ['qwen2.5-3b', 'qwen2.5-1.5b', 'qwen3-4b', 'llama3.2-3b']]  # S6 added after S0-S5
QUEUE += [('qwen2.5-3b', s) for s in ABL]
QUEUE += [('qwen2.5-7b', s) for s in ['S3', 'S4', 'S6', 'S5', 'S2', 'S1']]
# notice-matched control (23 Oct): unmasked bundles with a neutral privacy notice
QUEUE += [(m, 'S0n') for m in ['qwen2.5-3b', 'qwen2.5-1.5b', 'llama3.2-3b', 'qwen3-4b', 'qwen2.5-7b']]


def log(*a):
    msg = time.strftime('%H:%M:%S ') + ' '.join(str(x) for x in a)
    print(msg, flush=True)
    with open(LOG / 'a_run.log', 'a', encoding='utf-8') as f:
        f.write(msg + '\n')


def load_prompts():
    P = {}
    for l in open(D / 'a_prompts.jsonl', encoding='utf-8'):
        r = json.loads(l); P.setdefault(r['scheme'], []).append(r)
    return P


def subset_ids(prompts, n):
    """Deterministic subset of bundle ids, stratified by stage label only (round-robin over the eight labels)."""
    B = {b['id']: b for b in json.load(open(D / 'a_bundles.json'))}
    ids = sorted({p['bundle'] for p in prompts})
    strata = {}
    for i in ids:
        strata.setdefault((B[i]['stage']), []).append(i)
    out, k = [], 0
    while len(out) < n and any(strata.values()):
        for s in sorted(strata):
            if strata[s]:
                out.append(strata[s].pop(0 if k % 2 == 0 else len(strata[s]) // 2))
        k += 1
    return set(out[:n])


def kill_own_orphan():
    f = LOG / 'a_server.pid'
    if not f.exists():
        return
    pid = f.read_text().strip()
    out = subprocess.run(['tasklist', '/FI', f'PID eq {pid}', '/FO', 'CSV', '/NH'], capture_output=True, text=True).stdout
    if 'llama-server' in out:
        subprocess.run(['taskkill', '/F', '/PID', pid], capture_output=True)
        log(f'killed orphaned server pid {pid}')
    f.unlink()


def run_unit(model, scheme, prompts, limit=None):
    R.mkdir(parents=True, exist_ok=True)
    out = R / f'{model}__{scheme}.jsonl'
    done = set()
    if out.exists():
        for l in open(out, encoding='utf-8'):
            try:
                r = json.loads(l)
                if 'error' not in r:
                    done.add(r['id'])
            except Exception:
                pass
    items = [p for p in prompts[scheme] if p['id'] not in done and (limit is None or p['bundle'] in limit)]
    if not items:
        return 0
    gguf, slots, ctx, extra = MODELS[model]
    schema = json.load(open(D / 'a_schema.json'))
    lock = __import__('threading').Lock()

    def fn(srv, p):
        t = time.time()
        r = srv.chat(p['messages'], temperature=0.0, max_tokens=256, seed=17,
                     response_format={'type': 'json_schema', 'json_schema': {'name': 'triage', 'schema': schema}},
                     **extra)
        rec = dict(id=p['id'], bundle=p['bundle'], scheme=scheme, model=model, text=r['text'], finish=r['finish'],
                   ptok=r['usage'].get('prompt_tokens'), ctok=r['usage'].get('completion_tokens'),
                   sec=round(time.time() - t, 2))
        with lock:
            with open(out, 'a', encoding='utf-8') as f:
                f.write(json.dumps(rec) + '\n')
        return rec

    t0 = time.time()
    # an orphaned server of this queue (e.g. after a hung run) keeps the GPU memory and makes the next one fail
    # to load; kill only that one (other projects run their own llama-servers on this machine)
    kill_own_orphan()
    with llm.Server(gguf, slots=slots, ctx_per_slot=ctx, tag=f'a_{model}') as srv:
        (LOG / 'a_server.pid').write_text(str(srv.proc.pid))
        res = srv.map(items, fn, threads=slots)
    errs = sum(1 for r in res if r and 'error' in r)
    log(f'{model} {scheme}: {len(items)} prompts in {time.time() - t0:.0f}s, errors {errs}')
    return len(items)


def gpu_busy(limit_mib=1200):
    """True if another job holds GPU memory (this card cannot host two LLM servers)."""
    try:
        out = subprocess.run(['nvidia-smi', '--query-gpu=memory.used', '--format=csv,noheader,nounits'],
                             capture_output=True, text=True, timeout=30).stdout
        return int(out.strip().splitlines()[0]) > limit_mib
    except Exception:
        return False


def main():
    LOG.mkdir(exist_ok=True)
    kill_own_orphan()
    if gpu_busy():
        log('GPU busy (another job holds memory); retry at the next scheduled start')
        return
    llm.keep_awake(True)
    flt = sys.argv[1] if len(sys.argv) > 1 else ''
    nmax = int(sys.argv[2]) if len(sys.argv) > 2 else None
    prompts = load_prompts()
    for m, s in QUEUE:
        if flt and flt not in f'{m}__{s}':
            continue
        lim = subset_ids(prompts[s], nmax) if nmax else (subset_ids(prompts[s], MAXSUB) if (m in SUBSET_MODELS or s in ABL) else None)
        try:
            run_unit(m, s, prompts, lim)
        except Exception as e:
            log(f'{m} {s}: FAILED {e!r}')
    log('ALL DONE' if not flt else f'done {flt}')


if __name__ == '__main__':
    main()
