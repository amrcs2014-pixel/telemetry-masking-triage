"""llama.cpp server management + a small concurrent client (stdlib only, so it runs under Task Scheduler).

Usage pattern:
    with Server(model_path, slots=8, ctx_per_slot=3072) as srv:
        results = srv.map(requests, worker_fn, threads=8)
"""
import json, os, socket, subprocess, threading, time, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor

_EXE = ".exe" if os.name == "nt" else ""
# llama.cpp build b11370 (CUDA); set LLAMA_DIR to the folder that holds llama-server
LLAMA_DIR = os.environ.get("LLAMA_DIR", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin", "llama"))
SERVER = os.path.join(LLAMA_DIR, "llama-server" + _EXE)
LOGDIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")


def keep_awake(on=True):
    """Ask Windows not to sleep while a queue is running (ES_CONTINUOUS | ES_SYSTEM_REQUIRED); no settings changed."""
    try:
        import ctypes
        ctypes.windll.kernel32.SetThreadExecutionState(0x80000001 if on else 0x80000000)
    except Exception:
        pass


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def post(url, payload, timeout=900):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", errors="replace"))


class Server:
    def __init__(self, model, slots=8, ctx_per_slot=3072, ngl=99, extra=(), tag=None, kv_q8=False):
        self.model, self.slots, self.ctx = model, slots, ctx_per_slot * slots
        self.ngl, self.extra = ngl, list(extra)
        self.tag = tag or os.path.basename(model).replace(".gguf", "")
        self.kv_q8 = kv_q8
        self.port = free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self.proc = None

    def __enter__(self):
        args = [SERVER, "-m", self.model, "--host", "127.0.0.1", "--port", str(self.port), "-ngl", str(self.ngl),
                "-c", str(self.ctx), "-np", str(self.slots), "--jinja", "--no-webui", "-fa", "on", "--seed", "17"]
        if self.kv_q8:
            args += ["-ctk", "q8_0", "-ctv", "q8_0"]
        args += self.extra
        os.makedirs(LOGDIR, exist_ok=True)
        self.err = open(os.path.join(LOGDIR, f"srv_{self.tag}.err"), "w", encoding="utf-8", errors="replace")
        flags = 0x08000000 if os.name == "nt" else 0          # CREATE_NO_WINDOW
        self.proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=self.err, creationflags=flags)
        t0 = time.time()
        while time.time() - t0 < 600:
            if self.proc.poll() is not None:
                raise RuntimeError(f"llama-server exited ({self.proc.returncode}); see srv_{self.tag}.err")
            try:
                with urllib.request.urlopen(self.url + "/health", timeout=5) as r:
                    if r.status == 200:
                        return self
            except Exception:
                pass
            time.sleep(2)
        raise RuntimeError("llama-server did not become healthy")

    def __exit__(self, *a):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(30)
            except Exception:
                self.proc.kill()
        try:
            self.err.close()
        except Exception:
            pass

    # ---- endpoints
    def chat(self, messages, timeout=900, **params):
        body = {"messages": messages, "stream": False}
        body.update(params)
        r = post(self.url + "/v1/chat/completions", body, timeout)
        ch = r["choices"][0]
        return {"text": ch["message"].get("content") or "", "finish": ch.get("finish_reason"),
                "usage": r.get("usage", {}), "timings": r.get("timings", {})}

    def template(self, messages, **kw):
        body = {"messages": messages}
        body.update(kw)
        return post(self.url + "/apply-template", body)["prompt"]

    def complete(self, prompt, timeout=900, **params):
        body = {"prompt": prompt, "stream": False, "cache_prompt": True}
        body.update(params)
        return post(self.url + "/completion", body, timeout)

    def tokenize(self, text):
        return post(self.url + "/tokenize", {"content": text})["tokens"]

    def map(self, items, fn, threads=8):
        """Run fn(self, item) concurrently; returns list of results in completion order (fn handles persistence)."""
        out = []
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for r in ex.map(lambda it: _safe(fn, self, it), items):
                out.append(r)
        return out


def _safe(fn, srv, it):
    for attempt in range(3):
        try:
            return fn(srv, it)
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
            if srv.proc.poll() is not None:
                raise
            time.sleep(5 * (attempt + 1))
        except Exception as e:
            return {"error": repr(e)}
    return {"error": "retries exhausted"}
