# Telemetry masking before language-model alert triage

Code, derived data, every analyst answer and the evaluation results accompanying the manuscript *Masking security telemetry for LLM-based alert triage: a privacy–utility evaluation of pseudonymisation schemes*. The manuscript itself is not included in this repository.

The study asks two questions about masking identifiers in security alerts before a language model triages them:
- **Utility:** what each masking scheme costs a local LLM analyst.
- **Protection:** what each scheme still exposes to whoever receives the masked alerts.

Alert bundles are built from the public [AIT Alert Data Set](https://doi.org/10.5281/zenodo.8263181). The identifiers in them are masked with six schemes. Five open-weight models, run locally through llama.cpp, then answer four triage tasks. A separate audit measures residual identifiers, attribute disclosure and cross-bundle linkability, without any language model.

## Conditions

| Code | Scheme | Example (`src -> dst`) |
|---|---|---|
| `S0` | none (unmasked baseline) | `192.168.230.122:34642 -> 172.19.130.68:80` |
| `S0n` | none, plus a neutral privacy notice (notice-matched control) | as `S0` |
| `S1` | redaction | `[IP]:34642 -> [IP]:80` |
| `S2` | random token per occurrence | `IP_3694:34642 -> IP_e77a:80` |
| `S3` | consistent token per bundle | `IP_2:34642 -> IP_3:80` |
| `S4` | global Crypto-PAn addresses + keyed-hash names | `39.96.239.6:34642 -> 80.111.181.196:80` |
| `S5` | role-preserving token per bundle | `INT_HOST_1:34642 -> INT_SRV_2:80` |
| `S6` | Crypto-PAn + keyed hash, key drawn per bundle | `49.161.102.122:34642 -> 85.108.29.188:80` |
| `Rip`, `Rname`, `Ruser` | ablation: redact only IPs / only host and domain names / only accounts and e-mail | |

**Tasks:**
- **T1:** verdict (escalate or close).
- **T2:** attack stage (seven stages plus benign).
- **T3:** involved hosts (F1 after mapping surrogates back).
- **T4:** host to contain.

**Protection audit:**
- **P0:** residual identifiers.
- **P1:** attribute disclosure. A logistic-regression adversary sees the context tokens and the surrogate form, and is evaluated leave-one-scenario-out.
- **P2:** cross-bundle linkability (surrogate equality plus context cosine).

## Layout

| Path | Contents |
|---|---|
| `scripts/get_data.py` | Downloads `ait_ads.zip` and `labels.csv` from Zenodo, verifies MD5, unpacks to `data/ait/` |
| `src/a_load.py` | Parses Wazuh/AMiner alerts; labels attack alerts (step window AND attacker mention or rare rule); finds the attacker address |
| `src/a_entities.py` | Rule-based identifier tagger (IPv4, host, domain, user, e-mail) |
| `src/a_bundles.py` | Alert bundles (−30 s … +90 s around an anchor, ≤ 8 grouped lines) with ground truth: verdict, stage, involved hosts, containment target |
| `src/a_mask.py` | Masking schemes S0–S6 and the ablation variants; surrogate maps for back-mapping |
| `src/a_prompts.py` | System prompt, per-scheme privacy notices, JSON schema; writes all prompts and surrogate maps |
| `src/llm.py`, `src/a_run.py` | llama.cpp server management and the resumable analyst queue (greedy decoding, seed 17, JSON-schema grammar) |
| `src/a_score.py` | Back-mapping and scoring; paired McNemar / bootstrap tests with Holm correction in five families |
| `src/a_errors.py` | What the analysts chose to contain (attacker, victim, other host, internet host, none) |
| `src/a_protect.py` | Protection audit P0–P2 with bundle-bootstrap intervals |
| `src/a_report.py` | Tables, LaTeX number macros and result figures, written to `outputs/` |
| `src/a_fig1.py`, `src/a_method_diagram.py` | Study-design and methodology diagrams (written to `outputs/`) |
| `data/a_bundles.json` | The 351 bundles (192 attack, 159 benign) with tagged entities and ground truth |
| `data/a_prompts.jsonl` | All 3,861 prompts: 351 bundles × (S0–S6, S0n, Rip, Rname, Ruser) |
| `data/a_maps.json` | Surrogate map for every prompt |
| `data/a_schema.json`, `data/a_meta.json` | Answer schema; per-scenario attacker address and alert counts |
| `results/a_gen/<model>__<condition>.jsonl` | Every raw analyst answer (11,274 in total) with token counts and latency |
| `results/a_scores.jsonl` | Per-answer scores |
| `results/a_eval.json` | Aggregates per model × condition and every paired test (`family`: main, ablation, direct, control, main_n) |
| `results/a_protect.json`, `results/a_errors.json` | Protection audit; containment-choice counts |
| `figures/` | PNG renderings of the result figures and the study-design diagrams |

## Analyst models

Q4_K_M GGUF files, served by llama.cpp build b11370 (CUDA). Place them in `models/` or set `MODEL_DIR`.

| Model | File | Source | SHA-256 |
|---|---|---|---|
| Qwen2.5-1.5B-Instruct | `qwen2.5-1.5b-instruct-q4_k_m.gguf` | [Qwen/Qwen2.5-1.5B-Instruct-GGUF](https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF) | `6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e` |
| Qwen2.5-3B-Instruct | `qwen2.5-3b-instruct-q4_k_m.gguf` | [Qwen/Qwen2.5-3B-Instruct-GGUF](https://huggingface.co/Qwen/Qwen2.5-3B-Instruct-GGUF) | `626b4a6678b86442240e33df819e00132d3ba7dddfe1cdc4fbb18e0a9615c62d` |
| Qwen2.5-7B-Instruct | `qwen2.5-7b-instruct-q4_k_m-0000{1,2}-of-00002.gguf` | [Qwen/Qwen2.5-7B-Instruct-GGUF](https://huggingface.co/Qwen/Qwen2.5-7B-Instruct-GGUF) | `dfce12e3862a5283ccfb88221b48480e58745165de856439950d0f22590580db`, `539cf93f78e887edea1c04e2d7d8cdaca9d01dae9c9025bcb8accbe29df3d72a` |
| Qwen3-4B (non-thinking) | `Qwen3-4B-Q4_K_M.gguf` | [Qwen/Qwen3-4B-GGUF](https://huggingface.co/Qwen/Qwen3-4B-GGUF) | `7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5` |
| Llama-3.2-3B-Instruct | `llama-3.2-3b-instruct-q4_k_m.gguf` | quantised locally (`llama-quantize … Q4_K_M`, b11370, no imatrix) from `Llama-3.2-3B-Instruct-f16.gguf` of [bartowski/Llama-3.2-3B-Instruct-GGUF](https://huggingface.co/bartowski/Llama-3.2-3B-Instruct-GGUF) (F16 SHA-256 `b5ebe8fbb5ab5f05aaa056948668c5f7443df9d0883497f1d9c05f57fb8ea6cd`) | `c5e6cf2c071a429e2380d2d1182c06a20b8c999d0c059636530e4a84beb8e8d4` |

Qwen2.5-1.5B, Qwen2.5-3B and Llama-3.2-3B answer all 351 bundles. Qwen3-4B and Qwen2.5-7B answer a 150-bundle subset, stratified by stage label (129 attack, 21 benign). The ablation variants are run on Qwen2.5-3B over the same subset.

## Reproduce

```bash
pip install -r requirements.txt
```

**From the committed answers (no GPU, no source data).** These steps reproduce every utility number, test, table and figure:

```bash
python src/a_score.py        # -> results/a_scores.jsonl, results/a_eval.json
python src/a_errors.py       # -> results/a_errors.json
python src/a_report.py       # -> outputs/ (tables, number macros, figures)
```

**Protection audit** (needs the parsed alerts):

```bash
python scripts/get_data.py   # AIT-ADS from Zenodo (about 96 MB), checksum-verified
python src/a_load.py         # -> data/a_alerts.pkl (about 1.1 GB), data/a_meta.json
python src/a_protect.py      # -> results/a_protect.json
```

**Full rebuild.** This rebuilds the bundles and prompts, then reruns the analysts:

```bash
python src/a_bundles.py      # -> data/a_bundles.json
python src/a_prompts.py      # -> data/a_prompts.jsonl, data/a_maps.json, data/a_schema.json
LLAMA_DIR=/path/to/llama.cpp MODEL_DIR=/path/to/models python src/a_run.py
```

`a_run.py` resumes from whatever is already in `results/a_gen/`. To rerun a model, delete or move its files first. An optional filter argument restricts the run, e.g. `python src/a_run.py qwen2.5-3b__S0n`.

**Reference hardware.** One NVIDIA GTX 1060 (6 GB), 16 GB RAM, Windows 11 and Python 3.11. A single masking condition takes about 15–35 min per model.

## Notes

- **Masking key.** The key in `src/a_mask.py` is a fixed, deliberately public research key. It is used so that the pseudonyms in the committed prompts can be regenerated exactly. A deployment must use its own secret key.
- **Attacker address.** In the AIT testbeds the attacker connects through the organisation's VPN. The attacker address in `data/a_meta.json` is therefore the inner address of the VPN gateway.
- **Determinism.** Answers were produced with greedy decoding and a fixed seed. Re-running on other GPUs or llama.cpp builds can change a small number of answers.

## Licence

- **Code:** MIT (see `LICENSE`).
- **Derived data:** the bundles, prompts and maps in `data/` are derived from the AIT Alert Data Set (Landauer et al., Zenodo 8263181, CC BY 4.0) and are distributed under the same CC BY 4.0 terms. Please cite the original data set as well.

## Citation

See `CITATION.cff`.
