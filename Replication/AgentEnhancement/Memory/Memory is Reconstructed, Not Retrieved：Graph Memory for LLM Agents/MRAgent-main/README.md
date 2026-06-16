# MRAgent

> This repository contains the code for the paper
> **"Memory is Reconstructed, Not Retrieved: Graph Memory for LLM Agents."**

A retrieval-augmented question-answering system that builds a **graph-structured
episodic memory** from long multi-session dialogues and answers questions through an
**LLM tool-calling reasoning loop**. The system is evaluated on the **LoCoMo** and
**LongMemEval (LM)** benchmarks.

For each conversation sample the pipeline runs four stages:

```
rewrite  →  embed  →  extract_keyword  →  store (build graph)  →  answer
(LLM)         (OpenAI       (LLM)              (in-memory graph)      (tool-calling
              embedding)                                              reasoning loop)
```

The **`rewrite`** stage turns each raw dialogue turn into a self-contained, normalized
sentence: it resolves pronouns to explicit entities (coreference resolution), converts
relative times to absolute `YYYY-MM-DD` dates, attaches a short topic tag, and extracts
topics and person-level facts. (No language translation is involved.)

At answer time, candidate evidence is retrieved by coarse embedding similarity
(top-`K1`) and fine-grained LLM re-ranking (top-`K2`); the model then iteratively
calls memory tools (keyword / topic / personal / temporal / context lookups) before
producing a short final answer.

---

## 1. Repository Structure

```
run.py                    # main entry point (per-sample pipeline + multithreaded QA)
common/
    config.py             # CLI args, model selection, API keys, paths
    utils.py              # JSON extraction, top-k similarity
    logging_utils.py      # per-sample file logging
memory/
    system.py             # MemorySystem: key nodes, episode/topic graph, raw text
    controller.py         # MemoryController: tool implementations over the graph
llm/
    controller.py         # LLM wrapper (chat / tool-calling loop, via OpenRouter)
    embeddings.py         # OpenAI text-embedding wrapper
    rag_utils.py          # get_embeddings(): batched embedding + L2 normalization
agent/
    agent.py              # Agent: question_format / rewrite / keyword / store / answer_question
    tools.py              # tool schemas (TOOLS) + dispatch (ToolBridge)
prompts/
    prompts.py            # all system/user prompts (Prompts)
    schema.py             # JSON-schema validators for rewrite / keyword output
data/
    get_data.py           # load dataset_{name}.json into conversations + questions
    embed_rewrite.py    # embed_sample(): build per-sample embedding .pkl
    dataset_locomo.json   # benchmark data (LoCoMo)
    dataset_LM.json       # benchmark data (LongMemEval)
eval/
    judge.py              # LLM-as-judge (gpt-4o-mini) accuracy
    evaluation.py         # F1 / exact-match metrics
    evaluate_model.py     # F1/EM evaluation entry
    evaluate_reasoning.py # F1 + LLM-judge evaluation entry
```

---

## 2. Installation

Python 3.9+. Install dependencies:

```bash
pip install openai torch numpy tqdm requests regex jsonschema nltk bert_score python-dotenv
```

> `torch` is used only for embedding tensor ops (L2 normalization); a CPU build is
> sufficient. `nltk` / `bert_score` are required only by the `eval/` scripts.

---

## 3. Configuration

All components — the chat LLM, the text-embedding model, and the LLM-as-judge
evaluator — are accessed through a single **OpenRouter** key (OpenAI-compatible API).
The key is read from a `.env` file at the repository root; **no key is hard-coded**.

Copy the template and fill in your key:

```bash
cp .env.example .env
# then edit .env:
# OPENROUTER_API_KEY=sk-or-v1-xxxxxxxx
```

`.env` is git-ignored. The same `OPENROUTER_API_KEY` is used everywhere:

| Component | File | Model |
| --- | --- | --- |
| Chat / reasoning | `common/config.py` (`--model` → `MODEL`) | e.g. `gemini` → `google/gemini-2.5-flash` |
| Embedding | `llm/embeddings.py` | `text-embedding-3-large` (3072-d) |
| LLM-as-judge | `eval/judge.py` | `openai/gpt-4o-mini` |

Other tunables in `common/config.py`: retrieval breadth `K1=80` (coarse) / `K2=20`
(fine), and `OPENROUTER_URL` (base URL, shared by all three components).

---

## 4. Data Layout

Place the benchmark file at `data/dataset_<name>.json`. Generated intermediate
artifacts and results are written under per-dataset subfolders:

```
data/<dataset>/rewrite_<model>/<sample_id>_rewrite.json   # stage 1 output
data/<dataset>/keyword_<model>/<sample_id>_keyword.json       # stage 3 output
data/<dataset>/embedding/gpt_<model>/<sample_id>_embedding.pkl# stage 2 output
result/<dataset>/<sample_id>_result_<model>_<file>.jsonl      # predictions (the only run output)
```

The run writes a single output per sample — the `_result_*.jsonl` predictions file
(one JSON line per question: gold answer, prediction, category, evidence labels,
retrieved support). A stage is **skipped if its output file already exists**, so
generation runs once and subsequent runs reuse the cached `rewrite` / `keyword` /
`embedding` files.

---

## 5. Usage

The single entry point is `run.py`, invoked from the repository root.

### 5.1 Arguments

| Argument | Meaning | Default |
| --- | --- | --- |
| `--data` | dataset name (`locomo` / `LM`) | `locomo` |
| `--model` | chat model short name (`gemini` / `claude` / `gpt4o` / `qwen`) | `gemini` |
| `--file` | run/experiment tag appended to result filenames | `0` |
| `--sample` | (LoCoMo) run a single sample id, e.g. `42`; omit to run all | `None` |
| `--ca` | (LM) category index: `0`=multi-session, `1`=single-session-user, `2`=temporal-reasoning | `1` |
| `--lm_batch` | (LM) sessions merged per rewrite call (`1` recommended) | `1` |

### 5.2 LoCoMo

```bash
# all conversations
python run.py --data locomo --model gemini --file myrun

# a single conversation
python run.py --data locomo --model gemini --file myrun --sample 42
```

### 5.3 LongMemEval (LM)

`--ca` selects the question category (one run per category):

```bash
python run.py --data LM --model gemini --file myrun --ca 0 --lm_batch 10   # multi-session
python run.py --data LM --model gemini --file myrun --ca 1 --lm_batch 10   # single-session-user
python run.py --data LM --model gemini --file myrun --ca 2 --lm_batch 10   # temporal-reasoning
```

`--lm_batch` controls rewrite granularity. `--lm_batch 1` (default) rewrites one
session per LLM call and produces per-session records compatible with all downstream
readers. Values `>1` merge multiple sessions per call (range-keyed records, handled by
the robust readers and the origin-prefixed graph store).

Each question is answered concurrently (10 worker threads); predictions stream to the
`result/<dataset>/` files and runs are resumable (already-answered questions are
skipped on restart).

---

## 6. Evaluation

```bash
# F1 + LLM-as-judge accuracy (writes result_judge_<data>_<model>_<file>.jsonl)
python eval/evaluate_reasoning.py --data locomo --model gemini --file myrun --allfile

# F1 / exact-match table
python eval/evaluate_model.py
```

The LLM judge (`eval/judge.py`) grades a prediction `CORRECT`/`WRONG` against the gold
answer with `gpt-4o-mini`, using lenient matching (topic overlap; date equivalence for
temporal questions).

---

## 7. Notes

- The pipeline is **cache-based**: delete the corresponding `rewrite` / `keyword` /
  `embedding` files to force regeneration of a sample.
- Per-sample reasoning traces are logged under `log/<dataset>/`.
- Tool inventory (7 tools): `edges_by_tag`, `query_conversation_time`,
  `query_event_keywords`, `query_event_context`, `query_personal_information`,
  `query_personal_aspect`, `query_topic_events`.
