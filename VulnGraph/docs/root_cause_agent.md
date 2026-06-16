# Root Cause Agent Minimum Loop

## Scope

The Root Cause Agent extracts a code-level vulnerability mechanism for one CVE. It does not judge target versions, plan versions, aggregate affected ranges, or consume ground truth.

```text
bounded CVE/repo graph context
  -> strict root-cause prompt
  -> OpenCode read-only session
  -> read-only Git tool calls
  -> RootCauseAgentOutput JSON
  -> Pydantic validation
  -> append-only graph events and run artifacts
```

## Backend boundary

VulnGraph owns:

- CVE/repo-scoped context extraction and character/node budgets;
- task prompt and output JSON Schema;
- identity and reference validation;
- graph-event conversion, snapshots, and run artifacts.

OpenCode owns:

- model/provider selection;
- agent session and tool loop;
- read-only Git tool execution;
- temporary conversational context during one run.

Each root-cause run creates a fresh session. Raw conversational history remains in OpenCode. Only the structured command excerpts, anchors, predicates, hypotheses, risk flags, and candidate memories enter VulnGraph.

## Git permissions

The default session is a strict tool allowlist. It denies file editing, shell, generic file search/read, web access, task/subagent orchestration, todo tools, and interactive questions. It allows only these repository tools:

```text
vg_git_diff, vg_git_show, vg_git_grep, vg_git_log, vg_list_tags,
vg_git_ls_tree, vg_git_cat_file, vg_git_rev_parse, vg_git_merge_base, vg_git_show_ref
```

The tools under `.opencode/tools/` execute `git -c safe.directory=<repo_path> -C <repo_path> ...`, so a read-only agent account can inspect repositories owned by the local user without changing global Git configuration. `--allow-bash` exists only as an explicit compatibility escape hatch and is not the default.

If the model returns syntactically valid JSON that fails schema/reference validation, VulnGraph permits one same-session repair turn. The repair prompt forbids tool calls and the service rejects the repair if `command_invocations` or their outputs change.

## Start OpenCode

Run the server from the VulnGraph directory so OpenCode loads `.opencode/tools/`:

```powershell
Set-Location 'E:\AI\Agent\workflow\VulnGraph'
opencode.cmd serve --hostname 127.0.0.1 --port 4096
```

## Seed minimum context

Create a seed JSON containing at least the CVE, repository name, and known fix commit:

```json
{
  "cve_id": "CVE-YYYY-NNNN",
  "repo": "owner/repo",
  "cwe_id": "CWE-NNN",
  "cve_description": "authoritative CVE description",
  "fix_commit": "FIX_COMMIT_SHA",
  "references": []
}
```

Load it into a dedicated graph store:

```powershell
$env:PYTHONPATH='src'
python -m vulngraph.cli.main seed `
  --store 'data\graphs\CVE-YYYY-NNNN' `
  --input 'data\fixtures\CVE-YYYY-NNNN.seed.json'
```

## Run the Root Cause Agent

```powershell
$env:PYTHONPATH='src'
python -m vulngraph.cli.main root-cause `
  --store 'data\graphs\CVE-YYYY-NNNN' `
  --runs 'runs' `
  --cve 'CVE-YYYY-NNNN' `
  --repo 'owner/repo' `
  --repo-path 'E:\path\to\target-repo' `
  --base-url 'http://127.0.0.1:4096'
```

VulnGraph defaults to `deepseek/deepseek-v4-pro`. OpenCode reads the DeepSeek credential from its local credential store or `DEEPSEEK_API_KEY`; VulnGraph never copies the API key into run artifacts. Pass `--provider-id` and `--model-id` only to override the default. Use `--agent` only when selecting a named OpenCode agent.

## Outputs

Graph state:

```text
<store>/events.jsonl
<store>/nodes.jsonl
<store>/edges.jsonl
```

Per-run audit artifacts:

```text
runs/<CVE>/<run-id>/prompt.json
runs/<CVE>/<run-id>/raw_output.json
runs/<CVE>/<run-id>/output.json
```

The output graph contains `RootCauseHypothesis`, `VulnerablePredicate`, `FixPredicate`, `GuardCondition`, `NegativeApplicabilityCondition`, `CodeAnchor`, and `RiskFlag` nodes. Agent-produced memory remains `candidate` and cannot enter a production packet by default.

## Ten-case batch

The batch command creates one graph store and one fresh OpenCode session per CVE. A failed case is recorded and does not stop later cases.

```powershell
$env:PYTHONPATH='src'
python -m vulngraph.cli.main root-cause-batch `
  --dataset 'E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet_10.json' `
  --nvd 'E:\AI\Agent\workflow\VulnVersion\DataSet\BaseData_nvd.json' `
  --repo-root 'E:\AI\Agent\workflow\VulnVersion\repo' `
  --output-root 'runs\batches\root-cause-10-v1' `
  --limit 10
```

The batch writes `summary.json` after every case. The local VulnVersion files are evaluation inputs only; VulnGraph does not import or execute old Step2/VET code.

## Current limitations

- The first run assumes a known fix commit or sufficiently useful references in the seed graph.
- Root-cause hypotheses are stored as `raw`; a later verifier/promotion stage must decide whether they become `validated`.
- Command output is represented by excerpts supplied in the agent JSON, not a complete OpenCode event export.
- Prompt size is bounded by node and character budgets, but there is not yet adaptive summarization across multiple runs.
