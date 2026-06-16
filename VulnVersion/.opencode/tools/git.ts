import { tool } from "@opencode-ai/plugin"
import { spawn } from "child_process"

type GitRunResult = { stdout: string; stderr: string; exitCode: number }

async function runGit(repoPath: string, args: string[], ignoreExitCodes: number[] = []): Promise<GitRunResult> {
  return new Promise((resolve, reject) => {
    const child = spawn("git", ["-C", repoPath, ...args], {
      stdio: ["ignore", "pipe", "pipe"]
    })

    let stdout = ""
    let stderr = ""

    child.stdout.on("data", (data: { toString: () => string; }) => {
      stdout += data.toString()
    })

    child.stderr.on("data", (data: { toString: () => string; }) => {
      stderr += data.toString()
    })

    child.on("error", (err: any) => {
      reject(err)
    })

    child.on("close", (code: number) => {
      const exitCode = code ?? 1
      if (exitCode !== 0 && !ignoreExitCodes.includes(exitCode)) {
        const message = stderr.trim() || stdout.trim() || `git exited with code ${exitCode}`
        reject(new Error(message))
      } else {
        resolve({ stdout, stderr, exitCode })
      }
    })
  })
}

function toLines(text: string): Array<{ no: number; text: string }> {
  const raw = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n")
  const lines = raw.length > 0 && raw[raw.length - 1] === "" ? raw.slice(0, -1) : raw
  return lines.map((t, i) => ({ no: i + 1, text: t }))
}

function sliceLines(
  lines: Array<{ no: number; text: string }>,
  startLine?: number,
  endLine?: number,
): Array<{ no: number; text: string }> {
  const start = startLine && startLine > 0 ? startLine : 1
  const end = endLine && endLine > 0 ? endLine : lines.length
  return lines.filter((l) => l.no >= start && l.no <= end)
}

function parseOnelineLog(lines: string[]): Array<{ hash: string; subject: string }> {
  const out: Array<{ hash: string; subject: string }> = []
  for (const line of lines) {
    const trimmed = line.trim()
    if (!trimmed) continue
    const m = /^([0-9a-f]{7,40})\s+(.*)$/.exec(trimmed)
    if (!m) continue
    out.push({ hash: m[1]!, subject: m[2] ?? "" })
  }
  return out
}

type ParsedDiff = Array<{
  path: string
  hunks: Array<{
    header: string
    removed: string[]
    added: string[]
  }>
}>

function parseGitPatch(patch: string): ParsedDiff {
  const lines = patch.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n")
  const files: ParsedDiff = []
  let currentFile: ParsedDiff[number] | undefined
  let currentHunk: ParsedDiff[number]["hunks"][number] | undefined

  function flushHunk() {
    if (currentFile && currentHunk) {
      currentFile.hunks.push(currentHunk)
    }
    currentHunk = undefined
  }

  function flushFile() {
    flushHunk()
    currentFile = undefined
  }

  for (const line of lines) {
    if (line.startsWith("diff --git ")) {
      flushFile()
      const m = /^diff --git a\/(.+?) b\/(.+)$/.exec(line)
      const path = m?.[2] ?? ""
      currentFile = { path, hunks: [] }
      files.push(currentFile)
      continue
    }

    if (!currentFile) continue

    if (line.startsWith("@@ ")) {
      flushHunk()
      currentHunk = { header: line, removed: [], added: [] }
      continue
    }

    if (!currentHunk) continue

    if (line.startsWith("--- ") || line.startsWith("+++ ")) continue
    if (line.startsWith("\\ No newline at end of file")) continue

    if (line.startsWith("-") && !line.startsWith("---")) {
      currentHunk.removed.push(line.slice(1))
      continue
    }
    if (line.startsWith("+") && !line.startsWith("+++")) {
      currentHunk.added.push(line.slice(1))
      continue
    }
  }

  flushFile()
  return files
}

export const git_show = tool({
  description: "Read file contents at a given ref without checkout, with line slicing.",
  args: {
    repo_path: tool.schema.string(),
    ref: tool.schema.string(),
    path: tool.schema.string(),
    start_line: tool.schema.number().int().optional(),
    end_line: tool.schema.number().int().optional(),
  },
  async execute(args: any) {
    const refResolved = (await runGit(args.repo_path, ["rev-parse", "--verify", args.ref])).stdout.trim()
    const content = (await runGit(args.repo_path, ["show", `${refResolved}:${args.path}`])).stdout
    const allLines = toLines(content)
    const sliced = sliceLines(allLines, args.start_line, args.end_line)
    const startLine = args.start_line && args.start_line > 0 ? args.start_line : 1
    const endLine =
      args.end_line && args.end_line > 0 ? Math.min(args.end_line, allLines.length) : allLines.length
    return {
      ref_resolved: refResolved,
      path: args.path,
      start_line: startLine,
      end_line: endLine,
      lines: sliced,
    }
  },
})

export const git_grep = tool({
  description: "Search for pattern at a given ref without checkout.",
  args: {
    repo_path: tool.schema.string(),
    ref: tool.schema.string(),
    pattern: tool.schema.string(),
    path_glob: tool.schema.string().optional(),
    max_matches: tool.schema.number().int().optional(),
  },
  async execute(args: any) {
    const refResolved = (await runGit(args.repo_path, ["rev-parse", "--verify", args.ref])).stdout.trim()
    const cmd = ["grep", "-n", "--no-color", "-e", args.pattern, refResolved]
    if (args.path_glob && args.path_glob.trim()) cmd.push("--", args.path_glob)
    
    // git grep returns exit code 1 if no matches found. We should treat this as empty result, not error.
    const { stdout, exitCode } = await runGit(args.repo_path, cmd, [1])
    
    if (exitCode === 1) {
       return {
        ref_resolved: refResolved,
        pattern: args.pattern,
        matches: [],
      }
    }

    const lines = stdout.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n")
    const matches: Array<{ path: string; line: number; text: string }> = []
    for (const line of lines) {
      if (!line) continue
      const first = line.indexOf(":")
      const second = first >= 0 ? line.indexOf(":", first + 1) : -1
      if (first < 0 || second < 0) continue
      const path = line.slice(0, first)
      const lineNo = Number(line.slice(first + 1, second))
      if (!Number.isFinite(lineNo)) continue
      const text = line.slice(second + 1)
      matches.push({ path, line: lineNo, text })
      if (args.max_matches && matches.length >= args.max_matches) break
    }
    return {
      ref_resolved: refResolved,
      pattern: args.pattern,
      matches,
    }
  },
})

export const git_diff = tool({
  description: "Read a commit patch and parse it into structured hunks.",
  args: {
    repo_path: tool.schema.string(),
    commit: tool.schema.string(),
    max_chars: tool.schema.number().int().optional(),
  },
  async execute(args: any) {
    const commitResolved = (await runGit(args.repo_path, ["rev-parse", "--verify", args.commit])).stdout.trim()
    const patch = (
      await runGit(args.repo_path, ["show", "--patch", "--no-color", "--format=", commitResolved])
    ).stdout
    const limited = args.max_chars && args.max_chars > 0 ? patch.slice(0, args.max_chars) : patch
    const files = parseGitPatch(limited)
    return { commit: commitResolved, files }
  },
})

export const git_log = tool({
  description: "Read git log on a ref/range, optionally filtered by path.",
  args: {
    repo_path: tool.schema.string(),
    range_or_ref: tool.schema.string(),
    path_glob: tool.schema.string().optional(),
    max_commits: tool.schema.number().int().optional(),
  },
  async execute(args: any) {
    const max = args.max_commits && args.max_commits > 0 ? String(args.max_commits) : "50"
    const cmd = ["log", "--oneline", "--decorate", `--max-count=${max}`, args.range_or_ref]
    if (args.path_glob && args.path_glob.trim()) cmd.push("--", args.path_glob)
    const out = (await runGit(args.repo_path, cmd)).stdout
    const lines = out.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n")
    return { range_or_ref: args.range_or_ref, commits: parseOnelineLog(lines) }
  },
})

export const git_ls_tree = tool({
  description: "List tree entries at a given ref and optional path.",
  args: {
    repo_path: tool.schema.string(),
    ref: tool.schema.string(),
    path: tool.schema.string().optional(),
    recursive: tool.schema.boolean().optional(),
    max_entries: tool.schema.number().int().optional(),
  },
  async execute(args: any) {
    const refResolved = (await runGit(args.repo_path, ["rev-parse", "--verify", args.ref])).stdout.trim()
    const cmd = ["ls-tree"]
    if (args.recursive) cmd.push("-r")
    cmd.push(refResolved)
    if (args.path && args.path.trim()) cmd.push("--", args.path)
    const out = (await runGit(args.repo_path, cmd)).stdout
    const lines = out.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n")
    const entries: Array<{ mode: string; type: string; object: string; path: string }> = []
    for (const line of lines) {
      if (!line) continue
      const m = /^(\d+)\s+(\w+)\s+([0-9a-f]{40})\t(.+)$/.exec(line)
      if (!m) continue
      entries.push({ mode: m[1]!, type: m[2]!, object: m[3]!, path: m[4]! })
      if (args.max_entries && entries.length >= args.max_entries) break
    }
    return { ref_resolved: refResolved, entries }
  },
})

export const git_cat_file = tool({
  description: "Inspect a git object type/size and optionally pretty-print content with limits.",
  args: {
    repo_path: tool.schema.string(),
    object: tool.schema.string(),
    pretty: tool.schema.boolean().optional(),
    max_chars: tool.schema.number().int().optional(),
  },
  async execute(args: any) {
    const objResolved = (await runGit(args.repo_path, ["rev-parse", "--verify", args.object])).stdout.trim()
    const type = (await runGit(args.repo_path, ["cat-file", "-t", objResolved])).stdout.trim()
    const sizeStr = (await runGit(args.repo_path, ["cat-file", "-s", objResolved])).stdout.trim()
    const size = Number(sizeStr)
    let content: string | undefined
    if (args.pretty) {
      const raw = (await runGit(args.repo_path, ["cat-file", "-p", objResolved])).stdout
      const limited = args.max_chars && args.max_chars > 0 ? raw.slice(0, args.max_chars) : raw
      content = limited
    }
    return { object_resolved: objResolved, type, size: Number.isFinite(size) ? size : null, content }
  },
})

export const git_rev_parse = tool({
  description: "Resolve a git rev to a full object id.",
  args: {
    repo_path: tool.schema.string(),
    rev: tool.schema.string(),
  },
  async execute(args: any) {
    const resolved = (await runGit(args.repo_path, ["rev-parse", "--verify", args.rev])).stdout.trim()
    return { rev: args.rev, resolved }
  },
})

export const git_merge_base = tool({
  description: "Compute merge base between two refs.",
  args: {
    repo_path: tool.schema.string(),
    ref_a: tool.schema.string(),
    ref_b: tool.schema.string(),
  },
  async execute(args: any) {
    const a = (await runGit(args.repo_path, ["rev-parse", "--verify", args.ref_a])).stdout.trim()
    const b = (await runGit(args.repo_path, ["rev-parse", "--verify", args.ref_b])).stdout.trim()
    const base = (await runGit(args.repo_path, ["merge-base", a, b])).stdout.trim()
    return { ref_a_resolved: a, ref_b_resolved: b, merge_base: base }
  },
})

export const git_show_ref = tool({
  description: "List references and their object ids with optional glob.",
  args: {
    repo_path: tool.schema.string(),
    ref_glob: tool.schema.string().optional(),
    max_refs: tool.schema.number().int().optional(),
  },
  async execute(args: any) {
    const cmd = ["show-ref"]
    if (args.ref_glob && args.ref_glob.trim()) cmd.push(args.ref_glob)
    const out = (await runGit(args.repo_path, cmd)).stdout
    const lines = out.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n")
    const refs: Array<{ oid: string; ref: string }> = []
    for (const line of lines) {
      if (!line) continue
      const m = /^([0-9a-f]{40})\s+(.+)$/.exec(line)
      if (!m) continue
      refs.push({ oid: m[1]!, ref: m[2]! })
      if (args.max_refs && refs.length >= args.max_refs) break
    }
    return { refs }
  },
})
