import { tool } from "@opencode-ai/plugin"
import { spawn } from "child_process"

type GitResult = { stdout: string; stderr: string; exitCode: number }

async function runGit(repoPath: string, args: string[], allowedExitCodes: number[] = []): Promise<GitResult> {
  return new Promise((resolve, reject) => {
    const child = spawn("git", ["-c", `safe.directory=${repoPath}`, "-C", repoPath, ...args], {
      stdio: ["ignore", "pipe", "pipe"],
    })
    let stdout = ""
    let stderr = ""
    child.stdout.on("data", (data) => { stdout += data.toString() })
    child.stderr.on("data", (data) => { stderr += data.toString() })
    child.on("error", reject)
    child.on("close", (code) => {
      const exitCode = code ?? 1
      if (exitCode !== 0 && !allowedExitCodes.includes(exitCode)) {
        reject(new Error(stderr.trim() || stdout.trim() || `git exited with ${exitCode}`))
      } else {
        resolve({ stdout, stderr, exitCode })
      }
    })
  })
}

async function resolveRef(repoPath: string, ref: string): Promise<string> {
  return (await runGit(repoPath, ["rev-parse", "--verify", ref])).stdout.trim()
}

function limited(text: string, maxChars?: number): string {
  return maxChars && maxChars > 0 ? text.slice(0, maxChars) : text
}

export const git_diff = tool({
  description: "Read a commit patch without modifying the repository.",
  args: {
    repo_path: tool.schema.string(),
    commit: tool.schema.string(),
    max_chars: tool.schema.number().int().optional(),
  },
  async execute(args) {
    const commit = await resolveRef(args.repo_path, args.commit)
    const patch = (await runGit(args.repo_path, ["show", "--patch", "--no-color", "--format=fuller", commit])).stdout
    return JSON.stringify({ commit, patch: limited(patch, args.max_chars) })
  },
})

export const git_show = tool({
  description: "Read a file at a Git ref without checkout.",
  args: {
    repo_path: tool.schema.string(),
    ref: tool.schema.string(),
    path: tool.schema.string(),
    start_line: tool.schema.number().int().optional(),
    end_line: tool.schema.number().int().optional(),
  },
  async execute(args) {
    const ref = await resolveRef(args.repo_path, args.ref)
    const content = (await runGit(args.repo_path, ["show", `${ref}:${args.path}`])).stdout
    const lines = content.replace(/\r\n/g, "\n").split("\n")
    const start = Math.max(1, args.start_line ?? 1)
    const end = Math.min(lines.length, args.end_line ?? lines.length)
    return JSON.stringify({ ref, path: args.path, start_line: start, end_line: end, lines: lines.slice(start - 1, end) })
  },
})

export const git_grep = tool({
  description: "Search a pattern at a Git ref without checkout.",
  args: {
    repo_path: tool.schema.string(),
    ref: tool.schema.string(),
    pattern: tool.schema.string(),
    path_glob: tool.schema.string().optional(),
    max_matches: tool.schema.number().int().optional(),
  },
  async execute(args) {
    const ref = await resolveRef(args.repo_path, args.ref)
    const command = ["grep", "-n", "--no-color", "-e", args.pattern, ref]
    if (args.path_glob) command.push("--", args.path_glob)
    const result = await runGit(args.repo_path, command, [1])
    const matches = result.exitCode === 1 ? [] : result.stdout.split(/\r?\n/).filter(Boolean)
    return JSON.stringify({ ref, pattern: args.pattern, matches: matches.slice(0, args.max_matches ?? 100) })
  },
})

export const git_log = tool({
  description: "Read Git history without modifying the repository.",
  args: {
    repo_path: tool.schema.string(),
    range_or_ref: tool.schema.string(),
    path_glob: tool.schema.string().optional(),
    max_commits: tool.schema.number().int().optional(),
  },
  async execute(args) {
    const command = ["log", "--oneline", "--decorate", `--max-count=${args.max_commits ?? 50}`, args.range_or_ref]
    if (args.path_glob) command.push("--", args.path_glob)
    return JSON.stringify({ commits: (await runGit(args.repo_path, command)).stdout.split(/\r?\n/).filter(Boolean) })
  },
})

export const git_ls_tree = tool({
  description: "List files at a Git ref without checkout.",
  args: {
    repo_path: tool.schema.string(),
    ref: tool.schema.string(),
    path: tool.schema.string().optional(),
    recursive: tool.schema.boolean().optional(),
    max_entries: tool.schema.number().int().optional(),
  },
  async execute(args) {
    const ref = await resolveRef(args.repo_path, args.ref)
    const command = ["ls-tree"]
    if (args.recursive) command.push("-r")
    command.push(ref)
    if (args.path) command.push("--", args.path)
    const entries = (await runGit(args.repo_path, command)).stdout.split(/\r?\n/).filter(Boolean)
    return JSON.stringify({ ref, entries: entries.slice(0, args.max_entries ?? 500) })
  },
})

export const git_cat_file = tool({
  description: "Inspect a Git object without modifying the repository.",
  args: {
    repo_path: tool.schema.string(),
    object: tool.schema.string(),
    pretty: tool.schema.boolean().optional(),
    max_chars: tool.schema.number().int().optional(),
  },
  async execute(args) {
    const object = await resolveRef(args.repo_path, args.object)
    const type = (await runGit(args.repo_path, ["cat-file", "-t", object])).stdout.trim()
    const size = Number((await runGit(args.repo_path, ["cat-file", "-s", object])).stdout.trim())
    const content = args.pretty ? limited((await runGit(args.repo_path, ["cat-file", "-p", object])).stdout, args.max_chars) : undefined
    return JSON.stringify({ object, type, size, content })
  },
})

export const git_rev_parse = tool({
  description: "Resolve a Git revision.",
  args: { repo_path: tool.schema.string(), rev: tool.schema.string() },
  async execute(args) { return JSON.stringify({ rev: args.rev, resolved: await resolveRef(args.repo_path, args.rev) }) },
})

export const git_merge_base = tool({
  description: "Compute the merge base of two Git refs.",
  args: { repo_path: tool.schema.string(), ref_a: tool.schema.string(), ref_b: tool.schema.string() },
  async execute(args) {
    const refA = await resolveRef(args.repo_path, args.ref_a)
    const refB = await resolveRef(args.repo_path, args.ref_b)
    const mergeBase = (await runGit(args.repo_path, ["merge-base", refA, refB])).stdout.trim()
    return JSON.stringify({ ref_a: refA, ref_b: refB, merge_base: mergeBase })
  },
})

export const git_show_ref = tool({
  description: "List Git references.",
  args: {
    repo_path: tool.schema.string(),
    ref_glob: tool.schema.string().optional(),
    max_refs: tool.schema.number().int().optional(),
  },
  async execute(args) {
    const command = ["show-ref"]
    if (args.ref_glob) command.push(args.ref_glob)
    const refs = (await runGit(args.repo_path, command)).stdout.split(/\r?\n/).filter(Boolean)
    return JSON.stringify({ refs: refs.slice(0, args.max_refs ?? 500) })
  },
})
