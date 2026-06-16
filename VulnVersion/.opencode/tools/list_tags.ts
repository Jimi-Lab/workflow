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

export default tool({
  description: "List git tags with optional glob and limit.",
  args: {
    repo_path: tool.schema.string(),
    tags_glob: tool.schema.string().optional(),
    max_tags: tool.schema.number().int().optional(),
  },
  async execute(args: any) {
    const cmd = args.tags_glob && args.tags_glob.trim() ? ["tag", "-l", args.tags_glob] : ["tag", "-l"]
    const out = (await runGit(args.repo_path, cmd)).stdout
    const tags = out
      .replace(/\r\n/g, "\n")
      .replace(/\r/g, "\n")
      .split("\n")
      .map((t) => t.trim())
      .filter(Boolean)
    const limited = args.max_tags && args.max_tags > 0 ? tags.slice(0, args.max_tags) : tags
    return { tags: limited }
  },
})
