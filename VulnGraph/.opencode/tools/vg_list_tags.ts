import { tool } from "@opencode-ai/plugin"
import { spawn } from "child_process"

export default tool({
  description: "List Git tags without modifying the repository.",
  args: {
    repo_path: tool.schema.string(),
    tags_glob: tool.schema.string().optional(),
    max_tags: tool.schema.number().int().optional(),
  },
  async execute(args) {
    const prefix = ["-c", `safe.directory=${args.repo_path}`, "-C", args.repo_path]
    const command = args.tags_glob ? [...prefix, "tag", "-l", args.tags_glob] : [...prefix, "tag", "-l"]
    const output = await new Promise<string>((resolve, reject) => {
      const child = spawn("git", command, { stdio: ["ignore", "pipe", "pipe"] })
      let stdout = ""
      let stderr = ""
      child.stdout.on("data", (data) => { stdout += data.toString() })
      child.stderr.on("data", (data) => { stderr += data.toString() })
      child.on("error", reject)
      child.on("close", (code) => code === 0 ? resolve(stdout) : reject(new Error(stderr || `git exited with ${code}`)))
    })
    const tags = output.split(/\r?\n/).map((value) => value.trim()).filter(Boolean)
    return JSON.stringify({ tags: tags.slice(0, args.max_tags ?? 500) })
  },
})
