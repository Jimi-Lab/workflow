import { LocalContext } from "../util/local-context"
import type { WorkspaceID } from "./schema"

export interface WorkspaceContext {
  workspaceID: string
}

const context = LocalContext.create<WorkspaceContext>("instance")

export const WorkspaceContext = {
  async provide<R>(input: { workspaceID: WorkspaceID; fn: () => R }): Promise<R> {
    return context.provide({ workspaceID: input.workspaceID as string }, () => input.fn())
  },

  get workspaceID() {
    try {
      return context.use().workspaceID
    } catch (err) {
      return undefined
    }
  },
}
