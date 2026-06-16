declare module "@opencode-ai/plugin" {
  export function tool(def: any): any
  export namespace tool {
    export const schema: {
      string(): any
      number(): { int(): any; optional(): any }
      boolean(): { optional(): any }
    }
  }
}

declare module "child_process" {
  export function spawn(...args: any[]): any
}

declare module "node:child_process" {
  export function spawn(...args: any[]): any
}

declare const Bun: {
  spawn: (...args: any[]) => any
}
