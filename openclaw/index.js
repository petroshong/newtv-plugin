// NewTV.dev for OpenClaw: OpenClaw's plugin hooks, translated to the events
// NewTV.dev's hook already handles for Claude Code, Codex and Cursor. Each
// event runs ~/.newtv/newtv-hook.mjs (the same file, checked against its
// published checksum when installed), so secrets are removed on this machine
// before anything is sent, exactly as for the other agents.
import { spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const HOOK = [process.env.NEWTV_HOOK, join(here, '..', 'newtv-hook.mjs'), join(homedir(), '.newtv', 'newtv-hook.mjs')].find((p) => p && existsSync(p))

// Runs the hook with one event; resolves with what it printed (JSON), or null.
function run(event) {
  if (!HOOK) return Promise.resolve(null)
  return new Promise((done) => {
    const child = spawn(process.execPath, [HOOK], { stdio: ['pipe', 'pipe', 'ignore'] })
    let out = ''
    const timer = setTimeout(() => child.kill(), 15_000)
    child.stdout.on('data', (d) => (out += d))
    child.on('close', () => {
      clearTimeout(timer)
      try {
        done(out.trim() ? JSON.parse(out) : null)
      } catch {
        done(null)
      }
    })
    child.on('error', () => done(null))
    child.stdin.end(JSON.stringify({ openclaw: true, ...event }))
  })
}

// OpenClaw's tools, as the hook knows them.
const text = (v) => {
  if (typeof v === 'string') return v
  const parts = Array.isArray(v) ? v : Array.isArray(v?.content) ? v.content : null
  if (parts) return parts.map((c) => (typeof c === 'string' ? c : c?.text ?? '')).join('\n')
  return v == null ? '' : JSON.stringify(v)
}
function asTool(name, params = {}, result) {
  const path = params.path ?? params.file_path ?? params.filePath
  switch (name) {
    case 'exec':
    case 'bash':
      return { tool_name: 'Bash', tool_input: { command: params.command ?? params.cmd ?? '', description: params.description }, tool_response: { stdout: text(result), exitCode: result?.details?.exitCode ?? result?.exitCode } }
    case 'read':
      return { tool_name: 'Read', tool_input: { file_path: path } }
    case 'write':
      return { tool_name: 'Write', tool_input: { file_path: path, content: params.content } }
    case 'edit':
      return { tool_name: 'Edit', tool_input: { file_path: path, ...(Array.isArray(params.edits) ? { edits: params.edits.map((e) => ({ old_string: e.oldText ?? e.old_string, new_string: e.newText ?? e.new_string })) } : { old_string: params.oldText ?? params.old_string, new_string: params.newText ?? params.new_string }) } }
    case 'apply_patch':
      return { tool_name: 'apply_patch', tool_input: { input: params.input ?? params.patch } }
    case 'web_search':
      return { tool_name: 'WebSearch', tool_input: { query: params.query } }
    case 'web_fetch':
      return { tool_name: 'WebFetch', tool_input: { url: params.url } }
    default:
      return { tool_name: name, tool_input: params, tool_response: { output: text(result).slice(0, 2000) } }
  }
}
const lastReply = (messages = []) => {
  for (let i = messages.length - 1; i >= 0; i--) {
    const m = messages[i]
    if (m?.role === 'assistant') return text(m.content ?? m) || null
  }
  return null
}

// A chat command's reply, or a prompt's context, handed from the first hook
// that sees a prompt to the next (the hook runs once per prompt).
const pending = new Map() // session id -> context for the prompt

export default {
  id: 'newtv',
  name: 'NewTV.dev',
  description: 'Broadcast OpenClaw sessions on NewTV.dev and learn from other agents.',
  register(api) {
    const base = (ctx = {}) => ({ session_id: ctx.sessionId ?? ctx.sessionKey ?? 'openclaw', cwd: ctx.workspaceDir ?? process.cwd(), model: ctx.modelId })
    // "newtv ..." typed as a message: answered here, never sent to the model.
    api.on('before_agent_reply', async (event, ctx) => {
      const prompt = String(event?.cleanedBody ?? event?.body ?? '')
      if (!/^\s*\/?newtv\b/i.test(prompt)) return
      const out = await run({ ...base(ctx), hook_event_name: 'UserPromptSubmit', prompt })
      if (out?.decision === 'block') return { handled: true, reply: { text: out.reason } }
      // An ordinary prompt that starts with "newtv": it's broadcast; keep its context.
      pending.set(base(ctx).session_id, out?.hookSpecificOutput?.additionalContext ?? '')
    }, { eligibleTriggers: ['user'] })
    // Each prompt: the session's broadcast starts or gets a new chapter; the
    // agent gets NewTV.dev's note (the watch link, a playbook if one fits).
    api.on('before_prompt_build', async (event, ctx) => {
      const id = base(ctx).session_id
      let context = pending.get(id)
      pending.delete(id)
      if (context === undefined) {
        const out = await run({ ...base(ctx), hook_event_name: 'UserPromptSubmit', prompt: String(event?.prompt ?? '') })
        context = out?.hookSpecificOutput?.additionalContext
      }
      return context ? { appendContext: context } : undefined
    })
    api.on('after_tool_call', async (event, ctx) => {
      const t = asTool(event?.toolName ?? ctx?.toolName, event?.params, event?.result)
      await run({ ...base(ctx), ...t, tool_use_id: event?.toolCallId ?? ctx?.toolCallId, ...(event?.error ? { hook_event_name: 'PostToolUseFailure', error: event.error } : { hook_event_name: 'PostToolUse' }) })
    })
    api.on('agent_end', async (event, ctx) => {
      await run({ ...base(ctx), hook_event_name: 'Stop', last_assistant_message: lastReply(event?.messages), ...(event?.success === false ? { status: 'error' } : {}) })
    })
    api.on('session_end', async (event, ctx) => {
      await run({ ...base(ctx), session_id: event?.sessionId ?? base(ctx).session_id, hook_event_name: 'SessionEnd' })
    })
  },
}
