import {
  capabilityMatrix,
  cast,
  commandGroups,
  corrections,
  errorTable,
  flagTraps,
  globalFlags,
  setupScript,
} from "@/data/reference"
import * as React from "react"
import { ChevronDown } from "lucide-react"
import { Prose } from "@/components/prose"
import { Terminal } from "@/components/terminal"
import { cn } from "@/lib/utils"

/** Remembers which prep panels a tester has folded away. */
const OPEN_KEY = "journeybook-panels-v1"

function readOpen(id: string, fallback: boolean): boolean {
  try {
    const raw = localStorage.getItem(OPEN_KEY)
    if (!raw) return fallback
    const map = JSON.parse(raw) as Record<string, boolean>
    return map[id] ?? fallback
  } catch {
    return fallback
  }
}

function writeOpen(id: string, open: boolean) {
  try {
    const raw = localStorage.getItem(OPEN_KEY)
    const map = raw ? (JSON.parse(raw) as Record<string, boolean>) : {}
    map[id] = open
    localStorage.setItem(OPEN_KEY, JSON.stringify(map))
  } catch {
    // Storage unavailable. The panel still opens and closes for this session.
  }
}

function Panel({
  id,
  title,
  lede,
  children,
  collapsible,
}: {
  id: string
  title: string
  lede?: string
  children: React.ReactNode
  /**
   * Set on the two panels that sit above the checks. They are prerequisites,
   * so they open by default -- but a tester on their third session has
   * already run setup and wants the checks nearer the top, so the choice is
   * remembered rather than reset on every load.
   */
  collapsible?: boolean
}) {
  const [open, setOpen] = React.useState(true)

  // Read persisted state after mount: reading localStorage during the first
  // render would make the markup depend on storage that can throw.
  React.useEffect(() => {
    if (collapsible) setOpen(readOpen(id, true))
  }, [collapsible, id])

  const toggle = () => {
    const next = !open
    setOpen(next)
    writeOpen(id, next)
  }

  const heading = (
    <>
      <h2 id={`${id}-heading`} className="text-[15px] font-semibold">
        {title}
      </h2>
      {lede ? (
        <p className="mt-1 max-w-[74ch] text-[13px] leading-relaxed text-muted-foreground">
          <Prose>{lede}</Prose>
        </p>
      ) : null}
    </>
  )

  return (
    <section
      id={id}
      aria-labelledby={`${id}-heading`}
      className="scroll-mt-24 rounded-lg border border-border bg-card"
    >
      {collapsible ? (
        <button
          type="button"
          onClick={toggle}
          aria-expanded={open}
          aria-controls={`${id}-body`}
          className={cn(
            "focus-ring flex w-full items-start gap-3 px-5 py-3.5 text-left",
            open && "border-b border-border"
          )}
        >
          <span className="min-w-0 flex-1">{heading}</span>
          <ChevronDown
            aria-hidden="true"
            className={cn(
              "mt-1 size-4 shrink-0 text-muted-foreground transition-transform",
              !open && "-rotate-90"
            )}
          />
        </button>
      ) : (
        <div className="border-b border-border px-5 py-3.5">{heading}</div>
      )}
      <div id={`${id}-body`} className="px-5 py-4" hidden={!open}>
        {children}
      </div>
    </section>
  )
}

export function SetupPanel() {
  return (
    <Panel
      id="setup"
      collapsible
      title="Before you run anything"
      lede="Point at a scratch instance, never a shared dev database. Every journey below assumes this has already run."
    >
      <Terminal label="Global setup" copy>
        {setupScript}
      </Terminal>
      <p className="mt-4 text-[13px] leading-relaxed text-muted-foreground">
        <span className="font-medium text-foreground">
          Available on every command:{" "}
        </span>
        <code className="rounded-[3px] bg-muted px-1 py-px font-mono text-[0.9em]">
          {globalFlags}
        </code>
      </p>
    </Panel>
  )
}

export function CastPanel() {
  return (
    <Panel
      id="cast"
      collapsible
      title="The cast"
      lede="Global role and per-vault role are two independent things, and the CLI checks both. These global roles are the ones the CLI actually requires — a principal without them is refused before their vault grant is even consulted."
    >
      <div className="overflow-x-auto">
        <table className="w-full text-left text-[13px]">
          <thead className="text-muted-foreground">
            <tr className="border-b border-border">
              <th scope="col" className="py-2 pr-4 font-medium">
                Principal
              </th>
              <th scope="col" className="py-2 pr-4 font-medium">
                Global role
              </th>
              <th scope="col" className="py-2 font-medium">
                Why that role
              </th>
            </tr>
          </thead>
          <tbody>
            {cast.map((c) => (
              <tr
                key={c.name}
                className="border-b border-border/60 last:border-0"
              >
                <td className="py-2 pr-4 font-mono whitespace-nowrap">
                  {c.name}
                </td>
                <td className="py-2 pr-4 font-mono whitespace-nowrap text-foreground">
                  {c.role}
                </td>
                <td className="py-2 leading-snug text-muted-foreground">
                  {c.why}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  )
}

export function ErrorPanel() {
  return (
    <Panel
      id="errors"
      title="Which gate produced your error"
      lede="A test that only asserts “non-200” cannot tell these apart, and the difference is usually the finding."
    >
      <dl className="space-y-3.5">
        {errorTable.map((e) => (
          <div
            key={e.message}
            className="grid gap-1.5 md:grid-cols-[1.2fr_1fr] md:gap-6"
          >
            <dt className="transcript rounded border border-term-border bg-term px-2.5 py-1.5 text-term-foreground">
              <span className="transcript-line">{e.message}</span>
            </dt>
            <dd className="self-center text-[13px] leading-snug text-muted-foreground">
              {e.gate}
            </dd>
          </div>
        ))}
      </dl>
    </Panel>
  )
}

export function CapabilityPanel() {
  return (
    <Panel
      id="capabilities"
      title="What each door can reach"
      lede="Large parts of the key and certificate lifecycle have no CLI command at all. Reaching for one that does not exist is the most common way to waste an hour in this playbook."
    >
      <div className="overflow-x-auto">
        <table className="w-full text-left text-[13px]">
          <thead className="text-muted-foreground">
            <tr className="border-b border-border">
              <th scope="col" className="py-2 pr-4 font-medium">
                Capability
              </th>
              <th scope="col" className="py-2 pr-4 font-medium">
                CLI
              </th>
              <th scope="col" className="py-2 font-medium">
                HTTP
              </th>
            </tr>
          </thead>
          <tbody>
            {capabilityMatrix.map((r) => (
              <tr
                key={r.capability}
                className="border-b border-border/60 last:border-0"
              >
                <td className="py-2 pr-4">{r.capability}</td>
                <td className="py-2 pr-4 font-mono whitespace-nowrap">
                  {r.cli === "none" ? (
                    <span className="text-muted-foreground">none</span>
                  ) : (
                    r.cli
                  )}
                </td>
                <td className="py-2 font-mono">
                  {r.http === "none" ? (
                    <span className="text-muted-foreground">none</span>
                  ) : (
                    r.http
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  )
}

export function CommandPanel() {
  return (
    <Panel
      id="commands"
      title="Command groups and flag traps"
      lede="Every group the CLI registers, then the flags whose behaviour does not match their help text."
    >
      <div className="overflow-x-auto">
        <table className="w-full text-left text-[13px]">
          <tbody>
            {commandGroups.map((g) => (
              <tr key={g.group} className="border-b border-border/60">
                <td className="py-1.5 pr-5 font-mono whitespace-nowrap">
                  rocketvault {g.group}
                </td>
                <td className="py-1.5 font-mono text-muted-foreground">
                  {g.subcommands}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <dl className="mt-6 space-y-3">
        {flagTraps.map((t) => (
          <div
            key={t.command}
            className="grid gap-1 md:grid-cols-[minmax(0,17rem)_1fr] md:gap-6"
          >
            <dt className="font-mono text-[13px] leading-snug">{t.command}</dt>
            <dd className="text-[13px] leading-relaxed text-muted-foreground">
              {t.gotcha}
            </dd>
          </div>
        ))}
      </dl>
    </Panel>
  )
}

export function CorrectionsPanel() {
  return (
    <Panel
      id="corrections"
      title="Nine claims that turned out to be wrong"
      lede="Each of these was believed, written down, and then disproved against the code. If a runbook in your team still says the left-hand column, it needs fixing."
    >
      <ol className="space-y-4">
        {corrections.map((c) => (
          <li
            key={c.n}
            className="grid gap-1.5 md:grid-cols-[1fr_1.3fr] md:gap-6"
          >
            <p className="text-[13px] leading-relaxed text-muted-foreground line-through decoration-1">
              {c.claimed}
            </p>
            <p className="text-[13px] leading-relaxed">
              <Prose>{c.actual}</Prose>
            </p>
          </li>
        ))}
      </ol>
    </Panel>
  )
}
