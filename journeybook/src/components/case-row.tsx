import * as React from "react"
import { ChevronRight } from "lucide-react"
import { cn } from "@/lib/utils"
import type { FlatCase } from "@/data"
import type { Case } from "@/data/types"
import type { Verdict } from "@/lib/run-state"
import { GutterSegment, VerdictControl } from "@/components/verdict"
import { Terminal } from "@/components/terminal"
import { Prose } from "@/components/prose"
import { Badge } from "@/components/ui/badge"

const surfaceLabel: Record<Case["surface"], string> = {
  cli: "CLI",
  http: "HTTP",
  both: "CLI + HTTP",
  db: "Database",
  local: "Local",
}

const flagLabel: Record<NonNullable<Case["flag"]>, string> = {
  divergence: "Divergence",
  gap: "Gap",
  trap: "Trap",
}

export function CaseRow({
  item,
  verdict,
  onVerdict,
  open,
  onToggle,
  focused,
}: {
  item: FlatCase
  verdict: Verdict
  onVerdict: (v: Verdict) => void
  open: boolean
  onToggle: () => void
  focused: boolean
}) {
  const panelId = `case-panel-${item.id}`
  // Only a verdict recorded in this session animates. Re-rendering a restored
  // run should not replay 150 animations on load.
  const first = React.useRef(true)
  React.useEffect(() => {
    first.current = false
  }, [])

  return (
    <li
      id={`case-${item.id}`}
      data-case={item.id}
      className={cn(
        "relative border-b border-border/70 last:border-b-0",
        focused && "bg-accent/40"
      )}
    >
      {/* The gutter. One segment per case, running the full height of the row
          with no gap above or below, so the rail down the page is a single
          unbroken readout of the whole run rather than a column of marks. */}
      <GutterSegment
        verdict={verdict}
        animate={!first.current}
        className="absolute inset-y-0 left-0 w-[4px]"
      />

      <div className="flex flex-col gap-1.5 py-2.5 pr-3 pl-5 sm:flex-row sm:items-start sm:gap-3">
        <button
          type="button"
          onClick={onToggle}
          aria-expanded={open}
          aria-controls={panelId}
          className="focus-ring group flex min-w-0 flex-1 items-start gap-3 text-left"
        >
          <ChevronRight
            aria-hidden="true"
            className={cn(
              "mt-[3px] size-3.5 shrink-0 text-muted-foreground transition-transform",
              open && "rotate-90"
            )}
          />
          <span className="mt-px w-9 shrink-0 font-mono text-[12px] text-muted-foreground tabular-nums">
            {item.id}
          </span>
          <span className="min-w-0 flex-1">
            <span className="block text-[14px] leading-snug font-medium group-hover:text-primary">
              {item.title}
            </span>
            <span className="mt-0.5 block text-[13px] leading-snug text-muted-foreground">
              {item.assert}
            </span>
          </span>
        </button>

        <div className="flex shrink-0 items-center gap-2 pl-[1.6rem] sm:pt-px sm:pl-0">
          {item.flag ? (
            <Badge variant="outline">{flagLabel[item.flag]}</Badge>
          ) : null}
          <span className="label shrink-0 text-muted-foreground sm:w-16 sm:text-right">
            {surfaceLabel[item.surface]}
          </span>
          <VerdictControl verdict={verdict} onChange={onVerdict} size="sm" />
        </div>
      </div>

      {open ? (
        <div
          id={panelId}
          className="space-y-4 pt-1 pr-3 pb-5 pl-5 sm:pl-[4.4rem]"
        >
          {item.precondition ? (
            <p className="max-w-[68ch] text-[13px] leading-relaxed text-muted-foreground">
              <span className="font-medium text-foreground">
                Before you run it.{" "}
              </span>
              <Prose>{item.precondition}</Prose>
            </p>
          ) : null}

          <Terminal label="Run" copy>
            {item.command}
          </Terminal>

          <Terminal label="Expected" tone="output">
            {item.expected}
          </Terminal>

          {item.notes ? (
            <p className="max-w-[68ch] text-[13px] leading-relaxed text-muted-foreground">
              <Prose>{item.notes}</Prose>
            </p>
          ) : null}
        </div>
      ) : null}
    </li>
  )
}
