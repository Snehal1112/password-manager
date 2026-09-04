import * as React from "react"
import { caseCount, source, suites } from "@/data"
import { cn } from "@/lib/utils"
import type { Theme } from "@/lib/theme"
import type { RunSummary } from "@/lib/summary"
import { BrandMark } from "@/components/brand"
import { RunStrip } from "@/components/verdict"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"

function ThemeToggle({
  theme,
  setTheme,
}: {
  theme: Theme
  setTheme: (t: Theme) => void
}) {
  // Labels are capitalised in the markup, not with a `capitalize` class:
  // CSS casing is visual only, so a screen reader would announce "dark".
  const options: Array<[Theme, string]> = [
    ["system", "System"],
    ["light", "Light"],
    ["dark", "Dark"],
  ]
  return (
    <ToggleGroup
      aria-label="Colour theme"
      variant="outline"
      size="sm"
      spacing={0}
      value={[theme]}
      onValueChange={(v) => setTheme(((v as Theme[])[0] ?? "system") as Theme)}
    >
      {options.map(([value, label]) => (
        <ToggleGroupItem key={value} value={value}>
          {label}
        </ToggleGroupItem>
      ))}
    </ToggleGroup>
  )
}

/**
 * Memoised because the strip below is 208 ticks in 21 groups, and App
 * re-renders on every search keystroke, every j/k, every expand and every
 * scroll section change. `summary` is itself memoised on the run map, so this
 * now re-renders only when a verdict actually changes.
 */
export const Masthead = React.memo(function Masthead({
  summary,
  theme,
  setTheme,
}: {
  summary: RunSummary
  theme: Theme
  setTheme: (t: Theme) => void
}) {
  const { groups, pass, fail, todo } = summary

  return (
    <header className="border-b border-border bg-card">
      <div className="mx-auto max-w-[92rem] px-5 py-6 md:px-8 md:py-8">
        <div className="flex flex-wrap items-start justify-between gap-x-8 gap-y-5">
          <div className="min-w-0">
            {/* The mark is decorative here: the h1 beside it already says
                "RocketVault", so announcing it again would double the name for
                a screen reader. `aria-hidden` beats dropping the label inside
                BrandMark, which is also used where it stands alone. */}
            <div className="flex items-center gap-3">
              <BrandMark
                aria-hidden="true"
                className="size-8 shrink-0 rounded-[7px] md:size-9"
              />
              <h1 className="font-mono text-[22px] leading-none font-semibold tracking-tight md:text-[27px]">
                <span className="text-primary">RocketVault</span> Journeybook
              </h1>
            </div>
            <p className="mt-2.5 max-w-[62ch] text-[14px] leading-relaxed text-muted-foreground">
              {suites.length} journeys, {caseCount} checks. Every command and
              every expected line below is transcribed from{" "}
              <code className="rounded-[3px] bg-muted px-1 py-px font-mono text-[0.9em]">
                {source.doc}
              </code>
              , never invented — where a capability has no CLI equivalent, the
              check says so instead of showing something plausible.
            </p>
          </div>

          <div className="shrink-0">
            <ThemeToggle theme={theme} setTheme={setTheme} />
          </div>
        </div>

        {/* The run at a glance: a tick per check, grouped by journey, each
            group as wide as its share of the 208. Below sm the ticks would be
            under a pixel wide, so the old proportional bar takes over there --
            still true, just coarser, rather than a row of invisible marks. */}
        <RunStrip groups={groups} className="mt-6 hidden sm:flex" />
        <div
          aria-hidden="true"
          className="mt-6 flex h-1.5 overflow-hidden rounded-full bg-untested sm:hidden"
        >
          <span
            className="bg-success transition-[width] duration-300"
            style={{ width: `${(pass / caseCount) * 100}%` }}
          />
          <span
            className="bg-destructive transition-[width] duration-300"
            style={{ width: `${(fail / caseCount) * 100}%` }}
          />
        </div>

        {/* The figures are the accessible readout for both bars above, which
            are drawn aria-hidden. Baseline-aligned so the 22px numerals, the
            11.5px labels and the 12.5px sentence all sit on one line. */}
        <div className="mt-2.5 flex flex-wrap items-baseline gap-x-6 gap-y-2">
          <Figure n={pass} label="passed" tone="pass" />
          <Figure n={fail} label="failed" tone="fail" />
          <Figure n={todo} label="untested" tone="todo" />
          <p className="max-w-[52ch] text-[12.5px] leading-relaxed text-muted-foreground sm:ml-auto sm:text-right">
            {runNote(summary)}
          </p>
        </div>
      </div>
    </header>
  )
})

/**
 * Journey letters read as a phrase. The strip above is grouped by journey and
 * every section heading leads with the letter, so the letter is the handle a
 * tester already has. Past three, naming them stops being navigation and
 * starts being a list.
 */
function journeyList(keys: string[]) {
  if (keys.length > 3) return `${keys.length} journeys`
  if (keys.length === 1) return `journey ${keys[0]}`
  return `journeys ${keys.slice(0, -1).join(", ")} and ${keys[keys.length - 1]}`
}

/**
 * What the strip means, in a sentence. Failures are attributed to journeys
 * only once there are some -- that is the moment the strip has just drawn a
 * tall red tick somewhere in the middle of the run and the sentence's job is
 * to say where.
 */
function runNote({ done, fail, failedSuites }: RunSummary) {
  if (done === 0) {
    return (
      <>
        {/* A bare kbd, not the Kbd component: that one is a 22px inline-flex
            chip, which would inflate this line box and drag the sentence off
            the figures' baseline. */}
        Nothing recorded yet. Press <kbd className="text-foreground">n</kbd> to
        open the first check — verdicts stay in this browser.
      </>
    )
  }
  if (done === caseCount) {
    return fail === 0
      ? "Run complete, nothing failed."
      : `Run complete. ${fail} ${fail === 1 ? "check" : "checks"} to write up, in ${journeyList(failedSuites)}.`
  }
  if (fail === 0) return `${done} of ${caseCount} recorded, nothing failed yet.`
  return `${done} of ${caseCount} recorded. ${
    fail === 1 ? "One failure" : `${fail} failures`
  } in ${journeyList(failedSuites)}.`
}

function Figure({
  n,
  label,
  tone,
}: {
  n: number
  label: string
  tone: "pass" | "fail" | "todo"
}) {
  return (
    <div className="flex items-baseline gap-2">
      {/* 22px, not the 30px this used to be. It sat alone in the top-right
          corner then; under a full-width strip that size would out-shout the
          h1, and 22px rhymes with the tick height directly above. */}
      <span
        className={cn(
          "text-[22px] leading-none font-semibold tabular-nums",
          tone === "pass" && "text-success",
          tone === "fail" && "text-destructive",
          tone === "todo" && "text-muted-foreground"
        )}
      >
        {n}
      </span>
      <span className="label text-muted-foreground">{label}</span>
    </div>
  )
}
