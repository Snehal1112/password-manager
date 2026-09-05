import * as React from "react"
import { Search } from "lucide-react"
import { allCases, caseCount, suites } from "@/data"
import type { FlatCase } from "@/data"
import { buildReport } from "@/lib/report"
import { useRunState, type Verdict } from "@/lib/run-state"
import { summarise } from "@/lib/summary"
import { useTheme } from "@/lib/theme"
import { CaseRow } from "@/components/case-row"
import { Footer } from "@/components/footer"
import { GateDiagram } from "@/components/gate-diagram"
import { Masthead } from "@/components/masthead"
import { Prose } from "@/components/prose"
import { Rail } from "@/components/rail"
import { Input } from "@/components/ui/input"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import {
  CapabilityPanel,
  CastPanel,
  CommandPanel,
  CorrectionsPanel,
  ErrorPanel,
  SetupPanel,
} from "@/components/reference-panels"

type Filter = "all" | "todo" | "pass" | "fail"

const filters: Array<[Filter, string]> = [
  ["all", "All"],
  ["todo", "Untested"],
  ["pass", "Passed"],
  ["fail", "Failed"],
]

/**
 * Honour the reduced-motion preference for JS-driven scrolling. The CSS block
 * in index.css resets `scroll-behavior`, which only governs scrolling the
 * browser starts; a `behavior: "smooth"` passed straight to the scroll API
 * ignores it, so every j/k press animated regardless of the setting.
 */
function scrollBehavior(): ScrollBehavior {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches
    ? "auto"
    : "smooth"
}

const SHORTCUTS_KEY = "journeybook-shortcuts"

/** Fields a search query is matched against. Ids are included so "A7" works. */
function haystack(c: FlatCase) {
  return [
    c.id,
    c.title,
    c.assert,
    c.command,
    c.expected,
    c.precondition,
    c.notes,
    c.suiteTitle,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase()
}

export default function App() {
  const { run, setVerdict, reset, verdictOf } = useRunState()
  const { theme, setTheme } = useTheme()

  const [filter, setFilter] = React.useState<Filter>("all")
  const [query, setQuery] = React.useState("")
  const [open, setOpen] = React.useState<Set<string>>(() => new Set())
  const [focusId, setFocusId] = React.useState<string | null>(null)
  const [copied, setCopied] = React.useState(false)
  const [activeSuite, setActiveSuite] = React.useState<string | null>(null)
  const searchRef = React.useRef<HTMLInputElement>(null)

  /*
   * Every binding here is a single unmodified character, which WCAG 2.1.4
   * only permits if it can be turned off, remapped, or confined to a focused
   * component. This is the "turned off" arm. It also matters in practice:
   * f and e are JAWS quick-nav keys, so a screen-reader user needs a way to
   * stop this page competing for them.
   */
  const [shortcuts, setShortcuts] = React.useState(() => {
    try {
      return localStorage.getItem(SHORTCUTS_KEY) !== "off"
    } catch {
      return true
    }
  })
  const toggleShortcuts = React.useCallback(() => {
    setShortcuts((on) => {
      try {
        localStorage.setItem(SHORTCUTS_KEY, on ? "off" : "on")
      } catch {
        // Storage blocked; the choice still holds for this session.
      }
      return !on
    })
  }, [])

  // One pass over the run, keyed on the run itself -- so typing in the search
  // box no longer re-tallies 208 cases, and the masthead's strip and figures
  // come from a single derivation rather than agreeing by coincidence.
  const summary = React.useMemo(() => summarise(run), [run])

  const q = query.trim().toLowerCase()
  const matches = React.useCallback(
    (c: FlatCase) => {
      if (filter !== "all" && verdictOf(c.id) !== filter) return false
      if (q && !haystack(c).includes(q)) return false
      return true
    },
    [filter, q, verdictOf]
  )

  /** The cases currently on screen, in document order -- j/k walk this. */
  const visible = React.useMemo(() => allCases.filter(matches), [matches])

  const toggleOpen = React.useCallback((id: string) => {
    setOpen((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  const focusCase = React.useCallback((id: string) => {
    setFocusId(id)
    const el = document.getElementById(`case-${id}`)
    el?.scrollIntoView({ block: "center", behavior: scrollBehavior() })
    // Move real focus, not just the highlight. The bg-accent tint alone is
    // invisible to a screen reader and to forced-colors mode, and it left the
    // "current" row disconnected from the browser's own focus, so Tab carried
    // on from wherever it had been. preventScroll because the line above has
    // already placed the row.
    el?.querySelector<HTMLButtonElement>("button")?.focus({
      preventScroll: true,
    })
  }, [])

  const nextTodo = React.useCallback(() => {
    const from = focusId ? allCases.findIndex((c) => c.id === focusId) + 1 : 0
    const order = [...allCases.slice(from), ...allCases.slice(0, from)]
    const target = order.find((c) => verdictOf(c.id) === "todo")
    if (target) focusCase(target.id)
  }, [focusId, verdictOf, focusCase])

  const copyReport = React.useCallback(async () => {
    try {
      await navigator.clipboard.writeText(buildReport(verdictOf))
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1800)
    } catch {
      // Clipboard blocked. Nothing useful to fall back to here.
    }
  }, [verdictOf])

  const clearRun = React.useCallback(() => {
    if (
      window.confirm(
        "Clear every recorded verdict? This cannot be undone, and the summary is not saved anywhere else."
      )
    ) {
      reset()
    }
  }, [reset])

  // Keyboard. Every binding is a bare letter, so it must not fire while the
  // tester is typing into the search box.
  React.useEffect(() => {
    if (!shortcuts) return
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null
      const typing =
        t &&
        (t.tagName === "INPUT" ||
          t.tagName === "TEXTAREA" ||
          t.isContentEditable)

      // A held key should not record 40 verdicts.
      if (e.repeat) return

      if (e.key === "/" && !typing) {
        e.preventDefault()
        searchRef.current?.focus()
        return
      }
      if (e.key === "Escape" && t === searchRef.current) {
        searchRef.current?.blur()
        return
      }
      if (typing || e.metaKey || e.ctrlKey || e.altKey) return

      const idx = focusId ? visible.findIndex((c) => c.id === focusId) : -1

      switch (e.key) {
        case "j": {
          e.preventDefault()
          const next = visible[Math.min(idx + 1, visible.length - 1)]
          if (next) focusCase(next.id)
          break
        }
        case "k": {
          e.preventDefault()
          const prev = visible[Math.max(idx - 1, 0)]
          if (prev) focusCase(prev.id)
          break
        }
        case "n":
          e.preventDefault()
          nextTodo()
          break
        case "p":
          if (focusId) setVerdict(focusId, "pass")
          break
        case "f":
          if (focusId) setVerdict(focusId, "fail")
          break
        case "x":
          if (focusId) setVerdict(focusId, "todo")
          break
        case "o":
          if (focusId) toggleOpen(focusId)
          break
        case "e":
          setOpen((prev) =>
            prev.size >= visible.length
              ? new Set()
              : new Set(visible.map((c) => c.id))
          )
          break
        default:
          break
      }
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [visible, focusId, focusCase, nextTodo, setVerdict, toggleOpen, shortcuts])

  // Highlight the journey the reader is actually looking at.
  React.useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        const shown = entries
          .filter((en) => en.isIntersecting)
          .sort(
            (a, b) => a.boundingClientRect.top - b.boundingClientRect.top
          )[0]
        if (shown) setActiveSuite(shown.target.id.replace("suite-", ""))
      },
      { rootMargin: "-15% 0px -70% 0px" }
    )
    for (const s of suites) {
      const el = document.getElementById(`suite-${s.key}`)
      if (el) observer.observe(el)
    }
    return () => observer.disconnect()
  }, [])

  return (
    <div className="min-h-dvh">
      {/* Roughly thirty tab stops sit between the top of the page and the
          first check -- the theme toggle, then the whole rail. */}
      <a
        href="#checks"
        className="focus-ring sr-only rounded-lg bg-card px-4 py-2 text-[13px] font-medium focus:not-sr-only focus:absolute focus:top-3 focus:left-3 focus:z-50 focus:border focus:border-border"
      >
        Skip to the checks
      </a>
      <Masthead summary={summary} theme={theme} setTheme={setTheme} />

      <div className="mx-auto max-w-[92rem] px-5 py-6 md:px-8 md:py-8">
        <GateDiagram />

        <div className="mt-8 grid gap-8 lg:grid-cols-[17rem_minmax(0,1fr)] lg:gap-10">
          <Rail
            verdictOf={verdictOf}
            activeSuite={activeSuite}
            onNextTodo={nextTodo}
            onReset={clearRun}
            onCopyReport={copyReport}
            copied={copied}
            shortcuts={shortcuts}
            onToggleShortcuts={toggleShortcuts}
          />

          <main className="min-w-0">
            {/* Prerequisites, so they come before the thing they prepare you
                for. Both fold away and remember the choice, because a tester
                on their third session has already run setup. */}
            <div className="mb-8 space-y-4">
              <SetupPanel />
              <CastPanel />
            </div>

            <div
              id="checks"
              className="sticky top-0 z-10 flex scroll-mt-4 flex-wrap items-center gap-3 bg-background/95 py-3 backdrop-blur"
            >
              <div className="relative basis-full sm:min-w-[13rem] sm:flex-1 sm:basis-auto">
                <Search
                  aria-hidden="true"
                  className="pointer-events-none absolute top-1/2 left-3.5 z-1 size-3.5 -translate-y-1/2 text-muted-foreground"
                />
                <Input
                  ref={searchRef}
                  type="search"
                  aria-label="Search checks"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Search commands, errors, or a check id"
                  className="border-input bg-card pl-9"
                />
              </div>

              <ToggleGroup
                aria-label="Filter by result"
                variant="outline"
                size="sm"
                spacing={0}
                value={[filter]}
                onValueChange={(v) =>
                  setFilter(((v as Filter[])[0] ?? "all") as Filter)
                }
                className="bg-card"
              >
                {filters.map(([f, label]) => (
                  <ToggleGroupItem key={f} value={f}>
                    {label}
                  </ToggleGroupItem>
                ))}
              </ToggleGroup>

              <span
                aria-live="polite"
                className="text-[12.5px] text-muted-foreground tabular-nums"
              >
                {visible.length} of {caseCount}
              </span>
            </div>

            {visible.length === 0 ? (
              <p className="rounded-lg border border-dashed border-border px-5 py-10 text-center text-[14px] text-muted-foreground">
                Nothing matches that. Clear the search, or switch the filter
                back to All.
              </p>
            ) : (
              <div className="space-y-8">
                {suites.map((s) => {
                  const shown = s.cases.filter((c) =>
                    matches({ ...c, suiteKey: s.key, suiteTitle: s.title })
                  )
                  if (!shown.length) return null
                  const p = s.cases.filter(
                    (c) => verdictOf(c.id) === "pass"
                  ).length
                  const f = s.cases.filter(
                    (c) => verdictOf(c.id) === "fail"
                  ).length

                  return (
                    <section
                      key={s.key}
                      id={`suite-${s.key}`}
                      aria-labelledby={`suite-${s.key}-heading`}
                      className="scroll-mt-20"
                    >
                      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
                        {/* The letter is inside the heading, not beside it,
                            so a narrow viewport cannot wrap it away from the
                            title it identifies. */}
                        <h2
                          id={`suite-${s.key}-heading`}
                          className="flex min-w-0 items-baseline gap-3 text-[17px] leading-tight font-semibold"
                        >
                          <span className="shrink-0 font-mono text-[15px] text-primary">
                            {s.key}
                          </span>
                          <span className="min-w-0">{s.title}</span>
                        </h2>
                        <span className="shrink-0 font-mono text-[12.5px] text-muted-foreground tabular-nums">
                          {f > 0 ? (
                            <span className="mr-2 text-destructive">
                              {f} failed
                            </span>
                          ) : null}
                          {p}/{s.cases.length}
                        </span>
                      </div>
                      <p className="mt-1 pl-[1.6rem] text-[13px] text-muted-foreground">
                        {s.actor}
                      </p>
                      <p className="mt-2.5 max-w-[74ch] pl-[1.6rem] text-[13.5px] leading-relaxed text-muted-foreground">
                        <Prose>{s.premise}</Prose>
                      </p>

                      <ul className="mt-4 overflow-hidden rounded-lg border border-border bg-card">
                        {shown.map((c) => (
                          <CaseRow
                            key={c.id}
                            item={{
                              ...c,
                              suiteKey: s.key,
                              suiteTitle: s.title,
                            }}
                            verdict={verdictOf(c.id) as Verdict}
                            onVerdict={(v) => {
                              setVerdict(c.id, v)
                              setFocusId(c.id)
                            }}
                            open={open.has(c.id)}
                            onToggle={() => {
                              toggleOpen(c.id)
                              setFocusId(c.id)
                            }}
                            focused={focusId === c.id}
                          />
                        ))}
                      </ul>
                    </section>
                  )
                })}
              </div>
            )}

            {/* Lookups, not prerequisites: consulted mid-run when a result
                surprises you. The prep panels moved above the checks. */}
            <div className="mt-12 space-y-6">
              <ErrorPanel />
              <CapabilityPanel />
              <CommandPanel />
              <CorrectionsPanel />
            </div>
          </main>
        </div>
      </div>

      <Footer
        onBackToTop={() =>
          window.scrollTo({ top: 0, behavior: scrollBehavior() })
        }
      />
    </div>
  )
}
