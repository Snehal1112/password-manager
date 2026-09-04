import { gates } from "@/data/reference"
import { Prose } from "@/components/prose"

/**
 * The page opens on this rather than a headline number, because it is the one
 * thing a RocketVault tester has to hold in their head to read any result
 * correctly. Three 403s mean three different things, and the journeys exist
 * largely to tell them apart.
 *
 * The numbering is earned: the gates genuinely run in this order, and a
 * request refused at gate 1 never reaches gate 3.
 */
export function GateDiagram() {
  return (
    <section
      aria-labelledby="gates-heading"
      className="rounded-lg border border-border bg-card"
    >
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 border-b border-border px-5 py-3.5">
        <h2 id="gates-heading" className="text-[15px] font-semibold">
          Three gates, in order
        </h2>
        <p className="text-[13px] text-muted-foreground">
          A request refused at gate 1 never reaches gate 3. Read the message,
          not the status code.
        </p>
      </div>

      {/* gap-px over a --border ground is what draws the dividers between the
          gates, so a hairline lands in exactly the places a gap exists and
          nowhere else -- no special case at the first or last panel. */}
      <ol className="grid gap-px overflow-hidden rounded-b-lg bg-border md:grid-cols-3">
        {gates.map((g) => (
          <li key={g.key} className="flex flex-col gap-2.5 bg-card px-5 py-4">
            <div className="flex items-baseline gap-2.5">
              <span className="font-mono text-[13px] text-muted-foreground tabular-nums">
                {g.n}
              </span>
              <h3 className="text-[15px] leading-none font-semibold">
                {g.name}
              </h3>
            </div>
            <p className="text-[13px] leading-snug text-muted-foreground">
              {g.scope}
            </p>
            {/* The hanging indent lives on the inner span, never on the
                padded box -- see the note on .transcript-line. */}
            <p className="transcript rounded border border-term-border bg-term px-2.5 py-1.5 text-term-foreground">
              <span className="transcript-line">{g.signature}</span>
            </p>
            <p className="text-[13px] leading-relaxed text-muted-foreground">
              <Prose>{g.detail}</Prose>
            </p>
          </li>
        ))}
      </ol>
    </section>
  )
}
