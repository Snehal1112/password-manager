import styled from "styled-components"

/**
 * Reference pattern for styled-components in this project.
 *
 * Tailwind stays the default. Reach for a styled block only when a value is
 * continuous and only known at runtime, as the fill width is here. Tailwind
 * can emit a class only if it can see it at build time, so a width driven by
 * a number prop is one of the few things a utility class cannot express.
 */

type Tone = "positive" | "caution" | "critical"

/**
 * Tokens are read from the plain `:root` / `.dark` blocks in `src/index.css`.
 * Those are real CSS custom properties at runtime, so the `.dark` class on
 * `<html>` reassigns them and these styles follow dark mode on their own.
 * This is why there is no styled-components `ThemeProvider`.
 */
const TONE_TOKENS: Record<Tone, string> = {
  positive: "var(--primary)",
  caution: "var(--chart-2)",
  critical: "var(--destructive)",
}

/**
 * `$value` and `$tone` are transient props. The `$` prefix tells
 * styled-components to use them for styling and stop them there, so they are
 * never forwarded to the DOM as unknown HTML attributes.
 */
type MeterFillProps = {
  $value: number
  $tone: Tone
}

const MeterTrack = styled.div`
  /* Use --radius, from the plain :root block, rather than --radius-lg.
     Utilities substitute an @theme inline token by value, so such a token
     reaches the stylesheet only when something else names it explicitly.
     --radius-lg happens to be emitted today and --color-primary is not, and
     that can flip when unrelated markup changes. */
  border-radius: var(--radius);
  background-color: var(--muted);
  border: 1px solid var(--border);
  block-size: 0.5rem;
  inline-size: 100%;
  overflow: hidden;
`

const MeterFill = styled.div<MeterFillProps>`
  background-color: ${(props) => TONE_TOKENS[props.$tone]};
  inline-size: ${(props) => props.$value}%;
  block-size: 100%;
  transition: inline-size 200ms ease-out;
`

type StyledMeterProps = {
  /** Percentage to fill, clamped to 0-100. */
  value: number
  tone?: Tone
  label: string
}

/**
 * A labelled meter whose fill is driven by a runtime number.
 *
 * Everything static is a Tailwind class, as usual. Only the two values that
 * change with props live in the styled blocks.
 */
export function StyledMeter({
  value,
  tone = "positive",
  label,
}: StyledMeterProps) {
  const clamped = Math.min(100, Math.max(0, value))

  return (
    <div className="flex flex-col gap-1.5" data-slot="styled-meter">
      <div className="flex items-baseline justify-between text-sm">
        <span>{label}</span>
        <span className="font-mono text-xs text-muted-foreground">
          {clamped}%
        </span>
      </div>
      <MeterTrack
        role="progressbar"
        aria-label={label}
        aria-valuenow={clamped}
        aria-valuemin={0}
        aria-valuemax={100}
      >
        <MeterFill $value={clamped} $tone={tone} />
      </MeterTrack>
    </div>
  )
}
