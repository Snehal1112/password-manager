import type * as React from "react"

/**
 * The RocketVault mark, transcribed from ../../web/public/rocketvault-icon.svg.
 *
 * It is inlined rather than imported as a file for the same reason the fonts
 * are: this page ships as one HTML file opened from disk, so a `<img src>`
 * pointing at a sibling asset would resolve to nothing once the file is
 * emailed on. Keep it byte-equivalent to the source SVG -- if the mark is
 * redrawn in web/public/, redraw it here too.
 *
 * The colours are the brand's own hex values, not theme tokens. A logo does
 * not restate itself per theme, and the teal-on-deep-teal pair carries on
 * both the paper and the dark ground.
 */
export function BrandMark({
  className,
  ...props
}: React.ComponentProps<"svg">) {
  return (
    <svg
      viewBox="0 0 64 64"
      className={className}
      role="img"
      aria-label="RocketVault"
      {...props}
    >
      <rect x="4" y="4" width="56" height="56" rx="14" fill="#0FA89A" />
      <rect x="9" y="9" width="46" height="46" rx="10" fill="#0A6B62" />
      <circle
        cx="32"
        cy="32"
        r="11"
        fill="none"
        stroke="#FFFFFF"
        strokeWidth="2.4"
      />
      <path
        d="M32 32V21"
        stroke="#FFFFFF"
        strokeWidth="2.4"
        strokeLinecap="round"
      />
      <circle cx="32" cy="32" r="2.1" fill="#FFFFFF" />
    </svg>
  )
}
