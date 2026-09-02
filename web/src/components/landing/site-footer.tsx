import { BrandLockup, GitHubMark } from "@/components/landing/brand"
import { Kbd } from "@/components/ui/kbd"
import { Separator } from "@/components/ui/separator"
import { API_DOCS_URL, DOCS_URL, REPO_URL } from "@/components/landing/content"

const LINKS = [
  { href: REPO_URL, label: "Source", mark: true },
  { href: DOCS_URL, label: "Administrator manual" },
  { href: API_DOCS_URL, label: "API guide" },
  { href: `${REPO_URL}/issues`, label: "Issues" },
]

export function SiteFooter() {
  return (
    <footer>
      <div className="mx-auto flex w-full max-w-6xl flex-col gap-4 px-6 py-10 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-4">
          <BrandLockup />
          <Separator orientation="vertical" className="hidden h-4 sm:block" />
          <span className="hidden items-center gap-1.5 text-xs text-muted-foreground sm:flex">
            Press <Kbd>d</Kbd> for dark mode
          </span>
        </div>

        <ul className="flex flex-wrap items-center gap-x-6 gap-y-2">
          {LINKS.map((link) => (
            <li key={link.label}>
              <a
                href={link.href}
                className="flex items-center gap-1.5 text-xs text-muted-foreground transition-colors hover:text-foreground"
              >
                {"mark" in link ? <GitHubMark className="size-3.5" /> : null}
                {link.label}
              </a>
            </li>
          ))}
        </ul>
      </div>
    </footer>
  )
}
