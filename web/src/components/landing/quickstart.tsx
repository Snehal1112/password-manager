import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { DOCS_URL, QUICKSTART, REPO_URL } from "@/components/landing/content"

export function Quickstart() {
  return (
    <section id="start" className="border-b border-border">
      <div className="mx-auto w-full max-w-6xl px-6 py-20">
        <h2 className="max-w-[24ch] font-heading text-2xl font-semibold tracking-tight sm:text-3xl">
          Running in five steps
        </h2>
        <p className="mt-5 max-w-[60ch] text-sm leading-7 text-muted-foreground">
          The server listens on port 8774 and reads a single config file.
        </p>

        <ol className="mt-12 space-y-px">
          {QUICKSTART.map((step, index) => (
            <li
              key={step.title}
              className="grid gap-4 border-t border-border py-6 last:border-b sm:grid-cols-[minmax(0,18rem)_minmax(0,1fr)] sm:gap-10"
            >
              <div className="flex gap-3">
                <span
                  aria-hidden="true"
                  className="font-heading text-xs text-muted-foreground/70 tabular-nums"
                >
                  {String(index + 1).padStart(2, "0")}
                </span>
                <div>
                  <h3 className="font-heading text-sm font-semibold tracking-tight">
                    {step.title}
                  </h3>
                  <p className="mt-1.5 text-sm leading-6 text-muted-foreground">
                    {step.body}
                  </p>
                </div>
              </div>

              <Card className="min-w-0 py-0">
                <CardContent className="overflow-x-auto p-4">
                  <pre className="font-heading text-xs leading-6">
                    <code>{step.code}</code>
                  </pre>
                </CardContent>
              </Card>
            </li>
          ))}
        </ol>

        <div className="mt-12 flex flex-wrap items-center gap-3">
          <Button render={<a href={REPO_URL} />} size="lg">
            Get the source
          </Button>
          <Button render={<a href={DOCS_URL} />} variant="outline" size="lg">
            Read the manual
          </Button>
        </div>
      </div>
    </section>
  )
}
