import { BrandIcon } from "@/components/landing/brand"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader } from "@/components/ui/card"
import { cn } from "@/lib/utils"
import { DOCS_URL, HERO_SESSION, REPO_URL } from "@/components/landing/content"

function Terminal() {
  return (
    <Card className="gap-0 overflow-hidden py-0">
      <CardHeader className="flex items-center justify-between border-b border-border px-4 py-2.5">
        <span className="font-heading text-xs text-muted-foreground">
          payments
        </span>
        <BrandIcon className="size-4" />
      </CardHeader>

      <CardContent className="overflow-x-auto p-4">
        <pre className="font-heading text-xs leading-6 text-foreground">
          <code>
            {HERO_SESSION.map((line, index) => (
              <div
                // A fixed, ordered transcript, so the index is stable.
                key={line.text}
                className="terminal-line"
                style={{ animationDelay: `${index * 90}ms` }}
              >
                {line.prompt ? (
                  <span className="mr-2 text-primary select-none">$</span>
                ) : null}
                <span className={cn(line.muted && "text-muted-foreground")}>
                  {line.text}
                </span>
              </div>
            ))}
          </code>
        </pre>
      </CardContent>
    </Card>
  )
}

export function Hero() {
  return (
    <section id="top" className="border-b border-border">
      <div className="mx-auto grid w-full max-w-6xl gap-12 px-6 py-20 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)] lg:items-center lg:py-28">
        <div>
          <h1 className="font-heading text-4xl leading-[1.1] font-semibold tracking-tight text-balance sm:text-5xl">
            Key management that stays on your own infrastructure
          </h1>

          <p className="mt-6 max-w-[58ch] text-base leading-7 text-muted-foreground">
            RocketVault is a self-hosted alternative to Azure Key Vault, written
            in Go. It holds secrets, cryptographic keys, and X.509 certificates,
            and hands them out only to callers you have granted a role.
          </p>

          <div className="mt-8 flex flex-wrap items-center gap-3">
            <Button render={<a href={REPO_URL} />} size="lg">
              Get the source
            </Button>
            <Button render={<a href={DOCS_URL} />} variant="outline" size="lg">
              Read the manual
            </Button>
          </div>

          <p className="mt-6 font-heading text-xs text-muted-foreground">
            MIT licensed. No cloud account, no subscription.
          </p>
        </div>

        <Terminal />
      </div>
    </section>
  )
}
