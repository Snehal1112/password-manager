import { Card, CardContent } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import {
  CLI_SAMPLE,
  GO_SAMPLE,
  INTEGRATIONS,
  REST_SAMPLE,
} from "@/components/landing/content"

function Sample({ code }: { code: string }) {
  return (
    <Card className="py-0">
      <CardContent className="overflow-x-auto p-5">
        <pre className="font-heading text-xs leading-6">
          <code>{code}</code>
        </pre>
      </CardContent>
    </Card>
  )
}

export function Usage() {
  return (
    <section id="usage" className="border-b border-border">
      <div className="mx-auto w-full max-w-6xl px-6 py-20">
        <div className="grid gap-10 lg:grid-cols-[minmax(0,0.8fr)_minmax(0,1.2fr)]">
          <div>
            <h2 className="max-w-[22ch] font-heading text-2xl font-semibold tracking-tight sm:text-3xl">
              Three ways in, one authorization model
            </h2>
            <p className="mt-5 max-w-[52ch] text-sm leading-7 text-muted-foreground">
              The CLI, the REST API, and the Go client run the same
              authorization checks, so a grant behaves identically whichever one
              you reach for. Sessions are cached after you sign in and refreshed
              in the background.
            </p>
          </div>

          <Tabs defaultValue="cli" className="min-w-0">
            <TabsList variant="line">
              <TabsTrigger value="cli">CLI</TabsTrigger>
              <TabsTrigger value="rest">REST</TabsTrigger>
              <TabsTrigger value="go">Go</TabsTrigger>
            </TabsList>

            <TabsContent value="cli" className="mt-5">
              <Sample code={CLI_SAMPLE} />
            </TabsContent>
            <TabsContent value="rest" className="mt-5">
              <Sample code={REST_SAMPLE} />
            </TabsContent>
            <TabsContent value="go" className="mt-5">
              <Sample code={GO_SAMPLE} />
            </TabsContent>
          </Tabs>
        </div>

        <dl className="mt-16 grid gap-x-10 gap-y-8 border-t border-border pt-10 sm:grid-cols-2 lg:grid-cols-3">
          {INTEGRATIONS.map(({ icon: Icon, term, body }) => (
            <div key={term}>
              <dt className="flex items-center gap-2 font-heading text-sm font-semibold tracking-tight">
                <Icon
                  aria-hidden="true"
                  className="size-4 shrink-0 text-muted-foreground"
                  strokeWidth={1.75}
                />
                {term}
              </dt>
              <dd className="mt-1.5 text-sm leading-6 text-muted-foreground">
                {body}
              </dd>
            </div>
          ))}
        </dl>
      </div>
    </section>
  )
}
