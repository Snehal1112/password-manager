import { ACCESS_ITEMS } from "@/components/landing/content"

export function Access() {
  return (
    <section id="access" className="border-b border-border">
      <div className="mx-auto grid w-full max-w-6xl gap-12 px-6 py-20 lg:grid-cols-[minmax(0,0.75fr)_minmax(0,1.25fr)]">
        <div>
          <h2 className="max-w-[20ch] font-heading text-2xl font-semibold tracking-tight sm:text-3xl">
            Who can reach what
          </h2>
          <p className="mt-5 max-w-[48ch] text-sm leading-7 text-muted-foreground">
            Nothing is permitted until a role grants it. A principal — a user or
            a service account — reaches only what it has been given, in the one
            vault it was given it in.
          </p>
        </div>

        <dl className="grid gap-x-10 gap-y-8 sm:grid-cols-2">
          {ACCESS_ITEMS.map(({ icon: Icon, term, body }) => (
            <div key={term}>
              <dt className="flex items-center gap-2 font-heading text-sm font-semibold tracking-tight">
                <Icon
                  aria-hidden="true"
                  className="size-4 shrink-0 text-muted-foreground"
                  strokeWidth={1.75}
                />
                {term}
              </dt>
              <dd className="mt-2 text-sm leading-6 text-muted-foreground">
                {body}
              </dd>
            </div>
          ))}
        </dl>
      </div>
    </section>
  )
}
