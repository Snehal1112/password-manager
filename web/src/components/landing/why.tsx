import { REASONS, REQUEST_FLOW } from "@/components/landing/content"

function Flow() {
  return (
    <ol className="flex flex-wrap items-center gap-x-2 gap-y-2">
      {REQUEST_FLOW.map((step, index) => (
        <li key={step} className="flex items-center gap-2">
          <span className="rounded-md border border-border px-2.5 py-1 font-heading text-xs text-muted-foreground">
            {step}
          </span>
          {index < REQUEST_FLOW.length - 1 ? (
            <span aria-hidden="true" className="text-muted-foreground/50">
              /
            </span>
          ) : null}
        </li>
      ))}
    </ol>
  )
}

export function Why() {
  return (
    <section id="why" className="border-b border-border">
      <div className="mx-auto w-full max-w-6xl px-6 py-20">
        <div className="grid gap-12 lg:grid-cols-[minmax(0,0.75fr)_minmax(0,1.25fr)]">
          <div>
            <h2 className="max-w-[20ch] font-heading text-2xl font-semibold tracking-tight sm:text-3xl">
              The same model, on infrastructure you control
            </h2>
            <p className="mt-5 max-w-[48ch] text-sm leading-7 text-muted-foreground">
              RocketVault follows Azure Key Vault's model closely enough that
              the concepts carry over, but nothing leaves your network and there
              is no subscription in the path.
            </p>
          </div>

          <dl className="grid gap-x-10 gap-y-8 sm:grid-cols-2">
            {REASONS.map(({ term, body }) => (
              <div key={term}>
                <dt className="font-heading text-sm font-semibold tracking-tight">
                  {term}
                </dt>
                <dd className="mt-2 text-sm leading-6 text-muted-foreground">
                  {body}
                </dd>
              </div>
            ))}
          </dl>
        </div>

        <div className="mt-16 border-t border-border pt-10">
          <p className="text-sm leading-6 text-muted-foreground">
            A request passes through authentication and authorization before it
            reaches a handler. Secrets, keys, and certificates are encrypted at
            rest with AES-256-GCM.
          </p>
          <div className="mt-5">
            <Flow />
          </div>
        </div>
      </div>
    </section>
  )
}
