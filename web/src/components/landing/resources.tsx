import { RESOURCES } from "@/components/landing/content"

export function Resources() {
  return (
    <section id="resources" className="border-b border-border">
      <div className="mx-auto w-full max-w-6xl px-6 py-20">
        <h2 className="max-w-[24ch] font-heading text-2xl font-semibold tracking-tight sm:text-3xl">
          What a vault holds
        </h2>

        <div className="mt-12 grid border-t border-l border-border lg:grid-cols-3">
          {RESOURCES.map(({ icon: Icon, title, body, details }) => (
            <article
              key={title}
              className="flex flex-col border-r border-b border-border p-8"
            >
              <Icon
                aria-hidden="true"
                className="size-5 text-primary"
                strokeWidth={1.75}
              />
              <h3 className="mt-4 font-heading text-sm font-semibold tracking-tight">
                {title}
              </h3>
              <p className="mt-2 text-sm leading-6 text-muted-foreground">
                {body}
              </p>

              <ul className="mt-6 space-y-2 border-t border-border pt-5">
                {details.map((detail) => (
                  <li
                    key={detail}
                    className="flex gap-2.5 text-sm leading-6 text-muted-foreground"
                  >
                    <span
                      aria-hidden="true"
                      className="mt-2.5 size-1 shrink-0 rounded-full bg-primary"
                    />
                    {detail}
                  </li>
                ))}
              </ul>
            </article>
          ))}
        </div>
      </div>
    </section>
  )
}
