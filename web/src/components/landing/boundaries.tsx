import { BOUNDARIES } from "@/components/landing/content"

export function Boundaries() {
  return (
    <section id="boundaries" className="border-b border-border">
      <div className="mx-auto grid w-full max-w-6xl gap-12 px-6 py-20 lg:grid-cols-[minmax(0,0.75fr)_minmax(0,1.25fr)]">
        <div>
          <h2 className="max-w-[20ch] font-heading text-2xl font-semibold tracking-tight sm:text-3xl">
            What it does not do
          </h2>
          <p className="mt-5 max-w-[48ch] text-sm leading-7 text-muted-foreground">
            Some of these follow from running one binary on your own
            infrastructure. Others are not built yet.
          </p>
        </div>

        <ul className="space-y-5">
          {BOUNDARIES.map((item) => (
            <li
              key={item}
              className="max-w-[76ch] border-l-2 border-border pl-5 text-sm leading-6 text-muted-foreground"
            >
              {item}
            </li>
          ))}
        </ul>
      </div>
    </section>
  )
}
