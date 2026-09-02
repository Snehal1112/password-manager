import {
  Item,
  ItemContent,
  ItemDescription,
  ItemGroup,
  ItemMedia,
  ItemSeparator,
  ItemTitle,
} from "@/components/ui/item"
import { OPERATIONS } from "@/components/landing/content"

export function Operations() {
  return (
    <section id="operations" className="border-b border-border">
      <div className="mx-auto w-full max-w-6xl px-6 py-20">
        <h2 className="max-w-[26ch] font-heading text-2xl font-semibold tracking-tight sm:text-3xl">
          What running it takes
        </h2>

        <ItemGroup className="mt-12 border-y border-border">
          {OPERATIONS.map(({ icon: Icon, term, body }, index) => (
            <div key={term}>
              {index > 0 ? <ItemSeparator /> : null}
              <Item className="px-0">
                <ItemMedia>
                  <Icon
                    aria-hidden="true"
                    className="size-4 text-muted-foreground"
                    strokeWidth={1.75}
                  />
                </ItemMedia>
                <ItemContent>
                  <ItemTitle className="font-heading tracking-tight">
                    {term}
                  </ItemTitle>
                  <ItemDescription className="max-w-[76ch]">
                    {body}
                  </ItemDescription>
                </ItemContent>
              </Item>
            </div>
          ))}
        </ItemGroup>
      </div>
    </section>
  )
}
