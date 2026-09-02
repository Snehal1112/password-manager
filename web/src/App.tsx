import { Access } from "@/components/landing/access"
import { Boundaries } from "@/components/landing/boundaries"
import { Hero } from "@/components/landing/hero"
import { Operations } from "@/components/landing/operations"
import { Quickstart } from "@/components/landing/quickstart"
import { Resources } from "@/components/landing/resources"
import { Roles } from "@/components/landing/roles"
import { SiteFooter } from "@/components/landing/site-footer"
import { SiteNav } from "@/components/landing/site-nav"
import { Usage } from "@/components/landing/usage"
import { Why } from "@/components/landing/why"

export default function App() {
  return (
    <div className="min-h-svh bg-background">
      <SiteNav />
      <main>
        <Hero />
        <Why />
        <Resources />
        <Usage />
        <Access />
        <Roles />
        <Operations />
        <Boundaries />
        <Quickstart />
      </main>
      <SiteFooter />
    </div>
  )
}
