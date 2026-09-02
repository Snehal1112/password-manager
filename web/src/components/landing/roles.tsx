import { Badge } from "@/components/ui/badge"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import {
  ACCOUNT_ROLE_COLUMNS,
  ACCOUNT_ROLES,
  VAULT_ROLES,
} from "@/components/landing/content"

export function Roles() {
  return (
    <section id="roles" className="border-b border-border">
      <div className="mx-auto grid w-full max-w-6xl gap-12 px-6 py-20 lg:grid-cols-2 lg:gap-16">
        <div>
          <h2 className="max-w-[22ch] font-heading text-2xl font-semibold tracking-tight sm:text-3xl">
            Azure's role names, granted per vault
          </h2>
          <p className="mt-5 max-w-[50ch] text-sm leading-7 text-muted-foreground">
            Grant any of these to a principal in a single vault. The names and
            their meanings follow Azure Key Vault, so a role you have used there
            behaves the same here.
          </p>

          <ul className="mt-8 flex flex-wrap gap-2">
            {VAULT_ROLES.map((role) => (
              <li key={role}>
                <Badge variant="outline" className="font-heading">
                  {role.replace("Key Vault ", "")}
                </Badge>
              </li>
            ))}
          </ul>
        </div>

        <div>
          <h3 className="font-heading text-sm font-semibold tracking-tight">
            Account roles
          </h3>
          <p className="mt-2 max-w-[52ch] text-sm leading-6 text-muted-foreground">
            Separate from vault roles, these govern the instance. Full means
            create, read, update, delete and list.
          </p>

          <div className="mt-6 overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="font-heading">Role</TableHead>
                  {ACCOUNT_ROLE_COLUMNS.map((column) => (
                    <TableHead key={column} className="font-heading">
                      {column}
                    </TableHead>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                {ACCOUNT_ROLES.map(({ role, cells }) => (
                  <TableRow key={role}>
                    <TableCell className="font-heading text-foreground">
                      {role}
                    </TableCell>
                    {cells.map((cell, index) => (
                      <TableCell
                        key={ACCOUNT_ROLE_COLUMNS[index]}
                        className={
                          cell === "—" ? "text-muted-foreground/50" : undefined
                        }
                      >
                        {cell}
                      </TableCell>
                    ))}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </div>
      </div>
    </section>
  )
}
