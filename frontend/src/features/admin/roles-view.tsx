"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Minus, Plus, Trash2 } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";
import { ErrorState, Guard } from "@/components/data/bits";
import { DataTable, type Column } from "@/components/data/data-table";
import { Container, PageHeader } from "@/components/layout/page";
import { Button } from "@/components/ui/button";
import { Checkbox, Field, Input, Textarea } from "@/components/ui/form-controls";
import { Panel } from "@/components/ui/misc";
import { ConfirmDialog, Sheet, SheetBody, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/overlays";
import { errorMessage } from "@/lib/api/client";
import { api } from "@/lib/api/endpoints";
import type { Permission, Role } from "@/lib/api/types";
import { countLabel } from "@/lib/format";
import { PERMISSION_GROUPS } from "@/lib/permissions";
import { useCan } from "@/lib/session";

function RoleSheet({ role, open, onOpenChange }: { role: Role | null; open: boolean; onOpenChange: (o: boolean) => void }) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent width="lg">
        <RoleForm role={role} onOpenChange={onOpenChange} />
      </SheetContent>
    </Sheet>
  );
}

function RoleForm({ role, onOpenChange }: { role: Role | null; onOpenChange: (o: boolean) => void }) {
  const qc = useQueryClient();
  const [name, setName] = React.useState(role ? (role.builtin ? `${role.name} (kopia)` : role.name) : "");
  const [description, setDescription] = React.useState(role?.description ?? "");
  const [perms, setPerms] = React.useState<Set<Permission>>(() => new Set(role?.permissions ?? ["dashboard:read"]));
  const editing = role && !role.builtin;
  const toggle = (p: Permission) =>
    setPerms((prev) => {
      const next = new Set(prev);
      if (next.has(p)) next.delete(p);
      else next.add(p);
      return next;
    });
  const save = async () => {
    try {
      if (editing) await api.roles.update(role.id, { name, description, permissions: [...perms] });
      else await api.roles.create({ name, description, permissions: [...perms] });
      qc.invalidateQueries({ queryKey: ["roles"] });
      toast.success(editing ? "Zapisano rolę" : "Utworzono rolę", { description: `${name}: ${countLabel(perms.size, ["uprawnienie", "uprawnienia", "uprawnień"])}` });
      onOpenChange(false);
    } catch (e) {
      toast.error("Nie udało się zapisać roli", { description: errorMessage(e) });
    }
  };
  return (
    <>
        <SheetHeader>
          <SheetTitle>{editing ? `Edytuj rolę: ${role.name}` : "Nowa rola"}</SheetTitle>
          <SheetDescription>API sprawdza uprawnienia przy każdym żądaniu; interfejs tylko ukrywa i blokuje niedostępne działania.</SheetDescription>
        </SheetHeader>
        <SheetBody className="grid content-start gap-5">
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Nazwa roli" htmlFor="role-name">
              <Input id="role-name" value={name} onChange={(e) => setName(e.target.value)} />
            </Field>
            <Field label="Opis" htmlFor="role-desc">
              <Textarea id="role-desc" value={description} onChange={(e) => setDescription(e.target.value)} className="min-h-9" />
            </Field>
          </div>
          {/* Permission groups as sections under hairlines, not boxed fieldsets. */}
          <div className="grid">
            {PERMISSION_GROUPS.map((g) => {
              const all = g.items.every((i) => perms.has(i.key));
              return (
                <div key={g.resource} className="border-t border-line py-4">
                  <fieldset className="grid gap-2">
                    <legend className="mb-2 flex items-center gap-3 text-sm font-semibold">
                      {g.label}
                      <button
                        type="button"
                        className="text-xs font-semibold text-link hover:underline"
                        onClick={() =>
                          setPerms((prev) => {
                            const next = new Set(prev);
                            g.items.forEach((i) => (all ? next.delete(i.key) : next.add(i.key)));
                            return next;
                          })
                        }
                      >
                        {all ? "odznacz" : "zaznacz wszystkie"}
                      </button>
                    </legend>
                    <div className="grid gap-2 sm:grid-cols-2">
                      {g.items.map((i) => (
                        <label key={i.key} className="flex items-center gap-2 text-sm">
                          <Checkbox checked={perms.has(i.key)} onCheckedChange={() => toggle(i.key)} />
                          {i.label}
                          <code className="mono ml-auto text-xs text-ink-2">{i.key}</code>
                        </label>
                      ))}
                    </div>
                  </fieldset>
                </div>
              );
            })}
          </div>
        </SheetBody>
        <SheetFooter>
          <span className="mr-auto text-sm text-ink-2">Wybrano {countLabel(perms.size, ["uprawnienie", "uprawnienia", "uprawnień"])}</span>
          <Button variant="secondary" onClick={() => onOpenChange(false)}>
            Anuluj
          </Button>
          <Button variant="primary" onClick={save} disabled={!name.trim() || perms.size === 0}>
            {editing ? "Zapisz rolę" : "Utwórz rolę"}
          </Button>
        </SheetFooter>
    </>
  );
}

export function RolesView() {
  const qc = useQueryClient();
  const can = useCan();
  const roles = useQuery({ queryKey: ["roles"], queryFn: api.roles.list });
  const [sheet, setSheet] = React.useState<{ role: Role | null } | null>(null);
  const [toDelete, setToDelete] = React.useState<Role | null>(null);
  const list = roles.data ?? [];

  const roleColumns: Column<Role>[] = [
    {
      key: "name",
      header: "Rola",
      cell: (r) => (
        <div className="grid gap-0.5">
          <span className="font-semibold">{r.name}</span>
          <span className="text-xs text-ink-2">
            {r.builtin ? "wbudowana" : "własna"}
            {/* Phones: the two counts move here instead of taking two columns. */}
            <span className="sm:hidden">
              , {countLabel(r.permissions.length, ["uprawnienie", "uprawnienia", "uprawnień"])}, {countLabel(r.users_count, ["użytkownik", "użytkownicy", "użytkowników"])}
            </span>
          </span>
        </div>
      ),
    },
    { key: "desc", header: "Opis", hideBelow: "md", cell: (r) => <span className="block max-w-2xl text-sm text-pretty text-ink-2">{r.description}</span> },
    { key: "perms", header: "Uprawnienia", hideBelow: "sm", className: "tabular text-right", headerClassName: "text-right", cell: (r) => r.permissions.length },
    { key: "users", header: "Użytkownicy", hideBelow: "sm", className: "tabular text-right", headerClassName: "text-right", cell: (r) => r.users_count },
    {
      key: "actions",
      header: <span className="sr-only">Akcje</span>,
      cell: (r) =>
        can("roles:manage") ? (
          <div className="flex flex-wrap justify-end gap-1">
            <Button size="sm" variant="ghost" onClick={() => setSheet({ role: r })}>
              {r.builtin ? "Utwórz kopię" : "Edytuj"}
            </Button>
            {!r.builtin ? (
              <Button size="icon-sm" variant="ghost" aria-label={`Usuń rolę ${r.name}`} onClick={() => setToDelete(r)}>
                <Trash2 />
              </Button>
            ) : null}
          </div>
        ) : null,
    },
  ];

  return (
    <Container className="pb-12">
      <PageHeader
        title="Role i uprawnienia"
        description="Role wbudowane można tylko skopiować; role własne edytujesz dowolnie."
        actions={
          <Guard permission="roles:manage">
            <Button variant="primary" onClick={() => setSheet({ role: null })}>
              <Plus /> Nowa rola
            </Button>
          </Guard>
        }
      />
      {roles.isError ? <ErrorState error={roles.error} onRetry={() => roles.refetch()} /> : null}
      {/* Roles are records, so they are a table above the matrix, not a row of identical cards. */}
      <Panel title="Role" flush className="mb-6">
        <DataTable columns={roleColumns} rows={roles.data} getId={(r) => r.id} loading={roles.isFetching && !roles.data} skeletonRows={5} caption="Role" />
      </Panel>
      <Panel title="Macierz uprawnień" description="API egzekwuje te same reguły (403 z nazwą brakującego uprawnienia)." flush>
        <div className="scroll-quiet relative overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-line bg-surface-2 text-left text-xs text-ink-2">
                <th scope="col" className="sticky left-0 z-10 bg-surface-2 py-2.5 pr-4 pl-5 font-semibold max-md:shadow-[1px_0_0_var(--line)]">
                  Uprawnienie
                </th>
                {list.map((r) => (
                  <th key={r.id} scope="col" className="px-3 py-2.5 text-center font-semibold whitespace-nowrap last:pr-5">
                    {r.name}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {PERMISSION_GROUPS.map((g) => (
                <React.Fragment key={g.resource}>
                  <tr className="border-b border-line bg-surface-2/60">
                    <th colSpan={list.length + 1} scope="colgroup" className="py-2 pr-4 pl-5 text-left text-xs font-semibold text-ink-2">
                      {g.label}
                    </th>
                  </tr>
                  {g.items.map((i) => (
                    <tr key={i.key} className="border-b border-line last:border-0">
                      {/* The permission name stays pinned while a narrow screen scrolls through the role columns. */}
                      <th scope="row" className="sticky left-0 z-10 bg-surface py-2 pr-4 pl-5 text-left font-normal max-md:min-w-44 max-md:shadow-[1px_0_0_var(--line)]">
                        {i.label} <code className="mono ml-1 text-xs text-ink-2 max-md:block max-md:ml-0">{i.key}</code>
                      </th>
                      {list.map((r) => {
                        const has = r.permissions.includes(i.key);
                        return (
                          <td key={r.id} className="px-3 py-2 text-center last:pr-5">
                            {has ? <Check className="mx-auto size-4 text-ink" strokeWidth={3} aria-label="tak" /> : <Minus className="mx-auto size-4 text-ink-3" aria-label="nie" />}
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
      <RoleSheet role={sheet?.role ?? null} open={Boolean(sheet)} onOpenChange={(o) => !o && setSheet(null)} />
      <ConfirmDialog
        open={Boolean(toDelete)}
        onOpenChange={(o) => !o && setToDelete(null)}
        title={`Usunąć rolę ${toDelete?.name}?`}
        description="Rolę można usunąć tylko wtedy, gdy nie jest przypisana do żadnego użytkownika. Tej operacji nie można cofnąć."
        confirmLabel="Usuń rolę"
        onConfirm={async () => {
          try {
            await api.roles.remove(toDelete!.id);
            qc.invalidateQueries({ queryKey: ["roles"] });
            toast.success("Usunięto rolę");
          } catch (e) {
            toast.error("Nie udało się usunąć roli", { description: errorMessage(e) });
          }
          setToDelete(null);
        }}
      />
    </Container>
  );
}
