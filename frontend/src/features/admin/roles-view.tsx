"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Lock, Minus, Plus, Trash2 } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";
import { ErrorState, Guard } from "@/components/data/bits";
import { Container, PageHeader } from "@/components/layout/page";
import { Button } from "@/components/ui/button";
import { Checkbox, Field, Input, Textarea } from "@/components/ui/form-controls";
import { Chip, Panel, Skeleton } from "@/components/ui/misc";
import { ConfirmDialog, Sheet, SheetBody, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/overlays";
import { errorMessage } from "@/lib/api/client";
import { api } from "@/lib/api/endpoints";
import type { Permission, Role } from "@/lib/api/types";
import { PERMISSION_GROUPS } from "@/lib/permissions";
import { useCan } from "@/lib/session";
import { cn } from "@/lib/utils";

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
      toast.success(editing ? "Zapisano rolę" : "Utworzono rolę", { description: `${name}: ${perms.size} uprawnień` });
      onOpenChange(false);
    } catch (e) {
      toast.error("Nie udało się zapisać roli", { description: errorMessage(e) });
    }
  };
  return (
    <>
        <SheetHeader>
          <SheetTitle>{editing ? `Edytuj rolę: ${role.name}` : "Nowa rola"}</SheetTitle>
          <SheetDescription>Wybierz uprawnienia. API sprawdza je przy każdym żądaniu — interfejs tylko ukrywa i blokuje niedostępne działania.</SheetDescription>
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
          <div className="grid gap-4">
            {PERMISSION_GROUPS.map((g) => {
              const all = g.items.every((i) => perms.has(i.key));
              return (
                <fieldset key={g.resource} className="grid gap-2 rounded-xl border border-line p-3">
                  <legend className="flex items-center gap-2 px-1 text-sm font-bold">
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
                        <code className="mono ml-auto text-xs text-ink-3">{i.key}</code>
                      </label>
                    ))}
                  </div>
                </fieldset>
              );
            })}
          </div>
        </SheetBody>
        <SheetFooter>
          <span className="mr-auto text-sm text-ink-2">Wybrano {perms.size} uprawnień</span>
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

  return (
    <Container className="pb-12">
      <PageHeader
        title="Role i uprawnienia"
        description="Cztery role wbudowane odpowiadają wymaganiom: Administracja; Dodawanie, usuwanie, modyfikacja; Modyfikacja i odczyt; Odczyt. Możesz tworzyć role własne o dowolnym zestawie uprawnień."
        actions={
          <Guard permission="roles:manage">
            <Button variant="primary" onClick={() => setSheet({ role: null })}>
              <Plus /> Nowa rola
            </Button>
          </Guard>
        }
      />
      {roles.isError ? <ErrorState error={roles.error} onRetry={() => roles.refetch()} /> : null}
      <div className="mb-6 grid gap-4 md:grid-cols-2 xl:grid-cols-5">
        {list.map((r) => (
          <article key={r.id} className="grid content-start gap-2 rounded-xl border border-line bg-surface p-4">
            <div className="flex items-start justify-between gap-2">
              <h3 className="font-bold">{r.name}</h3>
              {r.builtin ? <Lock className="size-4 text-ink-3" aria-label="rola wbudowana" /> : <Chip tone="accent">własna</Chip>}
            </div>
            <p className="text-sm leading-snug text-ink-2">{r.description}</p>
            <p className="text-xs text-ink-2">
              {r.permissions.length} uprawnień, {r.users_count} {r.users_count === 1 ? "użytkownik" : "użytkowników"}
            </p>
            {can("roles:manage") ? (
              <div className="mt-1 flex gap-1">
                <Button size="sm" variant="ghost" onClick={() => setSheet({ role: r })}>
                  {r.builtin ? "Utwórz kopię" : "Edytuj"}
                </Button>
                {!r.builtin ? (
                  <Button size="icon-sm" variant="ghost" aria-label={`Usuń rolę ${r.name}`} onClick={() => setToDelete(r)}>
                    <Trash2 />
                  </Button>
                ) : null}
              </div>
            ) : null}
          </article>
        ))}
        {!roles.data ? [0, 1, 2, 3, 4].map((i) => <Skeleton key={i} className="h-40 rounded-xl" />) : null}
      </div>
      <Panel title="Macierz uprawnień" description="Kto co może. Te same reguły egzekwuje API (odpowiedź 403 z nazwą brakującego uprawnienia)." flush>
        <div className="scroll-quiet relative overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-line bg-surface-2 text-left text-sm text-ink-2">
                <th scope="col" className="px-4 py-2.5 font-semibold">Uprawnienie</th>
                {list.map((r) => (
                  <th key={r.id} scope="col" className="px-3 py-2.5 text-center font-semibold whitespace-nowrap">
                    {r.name}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {PERMISSION_GROUPS.map((g) => (
                <React.Fragment key={g.resource}>
                  <tr className="border-b border-line bg-surface-2/60">
                    <th colSpan={list.length + 1} scope="colgroup" className="px-4 py-2 text-left text-xs font-bold tracking-wide text-ink-2">
                      {g.label}
                    </th>
                  </tr>
                  {g.items.map((i) => (
                    <tr key={i.key} className="border-b border-line last:border-0">
                      <th scope="row" className="px-4 py-2 text-left font-normal">
                        {i.label} <code className="mono ml-1 text-xs text-ink-3">{i.key}</code>
                      </th>
                      {list.map((r) => {
                        const has = r.permissions.includes(i.key);
                        return (
                          <td key={r.id} className="px-3 py-2 text-center">
                            {has ? (
                              <Check className={cn("mx-auto size-4 text-success")} strokeWidth={3} aria-label="tak" />
                            ) : (
                              <Minus className="mx-auto size-4 text-ink-3" aria-label="nie" />
                            )}
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
