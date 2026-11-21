"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2 } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";
import { ErrorState, Guard } from "@/components/data/bits";
import { DataTable, type Column } from "@/components/data/data-table";
import { Container, PageHeader } from "@/components/layout/page";
import { Button } from "@/components/ui/button";
import { Field, Input, Switch } from "@/components/ui/form-controls";
import { Panel } from "@/components/ui/misc";
import { ConfirmDialog, Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/overlays";
import { SimpleSelect } from "@/components/ui/select";
import { ApiError, errorMessage } from "@/lib/api/client";
import { api } from "@/lib/api/endpoints";
import type { User } from "@/lib/api/types";
import { fmtRelative } from "@/lib/format";
import { useCan, useSession } from "@/lib/session";

function NewUserDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <NewUserForm onOpenChange={onOpenChange} />
      </DialogContent>
    </Dialog>
  );
}

function NewUserForm({ onOpenChange }: { onOpenChange: (o: boolean) => void }) {
  const qc = useQueryClient();
  const roles = useQuery({ queryKey: ["roles"], queryFn: api.roles.list });
  const [form, setForm] = React.useState({ login: "", name: "", email: "", role_id: "r-4", password: "" });
  const [errors, setErrors] = React.useState<Record<string, string>>({});
  const submit = async () => {
    try {
      await api.users.create(form);
      qc.invalidateQueries({ queryKey: ["users"] });
      qc.invalidateQueries({ queryKey: ["roles"] });
      toast.success(`Utworzono konto ${form.login}`);
      onOpenChange(false);
    } catch (e) {
      if (e instanceof ApiError && e.fields) setErrors(e.fields);
      else toast.error("Nie udało się utworzyć konta", { description: errorMessage(e) });
    }
  };
  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) => setForm({ ...form, [k]: e.target.value });
  return (
    <>
        <DialogHeader>
          <DialogTitle>Nowy użytkownik</DialogTitle>
          <DialogDescription>Konto lokalne. Hasło musi mieć co najmniej 12 znaków; użytkownik zmieni je przy pierwszym logowaniu.</DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Imię i nazwisko" htmlFor="u-name" error={errors.name}>
            <Input id="u-name" value={form.name} onChange={set("name")} aria-invalid={Boolean(errors.name)} />
          </Field>
          <Field label="Login" htmlFor="u-login" error={errors.login}>
            <Input id="u-login" value={form.login} onChange={set("login")} aria-invalid={Boolean(errors.login)} placeholder="jan.nowak" />
          </Field>
          <Field label="E-mail" htmlFor="u-email" error={errors.email}>
            <Input id="u-email" type="email" value={form.email} onChange={set("email")} aria-invalid={Boolean(errors.email)} />
          </Field>
          <Field label="Rola" error={errors.role_id}>
            <SimpleSelect aria-label="Rola" value={form.role_id} onChange={(v) => setForm({ ...form, role_id: v || "r-4" })} options={(roles.data ?? []).map((r) => ({ value: r.id, label: r.name }))} />
          </Field>
          <Field label="Hasło tymczasowe" htmlFor="u-pass" error={errors.password} className="sm:col-span-2">
            <Input id="u-pass" type="password" autoComplete="new-password" value={form.password} onChange={set("password")} aria-invalid={Boolean(errors.password)} />
          </Field>
        </div>
        <DialogFooter>
          <Button variant="secondary" onClick={() => onOpenChange(false)}>
            Anuluj
          </Button>
          <Button variant="primary" onClick={submit}>
            Utwórz konto
          </Button>
        </DialogFooter>
    </>
  );
}

export function UsersView() {
  const qc = useQueryClient();
  const can = useCan();
  const session = useSession();
  const users = useQuery({ queryKey: ["users"], queryFn: api.users.list });
  const roles = useQuery({ queryKey: ["roles"], queryFn: api.roles.list });
  const [newOpen, setNewOpen] = React.useState(false);
  const [toDelete, setToDelete] = React.useState<User | null>(null);

  const update = async (u: User, body: Partial<Pick<User, "role_id" | "active">>, label: string) => {
    try {
      await api.users.update(u.id, body);
      qc.invalidateQueries({ queryKey: ["users"] });
      qc.invalidateQueries({ queryKey: ["roles"] });
      toast.success(label, { description: u.name });
    } catch (e) {
      toast.error("Nie udało się zapisać", { description: errorMessage(e) });
    }
  };

  const columns: Column<User>[] = [
    {
      key: "name",
      header: "Użytkownik",
      cell: (u) => (
        <div className="grid gap-0.5">
          <span className="font-semibold">
            {u.name} {u.id === session.user.id ? <span className="font-normal text-ink-2">(Ty)</span> : null}
            {!u.active ? <span className="font-normal text-ink-2"> (konto zablokowane)</span> : null}
          </span>
          <span className="text-xs text-ink-2 [overflow-wrap:anywhere]">
            {u.login}, {u.email}
          </span>
          <span className="text-xs text-ink-2 sm:hidden">Rola: {u.role_name}</span>
        </div>
      ),
    },
    {
      key: "role",
      header: "Rola",
      hideBelow: "sm",
      cell: (u) =>
        can("users:manage") && u.id !== session.user.id ? (
          <SimpleSelect
            quiet
            aria-label={`Rola: ${u.name}`}
            className="h-8 w-48 text-sm"
            value={u.role_id}
            onChange={(v) => v && v !== u.role_id && update(u, { role_id: v }, `Zmieniono rolę na ${roles.data?.find((r) => r.id === v)?.name}`)}
            options={(roles.data ?? []).map((r) => ({ value: r.id, label: r.name }))}
          />
        ) : (
          <span className="text-sm">{u.role_name}</span>
        ),
    },
    { key: "login", header: "Ostatnie logowanie", hideBelow: "lg", cell: (u) => <span className="text-sm whitespace-nowrap text-ink-2">{u.last_login_at ? fmtRelative(u.last_login_at) : "nigdy"}</span> },
    {
      key: "active",
      header: "Konto aktywne",
      hideBelow: "sm",
      cell: (u) => (
        <Switch
          aria-label={`Konto aktywne: ${u.name}`}
          checked={u.active}
          disabled={!can("users:manage") || u.id === session.user.id}
          onCheckedChange={(c) => update(u, { active: c }, c ? "Odblokowano konto" : "Zablokowano konto")}
        />
      ),
    },
    {
      key: "actions",
      header: <span className="sr-only">Akcje</span>,
      cell: (u) =>
        u.id !== session.user.id ? (
          <div className="flex justify-end">
            <Guard permission="users:manage">
              <Button size="icon-sm" variant="ghost" aria-label={`Usuń konto ${u.name}`} onClick={() => setToDelete(u)}>
                <Trash2 />
              </Button>
            </Guard>
          </div>
        ) : null,
    },
  ];

  return (
    <Container className="pb-12">
      <PageHeader
        title="Użytkownicy"
        description="Zmiana roli działa od następnego żądania użytkownika."
        actions={
          <Guard permission="users:manage">
            <Button variant="primary" onClick={() => setNewOpen(true)}>
              <Plus /> Nowy użytkownik
            </Button>
          </Guard>
        }
      />
      <Panel flush>
        {users.isError ? <ErrorState className="m-4" error={users.error} onRetry={() => users.refetch()} /> : null}
        <DataTable columns={columns} rows={users.data} getId={(u) => u.id} loading={users.isFetching && !users.data} caption="Użytkownicy" />
      </Panel>
      <NewUserDialog open={newOpen} onOpenChange={setNewOpen} />
      <ConfirmDialog
        open={Boolean(toDelete)}
        onOpenChange={(o) => !o && setToDelete(null)}
        title={`Usunąć konto ${toDelete?.name}?`}
        description={
          <>
            Historia działań w dzienniku zdarzeń zostanie zachowana. Zamiast usuwać, możesz zablokować konto. Tej operacji nie można cofnąć.
          </>
        }
        confirmLabel="Usuń konto"
        onConfirm={async () => {
          try {
            await api.users.remove(toDelete!.id);
            qc.invalidateQueries({ queryKey: ["users"] });
            toast.success("Usunięto konto");
          } catch (e) {
            toast.error("Nie udało się usunąć", { description: errorMessage(e) });
          }
          setToDelete(null);
        }}
      />
    </Container>
  );
}
