import { PERMISSIONS, type DefectDojoConfigInput, type Permission, type Role, type Settings } from "@/lib/api/types";
import { parseCidr } from "@/lib/net";
import { nextId } from "@/mock/db";
import type { RouteFn } from "@/mock/router";
import { iso } from "@/mock/time";
import { apiError, audit, badRequest, json, matchesText, notFound, paginate, publicUser } from "@/mock/util";

function ddPublic(db: import("@/mock/db").MockDB) {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { token, ...rest } = db.defectdojo;
  return rest;
}

export function adminRoutes(route: RouteFn) {
  /* ---------------- users ---------------- */
  route("GET", "/users", "users:read", (ctx) => json(ctx.db.users.map(publicUser)));

  route("POST", "/users", "users:manage", async (ctx) => {
    const body = await ctx.body<{ login: string; name: string; email: string; role_id: string; password: string }>();
    const fields: Record<string, string> = {};
    if (!/^[a-z0-9._-]{3,}$/.test(body.login ?? "")) fields.login = "Co najmniej 3 znaki: małe litery, cyfry, kropka, myślnik";
    if (!body.name?.trim()) fields.name = "Pole wymagane";
    if (!/^\S+@\S+\.\S+$/.test(body.email ?? "")) fields.email = "Niepoprawny adres e-mail";
    if (!ctx.db.roles.some((r) => r.id === body.role_id)) fields.role_id = "Wybierz rolę";
    if ((body.password ?? "").length < 12) fields.password = "Hasło musi mieć co najmniej 12 znaków";
    if (ctx.db.users.some((u) => u.login === body.login)) fields.login = "Login jest już zajęty";
    if (Object.keys(fields).length) return badRequest("Popraw zaznaczone pola.", fields);
    const role = ctx.db.roles.find((r) => r.id === body.role_id)!;
    const u = {
      id: nextId(ctx.db, "u"),
      login: body.login,
      name: body.name.trim(),
      email: body.email,
      role_id: role.id,
      role_name: role.name,
      active: true,
      last_login_at: null,
      created_at: iso(Date.now()),
      password: body.password,
    };
    ctx.db.users.push(u);
    role.users_count += 1;
    audit(ctx.db, ctx.user, "create", "user", u.name, `Utworzono konto z rolą ${role.name}`, [], u.id);
    return json(publicUser(u), { status: 201 });
  });

  route("PATCH", "/users/:id", "users:manage", async (ctx) => {
    const u = ctx.db.users.find((x) => x.id === ctx.params.id);
    if (!u) return notFound("Użytkownik");
    const body = await ctx.body<{ name?: string; email?: string; role_id?: string; active?: boolean }>();
    if (u.id === ctx.user!.id && (body.active === false || (body.role_id && body.role_id !== u.role_id)))
      return apiError(409, "conflict", "Nie możesz odebrać sobie roli ani zablokować własnego konta.");
    const changes = [];
    if (body.role_id && body.role_id !== u.role_id) {
      const role = ctx.db.roles.find((r) => r.id === body.role_id);
      if (!role) return badRequest("Nieznana rola.", { role_id: "Wybierz rolę" });
      const old = ctx.db.roles.find((r) => r.id === u.role_id);
      if (old) old.users_count -= 1;
      role.users_count += 1;
      changes.push({ field: "role", label: "Rola", before: u.role_name, after: role.name });
      u.role_id = role.id;
      u.role_name = role.name;
    }
    if (body.active !== undefined && body.active !== u.active) {
      changes.push({ field: "active", label: "Aktywne", before: u.active ? "tak" : "nie", after: body.active ? "tak" : "nie" });
      u.active = body.active;
    }
    if (body.name && body.name !== u.name) {
      changes.push({ field: "name", label: "Imię i nazwisko", before: u.name, after: body.name });
      u.name = body.name;
    }
    if (body.email && body.email !== u.email) {
      changes.push({ field: "email", label: "E-mail", before: u.email, after: body.email });
      u.email = body.email;
    }
    if (changes.length) audit(ctx.db, ctx.user, "update", "user", u.name, "Edytowano konto użytkownika", changes, u.id);
    return json(publicUser(u));
  });

  route("DELETE", "/users/:id", "users:manage", (ctx) => {
    const u = ctx.db.users.find((x) => x.id === ctx.params.id);
    if (!u) return notFound("Użytkownik");
    if (u.id === ctx.user!.id) return apiError(409, "conflict", "Nie możesz usunąć własnego konta.");
    ctx.db.users = ctx.db.users.filter((x) => x.id !== u.id);
    const role = ctx.db.roles.find((r) => r.id === u.role_id);
    if (role) role.users_count -= 1;
    audit(ctx.db, ctx.user, "delete", "user", u.name, "Usunięto konto użytkownika", [], u.id);
    return new Response(null, { status: 204 });
  });

  /* ---------------- roles ---------------- */
  route("GET", "/roles", "roles:read", (ctx) => json(ctx.db.roles));
  route("GET", "/permissions", "roles:read", () => json(PERMISSIONS));

  const cleanPerms = (p: unknown): Permission[] =>
    Array.isArray(p) ? (p.filter((x) => (PERMISSIONS as readonly string[]).includes(String(x))) as Permission[]) : [];

  route("POST", "/roles", "roles:manage", async (ctx) => {
    const body = await ctx.body<Pick<Role, "name" | "description" | "permissions">>();
    if (!body.name?.trim()) return badRequest("Podaj nazwę roli.", { name: "Pole wymagane" });
    if (ctx.db.roles.some((r) => r.name.toLowerCase() === body.name.trim().toLowerCase()))
      return badRequest("Rola o tej nazwie już istnieje.", { name: "Nazwa zajęta" });
    const perms = cleanPerms(body.permissions);
    if (!perms.length) return badRequest("Wybierz co najmniej jedno uprawnienie.", { permissions: "Brak uprawnień" });
    const role: Role = { id: nextId(ctx.db, "r"), key: `custom-${ctx.db.seq}`, name: body.name.trim(), description: body.description ?? "", builtin: false, permissions: perms, users_count: 0 };
    ctx.db.roles.push(role);
    audit(ctx.db, ctx.user, "create", "role", role.name, `Utworzono rolę własną (${perms.length} uprawnień)`, [], role.id);
    return json(role, { status: 201 });
  });

  route("PATCH", "/roles/:id", "roles:manage", async (ctx) => {
    const role = ctx.db.roles.find((r) => r.id === ctx.params.id);
    if (!role) return notFound("Rola");
    if (role.builtin) return apiError(409, "conflict", "Ról wbudowanych nie można zmieniać — utwórz kopię jako rolę własną.");
    const body = await ctx.body<Partial<Pick<Role, "name" | "description" | "permissions">>>();
    const changes = [];
    if (body.permissions) {
      const perms = cleanPerms(body.permissions);
      changes.push({ field: "permissions", label: "Uprawnienia", before: String(role.permissions.length), after: String(perms.length) });
      role.permissions = perms;
    }
    if (body.name && body.name !== role.name) {
      changes.push({ field: "name", label: "Nazwa", before: role.name, after: body.name });
      role.name = body.name;
      for (const u of ctx.db.users) if (u.role_id === role.id) u.role_name = role.name;
    }
    if (body.description !== undefined) role.description = body.description;
    audit(ctx.db, ctx.user, "update", "role", role.name, "Edytowano rolę", changes, role.id);
    return json(role);
  });

  route("DELETE", "/roles/:id", "roles:manage", (ctx) => {
    const role = ctx.db.roles.find((r) => r.id === ctx.params.id);
    if (!role) return notFound("Rola");
    if (role.builtin) return apiError(409, "conflict", "Ról wbudowanych nie można usuwać.");
    if (ctx.db.users.some((u) => u.role_id === role.id)) return apiError(409, "conflict", "Rola jest przypisana do użytkowników. Zmień im rolę przed usunięciem.");
    ctx.db.roles = ctx.db.roles.filter((r) => r.id !== role.id);
    audit(ctx.db, ctx.user, "delete", "role", role.name, "Usunięto rolę własną", [], role.id);
    return new Response(null, { status: 204 });
  });

  /* ---------------- integrations ---------------- */
  route("GET", "/integrations/defectdojo", "integrations:read", (ctx) => json(ddPublic(ctx.db)));

  route("PUT", "/integrations/defectdojo", "integrations:manage", async (ctx) => {
    const body = await ctx.body<DefectDojoConfigInput>();
    if (body.url !== undefined && !/^https?:\/\/\S+$/.test(body.url)) return badRequest("Podaj adres URL instancji DefectDojo.", { url: "Np. https://defectdojo.example" });
    const dd = ctx.db.defectdojo;
    const { api_token, ...rest } = body;
    Object.assign(dd, rest);
    if (api_token) {
      dd.token = api_token;
      dd.api_token_set = true;
      dd.api_token_masked = `••••••••••••${api_token.slice(-4)}`;
    }
    audit(ctx.db, ctx.user, "update", "integration", "DefectDojo", api_token ? "Zmieniono konfigurację i token DefectDojo (token zaszyfrowany)" : "Zmieniono konfigurację DefectDojo");
    return json(ddPublic(ctx.db));
  });

  route("POST", "/integrations/defectdojo/test", "integrations:manage", (ctx) => {
    const dd = ctx.db.defectdojo;
    const ok = dd.api_token_set && /^https?:\/\//.test(dd.url);
    dd.last_test = {
      ok,
      at: iso(Date.now()),
      version: ok ? "2.39.1" : null,
      latency_ms: ok ? 60 + Math.round(Math.random() * 60) : null,
      message: ok ? `Połączono z ${dd.url} — token ważny, produkt „${dd.product_name}” dostępny` : "Brak tokenu API lub niepoprawny adres",
    };
    return json(ddPublic(ctx.db));
  });

  route("GET", "/integrations/defectdojo/exports", "integrations:read", (ctx) => json(ctx.db.ddExports));
  route("GET", "/engines", "integrations:read", (ctx) => json(ctx.db.engines));

  /* ---------------- audit ---------------- */
  route("GET", "/audit", "audit:read", (ctx) => {
    const q = ctx.query.get("q");
    const actor = ctx.query.get("actor");
    const action = ctx.query.get("action");
    const resource = ctx.query.get("resource");
    const from = ctx.query.get("from");
    const to = ctx.query.get("to");
    const items = ctx.db.audit.filter(
      (e) =>
        matchesText(q, e.summary, e.resource_label, e.actor.name) &&
        (!actor || e.actor.id === actor) &&
        (!action || e.action === action) &&
        (!resource || e.resource === resource) &&
        (!from || e.at >= from) &&
        (!to || e.at <= to),
    );
    return json(paginate(items, ctx.query, 30));
  });

  /* ---------------- settings & encryption ---------------- */
  route("GET", "/settings", "settings:read", (ctx) => json(ctx.db.settings));

  route("PATCH", "/settings", "settings:manage", async (ctx) => {
    const body = await ctx.body<Partial<Settings>>();
    const s = ctx.db.settings;
    const fields: Record<string, string> = {};
    const safety = body.scan_safety;
    if (safety?.max_rate_rps !== undefined && (safety.max_rate_rps < 1 || safety.max_rate_rps > 5000)) fields.max_rate_rps = "Zakres 1–5000";
    if (safety?.max_concurrency !== undefined && (safety.max_concurrency < 1 || safety.max_concurrency > 512)) fields.max_concurrency = "Zakres 1–512";
    if (safety?.excluded_cidrs?.some((c) => !parseCidr(c))) fields.excluded_cidrs = "Każdy wpis musi być zakresem CIDR";
    const cd = body.change_detection;
    if (cd?.inactive_after_misses !== undefined && (cd.inactive_after_misses < 1 || cd.inactive_after_misses > 30)) fields.inactive_after_misses = "Zakres 1–30";
    if (Object.keys(fields).length) return badRequest("Popraw zaznaczone pola.", fields);
    const changes = [];
    if (safety?.max_rate_rps !== undefined && safety.max_rate_rps !== s.scan_safety.max_rate_rps)
      changes.push({ field: "max_rate_rps", label: "Limit zapytań/s", before: String(s.scan_safety.max_rate_rps), after: String(safety.max_rate_rps) });
    if (cd?.inactive_after_misses !== undefined && cd.inactive_after_misses !== s.change_detection.inactive_after_misses)
      changes.push({ field: "inactive_after_misses", label: "Nieaktywny po N skanach", before: String(s.change_detection.inactive_after_misses), after: String(cd.inactive_after_misses) });
    if (body.scan_safety) Object.assign(s.scan_safety, body.scan_safety);
    if (body.change_detection) Object.assign(s.change_detection, body.change_detection);
    if (body.retention) Object.assign(s.retention, body.retention);
    if (body.default_window) Object.assign(s.default_window, body.default_window);
    audit(ctx.db, ctx.user, "update", "settings", "Ustawienia", "Zmieniono ustawienia systemu", changes);
    return json(s);
  });

  route("GET", "/security/encryption", "settings:read", (ctx) => json(ctx.db.encryption));

  route("POST", "/security/encryption/rotate", "settings:manage", (ctx) => {
    const e = ctx.db.encryption;
    const old = e.key_id;
    const d = new Date();
    e.key_id = `kms-key-${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${Math.random().toString(36).slice(2, 6)}`;
    e.rotated_at = iso(d);
    e.key_created_at = iso(d);
    e.last_check_at = iso(d);
    audit(ctx.db, ctx.user, "rotate_key", "encryption", e.key_id, "Wykonano rotację klucza — dane zaszyfrowano ponownie", [{ field: "key_id", label: "Klucz", before: old, after: e.key_id }]);
    return json(e);
  });
}
