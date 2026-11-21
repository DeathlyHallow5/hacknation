# Attack Surface Intelligence — frontend (Next.js)

Interfejs CBI AGH do ciągłego monitoringu powierzchni ataku. Pełna dokumentacja, kontrakt API
dla backendu Rust i instrukcja podłączenia: [`../README.md`](../README.md).

```bash
npm install
npm run dev      # http://localhost:3000 — konta demo: jan.kowalski / anna.nowak / piotr.wisniewski / maria.wojcik, hasło: demo
```

Tryb API ustawia `ASI_API_MODE` (`mock` | `proxy` | `hybrid`) i `ASI_API_URL` — zobacz `.env.example`.
