// Appels à l'API de la console. Même origine, cookie de session posé par le
// serveur (`HttpOnly`, jamais lu ici). Toute erreur a la forme
// `{"error": "<code>", "message": "..."}` (docs/WEBUI.md §5).

export interface ApiError {
  error: string;
  message: string;
}

export interface Reply<T> {
  status: number;
  body: T | ApiError | null;
}

export async function call<T>(method: "GET" | "POST", path: string, body?: unknown): Promise<Reply<T>> {
  const init: RequestInit = { method, credentials: "same-origin", headers: {} };
  if (body !== undefined) {
    init.headers = { "Content-Type": "application/json" };
    init.body = JSON.stringify(body);
  }
  const res = await fetch(path, init);
  const text = await res.text();
  let parsed: T | ApiError | null = null;
  if (text !== "") {
    try {
      parsed = JSON.parse(text) as T | ApiError;
    } catch {
      parsed = null;
    }
  }
  return { status: res.status, body: parsed };
}

export function isError(body: unknown): body is ApiError {
  return typeof body === "object" && body !== null && "error" in body;
}

export interface ConsoleInfo {
  environment: "production" | "staging" | "demo" | "undeclared";
  version: string;
}

export interface Me {
  operator: string;
  role: "auditeur" | "ra_operateur" | "ca_operateur" | "admin";
}
