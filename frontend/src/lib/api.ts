/**
 * Couche d'accès réseau unique du frontend Adversum.
 *
 * Objectif : plus aucune URL backend ni clé API codée en dur dans les
 * composants. Tout passe par `apiFetch()` / `wsUrl()`, configurés par les
 * variables d'environnement Vite :
 *
 *   VITE_API_URL  URL de base du backend (vide = même origine, proxy Vite/Nginx)
 *   VITE_API_KEY  clé envoyée dans l'en-tête X-API-Key
 *
 * Voir frontend/.env.example.
 */

/** URL de base du backend, sans slash final. Vide = même origine. */
export const API_BASE: string = String(import.meta.env.VITE_API_URL ?? "").replace(/\/+$/, "");

/** Clé API partagée avec le backend (en-tête X-API-Key, ou ?api_key= sur le WS). */
export const API_KEY: string = String(import.meta.env.VITE_API_KEY ?? "").trim();

/** Nom de l'en-tête d'authentification attendu par FastAPI. */
export const API_KEY_HEADER = "X-API-Key";

/** Erreur réseau/API normalisée, levée par `apiFetch`. */
export class ApiError extends Error {
  /** Statut HTTP, ou 0 si la requête n'a jamais abouti. */
  readonly status: number;
  /** Message `detail` renvoyé par FastAPI, ou corps de réponse tronqué. */
  readonly detail: string;

  constructor(message: string, status = 0, detail = "") {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

export interface ApiFetchInit extends RequestInit {
  /**
   * Injecter l'en-tête X-API-Key (défaut : true).
   * Passer `false` pour les routes publiques (ex. `/metrics`).
   */
  auth?: boolean;
}

/** Construit l'URL absolue d'une route API à partir de `API_BASE`. */
export function apiUrl(path: string): string {
  // Les URL absolues (ex. reprise d'un lien externe) sont laissées intactes.
  if (/^https?:\/\//i.test(path)) return path;
  return `${API_BASE}${path.startsWith("/") ? path : `/${path}`}`;
}

function missingKeyError(): ApiError {
  return new ApiError(
    "Clé API absente : définissez VITE_API_KEY (voir frontend/.env.example).",
    0,
    "VITE_API_KEY absent"
  );
}

/** Extrait un message d'erreur lisible : `{detail}` FastAPI, sinon texte brut. */
async function readErrorDetail(res: Response): Promise<string> {
  try {
    const text = await res.clone().text();
    if (!text.trim()) return res.statusText;
    try {
      const parsed = JSON.parse(text) as { detail?: unknown; error?: unknown };
      if (typeof parsed.detail === "string" && parsed.detail) return parsed.detail;
      if (typeof parsed.error === "string" && parsed.error) return parsed.error;
    } catch {
      /* corps non-JSON : on retombe sur le texte brut */
    }
    return text.slice(0, 300);
  } catch {
    return res.statusText;
  }
}

/**
 * `fetch` authentifié vers le backend.
 *
 * - préfixe le chemin par `API_BASE` ;
 * - injecte `X-API-Key` (sauf `auth: false`) ;
 * - lève une `ApiError` explicite si la clé est absente ou si `!res.ok`.
 */
export async function apiFetch(path: string, init: ApiFetchInit = {}): Promise<Response> {
  const { auth = true, headers, ...rest } = init;

  if (auth && !API_KEY) throw missingKeyError();

  const merged = new Headers(headers);
  if (auth && !merged.has(API_KEY_HEADER)) merged.set(API_KEY_HEADER, API_KEY);

  const res = await fetch(apiUrl(path), { ...rest, headers: merged });

  if (!res.ok) {
    const detail = await readErrorDetail(res);
    throw new ApiError(
      `Requête ${path} échouée (HTTP ${res.status})${detail ? ` : ${detail}` : ""}`,
      res.status,
      detail
    );
  }

  return res;
}

/**
 * Construit l'URL du WebSocket : `wss://` si la page (ou `VITE_API_URL`) est en
 * HTTPS, et `?api_key=` encodé — le backend refuse désormais un flux non
 * authentifié.
 */
export function wsUrl(path: string): string {
  const normalized = path.startsWith("/") ? path : `/${path}`;
  const origin = API_BASE || window.location.origin;
  const base = new URL(origin, window.location.origin);
  const scheme = base.protocol === "https:" ? "wss:" : "ws:";

  const url = new URL(`${scheme}//${base.host}${normalized}`);
  if (API_KEY) url.searchParams.set("api_key", API_KEY);
  return url.toString();
}
