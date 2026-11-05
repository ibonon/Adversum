/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** URL de base du backend. Vide = même origine (proxy Vite en dev, Nginx en prod). */
  readonly VITE_API_URL?: string;
  /** Clé API envoyée dans X-API-Key, et en `?api_key=` sur le WebSocket. */
  readonly VITE_API_KEY?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
