export type Session = { email: string; csrf_token: string };
export type Server = {
  id: string;
  name: string;
  description: string;
  tags: string[];
  archived: boolean;
};
export type Service = {
  id: string;
  server_id: string;
  name: string;
  kind: 'apache_status' | 'mrtg' | 'goaccess';
  url: string;
  interval_seconds: number;
  enabled: boolean;
  archived: boolean;
  revision: number;
  options: {
    apache_auto: boolean;
    authorize_origin?: boolean;
    allow_http?: boolean;
    goaccess_max_age_hours?: number;
  };
  has_credentials: boolean;
  status: 'waiting' | 'ok' | 'partial' | 'error' | 'stale' | 'pending' | 'paused' | 'archived';
};
export type Page<T> = { items: T[]; total: number };
export type Health = {
  database: string;
  scheduler: string;
  scheduler_last_seen: string | null;
  apache_collector: string;
  mrtg_collector: string;
};

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

export async function api<T>(
  path: string,
  csrf?: string,
  method = 'GET',
  body?: unknown,
): Promise<T> {
  const response = await fetch(`/api/v1${path}`, {
    method,
    credentials: 'same-origin',
    headers: {
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...(csrf ? { 'X-CSRF-Token': csrf } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new ApiError(
      response.status,
      typeof payload?.detail === 'string' ? payload.detail : 'No se pudo completar la solicitud.',
    );
  }
  return response.status === 204 ? (undefined as T) : response.json();
}
