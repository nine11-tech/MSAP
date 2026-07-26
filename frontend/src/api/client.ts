const configuredBaseUrl = import.meta.env.VITE_API_BASE_URL as string | undefined;

export const API_BASE_URL = (
  configuredBaseUrl ||
  (import.meta.env.DEV ? "http://127.0.0.1:8000/api" : "/api")
).replace(/\/$/, "");

export const API_DOCS_URL = `${API_BASE_URL.replace(/\/api$/, "")}/api/docs/`;

export class ApiError extends Error {
  status: number;
  code?: string;

  constructor(message: string, status: number, code?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

let csrfToken: string | null = null;

export function setCsrfToken(token: string | null) {
  csrfToken = token;
}

function isUnsafe(method = "GET") {
  return !["GET", "HEAD", "OPTIONS", "TRACE"].includes(method.toUpperCase());
}

export async function request<T>(
  path: string,
  options?: RequestInit,
): Promise<T> {
  const method = options?.method || "GET";
  const response = await fetch(`${API_BASE_URL}/${path.replace(/^\//, "")}`, {
    ...options,
    credentials: "include",
    headers: {
      Accept: "application/json",
      ...(options?.body ? { "Content-Type": "application/json" } : {}),
      ...(isUnsafe(method) && csrfToken
        ? { "X-CSRFToken": csrfToken }
        : {}),
      ...options?.headers,
    },
  });

  const responseText = await response.text();
  let body: unknown = null;
  if (responseText) {
    try {
      body = JSON.parse(responseText);
    } catch {
      body = responseText;
    }
  }

  if (!response.ok) {
    const detail =
      typeof body === "object" && body !== null && "detail" in body
        ? String(body.detail)
        : response.statusText || "API request failed";
    const code =
      typeof body === "object" && body !== null && "code" in body
        ? String(body.code)
        : undefined;
    if (
      response.status === 401 ||
      (response.status === 403 &&
        detail.toLowerCase().includes("authentication credentials"))
    ) {
      window.dispatchEvent(new CustomEvent("msap:session-expired"));
    }
    throw new ApiError(detail, response.status, code);
  }

  return body as T;
}

export function apiGet<T>(path: string): Promise<T> {
  return request<T>(path);
}

export function apiPost<TResponse, TBody = Record<string, unknown>>(
  path: string,
  body?: TBody,
): Promise<TResponse> {
  return request<TResponse>(path, {
    method: "POST",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

export async function initializeCsrf(): Promise<string> {
  const response = await request<{ csrfToken: string }>("auth/csrf/");
  setCsrfToken(response.csrfToken);
  return response.csrfToken;
}

export async function apiDownload(
  path: string,
): Promise<{ blob: Blob; filename: string | null }> {
  const response = await fetch(`${API_BASE_URL}/${path.replace(/^\//, "")}`, {
    credentials: "include",
    headers: { Accept: "application/pdf" },
  });

  if (!response.ok) {
    let detail = response.statusText || "Download failed";
    try {
      const body = (await response.json()) as { detail?: unknown };
      if (body.detail) detail = String(body.detail);
    } catch {
      // Keep the clean HTTP fallback when the response is not JSON.
    }
    throw new ApiError(detail, response.status);
  }

  const disposition = response.headers.get("Content-Disposition") || "";
  const filenameMatch = disposition.match(/filename="([^"]+)"/i);
  return {
    blob: await response.blob(),
    filename: filenameMatch?.[1] || null,
  };
}
