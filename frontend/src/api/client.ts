const configuredBaseUrl = import.meta.env.VITE_API_BASE_URL as string | undefined;

export const API_BASE_URL = (
  configuredBaseUrl || "http://127.0.0.1:8000/api"
).replace(/\/$/, "");

export const API_DOCS_URL = `${API_BASE_URL.replace(/\/api$/, "")}/api/docs/`;

export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}/${path.replace(/^\//, "")}`, {
    ...options,
    headers: {
      Accept: "application/json",
      ...(options?.body ? { "Content-Type": "application/json" } : {}),
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
    throw new ApiError(detail, response.status);
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

export async function apiDownload(
  path: string,
): Promise<{ blob: Blob; filename: string | null }> {
  const response = await fetch(`${API_BASE_URL}/${path.replace(/^\//, "")}`, {
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
