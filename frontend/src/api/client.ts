const configuredBaseUrl = import.meta.env.VITE_API_BASE_URL as string | undefined;

function alignDevelopmentLoopbackHost(baseUrl: string) {
  if (
    !import.meta.env.DEV ||
    typeof window === "undefined" ||
    !/^https?:\/\//i.test(baseUrl)
  ) {
    return baseUrl;
  }

  const apiUrl = new URL(baseUrl);
  const loopbackHosts = new Set(["localhost", "127.0.0.1"]);
  if (
    loopbackHosts.has(apiUrl.hostname) &&
    loopbackHosts.has(window.location.hostname)
  ) {
    // Keep local cookies same-site when Compose is configured with localhost
    // but the browser opened Vite on 127.0.0.1 (or vice versa).
    apiUrl.hostname = window.location.hostname;
    return apiUrl.toString();
  }
  return baseUrl;
}

export const API_BASE_URL = alignDevelopmentLoopbackHost(
  configuredBaseUrl ||
    (import.meta.env.DEV ? "http://127.0.0.1:8000/api" : "/api"),
).replace(/\/$/, "");

export const API_DOCS_URL = `${API_BASE_URL.replace(/\/api$/, "")}/api/docs/`;

export class ApiError extends Error {
  status: number;
  code?: string;
  endpoint?: string;

  constructor(
    message: string,
    status: number,
    code?: string,
    endpoint?: string,
  ) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.endpoint = endpoint;
  }
}

let csrfToken: string | null = null;

export function setCsrfToken(token: string | null) {
  csrfToken = token;
}

function isUnsafe(method = "GET") {
  return !["GET", "HEAD", "OPTIONS", "TRACE"].includes(method.toUpperCase());
}

function readCookie(name: string): string | null {
  if (typeof document === "undefined") return null;
  const prefix = `${encodeURIComponent(name)}=`;
  const cookie = document.cookie
    .split(";")
    .map((value) => value.trim())
    .find((value) => value.startsWith(prefix));
  if (!cookie) return null;

  try {
    return decodeURIComponent(cookie.slice(prefix.length));
  } catch {
    return cookie.slice(prefix.length);
  }
}

function csrfTokenForRequest() {
  // Django may rotate the CSRF cookie when login rotates the session. Prefer
  // that current cookie over an older token retained in memory.
  return readCookie("csrftoken") || csrfToken;
}

function responseDetail(body: unknown, fallback: string) {
  if (typeof body === "object" && body !== null && "detail" in body) {
    return String(body.detail);
  }
  return typeof body === "string" ? body : fallback;
}

function debugAuthRequest(
  endpoint: string,
  requestUrl: string,
  status: number | "network-error",
  detail?: string,
) {
  if (
    !import.meta.env.DEV ||
    !["auth/csrf/", "auth/login/", "auth/me/"].includes(endpoint)
  ) {
    return;
  }
  console.debug("[MSAP auth]", {
    endpoint,
    requestUrl,
    status,
    ...(detail ? { detail } : {}),
  });
}

export async function request<T>(
  path: string,
  options?: RequestInit,
): Promise<T> {
  const method = options?.method || "GET";
  const endpoint = path.replace(/^\//, "");
  const requestUrl = `${API_BASE_URL}/${endpoint}`;
  const currentCsrfToken = csrfTokenForRequest();
  let response: Response;
  try {
    response = await fetch(requestUrl, {
      ...options,
      credentials: "include",
      headers: {
        Accept: "application/json",
        ...(options?.body ? { "Content-Type": "application/json" } : {}),
        ...(isUnsafe(method) && currentCsrfToken
          ? { "X-CSRFToken": currentCsrfToken }
          : {}),
        ...options?.headers,
      },
    });
  } catch (error) {
    debugAuthRequest(
      endpoint,
      requestUrl,
      "network-error",
      error instanceof Error ? error.message : "Request failed",
    );
    throw error;
  }

  const responseText = await response.text();
  let body: unknown = null;
  if (responseText) {
    try {
      body = JSON.parse(responseText);
    } catch {
      body = responseText;
    }
  }

  const detail = responseDetail(
    body,
    response.statusText || (response.ok ? "" : "API request failed"),
  );
  debugAuthRequest(endpoint, requestUrl, response.status, detail || undefined);

  if (!response.ok) {
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
    throw new ApiError(detail, response.status, code, endpoint);
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

  const contentType = (response.headers.get("Content-Type") || "")
    .split(";", 1)[0]
    .trim()
    .toLowerCase();
  if (contentType !== "application/pdf") {
    throw new ApiError(
      `Report response was ${contentType || "missing a Content-Type"}; expected application/pdf.`,
      response.status,
      "INVALID_REPORT_CONTENT_TYPE",
      path,
    );
  }

  const disposition = response.headers.get("Content-Disposition") || "";
  const filenameMatch = disposition.match(/filename="([^"]+)"/i);
  const blob = await response.blob();
  const signature = new Uint8Array(await blob.slice(0, 5).arrayBuffer());
  if (String.fromCharCode(...signature) !== "%PDF-") {
    throw new ApiError(
      "Report response did not contain a valid PDF signature.",
      response.status,
      "INVALID_REPORT_CONTENT",
      path,
    );
  }
  return {
    blob,
    filename: filenameMatch?.[1] || null,
  };
}

export async function apiPostBlob(path: string): Promise<Blob> {
  const endpoint = path.replace(/^\//, "");
  const response = await fetch(`${API_BASE_URL}/${endpoint}`, {
    method: "POST",
    credentials: "include",
    headers: {
      Accept: "image/png",
      "Content-Type": "application/json",
      ...(csrfTokenForRequest()
        ? { "X-CSRFToken": csrfTokenForRequest() as string }
        : {}),
    },
    body: "{}",
  });

  if (!response.ok) {
    const responseText = await response.text();
    let body: unknown = responseText;
    try {
      body = responseText ? JSON.parse(responseText) : null;
    } catch {
      // Keep the bounded plain-text error returned by the backend.
    }
    const detail = responseDetail(
      body,
      response.statusText || "Screenshot request failed",
    );
    const code =
      typeof body === "object" && body !== null && "code" in body
        ? String(body.code)
        : undefined;
    throw new ApiError(detail, response.status, code, endpoint);
  }
  const contentType = (response.headers.get("Content-Type") || "")
    .split(";", 1)[0]
    .trim()
    .toLowerCase();
  if (contentType !== "image/png") {
    throw new ApiError(
      `Screenshot response was ${contentType || "missing a Content-Type"}; expected image/png.`,
      response.status,
      "INVALID_SCREENSHOT_CONTENT_TYPE",
      endpoint,
    );
  }

  const blob = await response.blob();
  if (blob.type && blob.type.toLowerCase() !== "image/png") {
    throw new ApiError(
      `Screenshot blob was ${blob.type}; expected image/png.`,
      response.status,
      "INVALID_SCREENSHOT_CONTENT_TYPE",
      endpoint,
    );
  }
  return blob;
}
