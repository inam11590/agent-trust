import "server-only";

const DEFAULT_API_URL = "http://127.0.0.1:8000";

export function getApiBaseUrl(): string {
  if (process.env.NODE_ENV === "production" && !process.env.AGENTTRUST_API_URL) {
    throw new Error("AGENTTRUST_API_URL must be configured in production");
  }
  const configured =
    process.env.AGENTTRUST_API_URL ??
    DEFAULT_API_URL;
  const url = new URL(configured);
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("AgentTrust API URL must use HTTP or HTTPS");
  }
  return url.toString().replace(/\/$/, "");
}

export async function backendFetch(
  path: string,
  init: RequestInit = {},
  accessToken?: string,
): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);

  try {
    return await fetch(`${getApiBaseUrl()}${path}`, {
      ...init,
      headers,
      cache: "no-store",
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timeout);
  }
}
