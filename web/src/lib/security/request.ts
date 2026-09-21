export function isSameOriginRequest(request: Request): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return true;
  try {
    const originUrl = new URL(origin);
    const requestUrl = new URL(request.url);
    if (originUrl.origin === requestUrl.origin) return true;

    // Normalize localhost and 127.0.0.1 for local environments
    const normOrigin = originUrl.host.replace("localhost", "127.0.0.1");
    const hostHeader = (request.headers.get("host") || requestUrl.host).replace("localhost", "127.0.0.1");
    return normOrigin === hostHeader && originUrl.protocol === requestUrl.protocol;
  } catch {
    return false;
  }
}
