const FRIENDLY_DETAILS: Record<string, string> = {
  "Email is already registered": "An account already uses this email address.",
  "Invalid email or password": "The email or password is incorrect.",
  "Incorrect email or password": "The email or password is incorrect.",
  "Agent not found": "The requested agent could not be found.",
  "Permission not found": "The requested permission could not be found.",
  "Invalid or already used MFA code": "That code is invalid or was already used. Try a fresh code.",
};

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function friendlyError(response: Response): Promise<ApiError> {
  let detail = "";
  try {
    const body = (await response.json()) as { detail?: unknown; message?: unknown };
    if (typeof body.detail === "string") detail = body.detail;
    else if (typeof body.message === "string") detail = body.message;
  } catch {
    // A generic message is safer than displaying an untrusted upstream body.
  }

  if (detail in FRIENDLY_DETAILS) {
    return new ApiError(response.status, FRIENDLY_DETAILS[detail]);
  }
  if (response.status === 401) {
    return new ApiError(401, "Your session has expired. Please sign in again.");
  }
  if (response.status === 403) {
    return new ApiError(403, "You do not have permission for this action.");
  }
  if (response.status === 410) {
    return new ApiError(410, "This invitation has expired.");
  }
  if (response.status === 429) {
    return new ApiError(429, "Too many attempts. Please wait and try again.");
  }
  if (response.status === 422) {
    return new ApiError(422, "Please check the form and try again.");
  }
  if (response.status === 503) {
    return new ApiError(503, "Unable to connect to AgentTrust API.");
  }
  return new ApiError(
    response.status,
    "Something went wrong. Please try again.",
  );
}

export async function apiRequest<T>(path: string, init: RequestInit = {}): Promise<T> {
  let response: Response;
  const organizationId = typeof window === "undefined" || path.startsWith("/security/")
    ? null : window.localStorage.getItem("agenttrust_organization_id");
  try {
    response = await fetch(`/api/backend${path}`, {
      ...init,
      headers: {
        ...(init.body ? { "Content-Type": "application/json" } : {}),
        ...(organizationId ? { "X-Organization-ID": organizationId } : {}),
        ...init.headers,
      },
      cache: "no-store",
    });
  } catch {
    throw new ApiError(503, "Unable to connect to AgentTrust API.");
  }
  if (!response.ok) throw await friendlyError(response);
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export async function authRequest<T>(path: string, body?: object): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`/api/auth/${path}`, {
      method: body ? "POST" : "GET",
      headers: body ? { "Content-Type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined,
      cache: "no-store",
    });
  } catch {
    throw new ApiError(503, "Unable to connect to AgentTrust API.");
  }
  if (!response.ok) throw await friendlyError(response);
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}
