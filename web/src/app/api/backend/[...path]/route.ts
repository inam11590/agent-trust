import { cookies } from "next/headers";
import { NextRequest, NextResponse } from "next/server";

import { backendFetch } from "@/lib/api/server";
import { SESSION_COOKIE } from "@/lib/auth/constants";
import { isSameOriginRequest } from "@/lib/security/request";

type Context = { params: Promise<{ path: string[] }> };
const ALLOWED_ROOTS = new Set([
  "agents", "audit-logs", "authorization-requests", "authorize", "developer",
  "devices", "invitations", "notification-preferences", "notifications", "organizations", "permissions", "risk", "users",
  "billing", "security",
]);

async function forward(request: NextRequest, context: Context) {
  const token = (await cookies()).get(SESSION_COOKIE)?.value;
  if (!token) return NextResponse.json({ detail: "Not authenticated" }, { status: 401 });

  const rawSegments = (await context.params).path;
  if (!rawSegments.length || !ALLOWED_ROOTS.has(rawSegments[0])) {
    return NextResponse.json({ detail: "Route not allowed" }, { status: 404 });
  }
  if (!["GET", "HEAD"].includes(request.method) && !isSameOriginRequest(request)) {
    return NextResponse.json({ detail: "Request origin rejected" }, { status: 403 });
  }
  const segments = rawSegments.map(encodeURIComponent).join("/");
  const path = `/${segments}${request.nextUrl.search}`;
  const hasBody = !["GET", "HEAD"].includes(request.method);
  try {
    const upstream = await backendFetch(path, {
      method: request.method,
      headers: {
        ...(hasBody ? { "Content-Type": request.headers.get("content-type") ?? "application/json" } : {}),
        ...(request.headers.get("x-organization-id") ? { "X-Organization-ID": request.headers.get("x-organization-id")! } : {}),
      },
      body: hasBody ? await request.text() : undefined,
    }, token);
    const contentType = upstream.headers.get("content-type") ?? "application/json";
    const isEventStream = contentType.startsWith("text/event-stream");
    const response = new NextResponse(
      upstream.status === 204 ? null : isEventStream ? upstream.body : await upstream.text(), {
      status: upstream.status,
      headers: {
        "Content-Type": contentType,
        "Cache-Control": isEventStream ? "no-cache, no-store" : "no-store",
        ...(isEventStream ? { "X-Accel-Buffering": "no" } : {}),
      },
    });
    if (upstream.status === 401) response.cookies.delete(SESSION_COOKIE);
    return response;
  } catch {
    return NextResponse.json({ detail: "Backend unavailable" }, { status: 503 });
  }
}

export const GET = forward;
export const POST = forward;
export const PATCH = forward;
export const PUT = forward;
export const DELETE = forward;
