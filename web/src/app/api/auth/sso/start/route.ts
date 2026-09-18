import { NextRequest, NextResponse } from "next/server";

import { backendFetch } from "@/lib/api/server";

export async function GET(request: NextRequest) {
  const organizationId = request.nextUrl.searchParams.get("organization_id");
  if (!organizationId || !/^[0-9a-f-]{36}$/i.test(organizationId)) {
    return NextResponse.json({ detail: "Enter a valid organization ID" }, { status: 400 });
  }
  try {
    const upstream = await backendFetch(`/auth/sso/${encodeURIComponent(organizationId)}/start`, { redirect: "manual" });
    const location = upstream.headers.get("location");
    if (upstream.status !== 302 || !location) return NextResponse.redirect(new URL("/login?error=sso", request.url));
    const destination = new URL(location);
    if (destination.protocol !== "https:" && !(process.env.NODE_ENV !== "production" && destination.hostname === "127.0.0.1")) {
      return NextResponse.json({ detail: "Invalid SSO provider redirect" }, { status: 502 });
    }
    const state = destination.searchParams.get("state");
    if (!state || !/^[A-Za-z0-9_.-]{40,200}$/.test(state)) {
      return NextResponse.json({ detail: "Invalid SSO state" }, { status: 502 });
    }
    const response = NextResponse.redirect(destination, { headers: { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" } });
    response.cookies.set("agenttrust_sso_state", state, {
      httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "lax",
      priority: "high", path: "/sso/callback", maxAge: 300,
    });
    return response;
  } catch {
    return NextResponse.redirect(new URL("/login?error=sso", request.url));
  }
}
