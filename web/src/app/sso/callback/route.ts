import { NextRequest, NextResponse } from "next/server";
import { timingSafeEqual } from "node:crypto";

import { backendFetch } from "@/lib/api/server";
import { SESSION_COOKIE } from "@/lib/auth/constants";

export async function GET(request: NextRequest) {
  const ticket = request.nextUrl.searchParams.get("ticket");
  const state = request.nextUrl.searchParams.get("state") ?? "";
  const expected = request.cookies.get("agenttrust_sso_state")?.value ?? "";
  const stateMatches = state.length >= 40 && state.length === expected.length &&
    timingSafeEqual(Buffer.from(state), Buffer.from(expected));
  if (!ticket || !/^[A-Za-z0-9_-]{32,200}$/.test(ticket) || !stateMatches) {
    return NextResponse.redirect(new URL("/login?error=sso", request.url));
  }
  try {
    const upstream = await backendFetch("/auth/sso/exchange", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ticket }),
    });
    if (!upstream.ok) return NextResponse.redirect(new URL("/login?error=sso", request.url));
    const body = await upstream.json();
    if (typeof body.access_token !== "string") return NextResponse.redirect(new URL("/login?error=sso", request.url));
    const response = NextResponse.redirect(new URL("/dashboard", request.url));
    response.cookies.set(SESSION_COOKIE, body.access_token, {
      httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "lax",
      priority: "high", path: "/", maxAge: body.expires_in,
    });
    response.cookies.set("agenttrust_sso_state", "", {
      httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "lax",
      path: "/sso/callback", maxAge: 0,
    });
    response.headers.set("Cache-Control", "no-store");
    response.headers.set("Referrer-Policy", "no-referrer");
    return response;
  } catch {
    return NextResponse.redirect(new URL("/login?error=sso", request.url));
  }
}
