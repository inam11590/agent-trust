import { NextResponse } from "next/server";

import { backendFetch } from "@/lib/api/server";
import { SESSION_COOKIE } from "@/lib/auth/constants";
import { isSameOriginRequest } from "@/lib/security/request";

export async function POST(request: Request) {
  if (!isSameOriginRequest(request)) {
    return NextResponse.json({ detail: "Request origin rejected" }, { status: 403 });
  }
  try {
    const payload = await request.json();
    const upstream = await backendFetch("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const body = await upstream.json();
    if (!upstream.ok) return NextResponse.json(body, { status: upstream.status });
    if (body.status === "MFA_REQUIRED") {
      return NextResponse.json({ status: "MFA_REQUIRED", challenge_token: body.challenge_token, expires_in: body.expires_in },
        { headers: { "Cache-Control": "no-store" } });
    }
    if (typeof body.access_token !== "string") return NextResponse.json({ detail: "Invalid login response" }, { status: 502 });

    const isHttps = request.url.startsWith("https://") || request.headers.get("x-forwarded-proto") === "https";
    const response = NextResponse.json({ authenticated: true });
    response.cookies.set(SESSION_COOKIE, body.access_token, {
      httpOnly: true,
      secure: isHttps,
      sameSite: "lax",
      priority: "high",
      path: "/",
      maxAge: body.expires_in,
    });
    return response;
  } catch {
    return NextResponse.json({ detail: "Backend unavailable" }, { status: 503 });
  }
}
