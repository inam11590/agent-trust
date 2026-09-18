import { NextResponse } from "next/server";

import { SESSION_COOKIE } from "@/lib/auth/constants";
import { isSameOriginRequest } from "@/lib/security/request";
import { backendFetch } from "@/lib/api/server";
import { cookies } from "next/headers";

export async function POST(request: Request) {
  if (!isSameOriginRequest(request)) {
    return NextResponse.json({ detail: "Request origin rejected" }, { status: 403 });
  }
  const token = (await cookies()).get(SESSION_COOKIE)?.value;
  if (token) {
    try { await backendFetch("/auth/logout", { method: "POST" }, token); } catch { /* Clear the browser cookie even if the API is unavailable. */ }
  }
  const response = new NextResponse(null, { status: 204 });
  response.cookies.set(SESSION_COOKIE, "", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    priority: "high",
    path: "/",
    maxAge: 0,
  });
  return response;
}
