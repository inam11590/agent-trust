import { NextResponse } from "next/server";

import { backendFetch } from "@/lib/api/server";
import { isSameOriginRequest } from "@/lib/security/request";

export async function POST(request: Request) {
  if (!isSameOriginRequest(request)) {
    return NextResponse.json({ detail: "Request origin rejected" }, { status: 403 });
  }
  try {
    const upstream = await backendFetch("/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(await request.json()),
    });
    return new NextResponse(await upstream.text(), {
      status: upstream.status,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
    });
  } catch {
    return NextResponse.json({ detail: "Backend unavailable" }, { status: 503 });
  }
}
