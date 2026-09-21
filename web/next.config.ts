import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: process.env.STANDALONE === "true" ? "standalone" : undefined,
  distDir: process.env.NEXT_DIST_DIR ?? ".next",
  poweredByHeader: false,
  reactStrictMode: true,
  async headers() {
    const scriptSource = process.env.NODE_ENV === "development"
      ? "script-src 'self' 'unsafe-inline' 'unsafe-eval'"
      : "script-src 'self' 'unsafe-inline'";
    const connectSource = process.env.NODE_ENV === "development"
      ? "connect-src 'self' ws: wss: http://127.0.0.1:* http://localhost:*"
      : "connect-src 'self'";
    const upgrade = process.env.AGENTTRUST_HTTPS === "true" ? "; upgrade-insecure-requests" : "";
    const csp = `default-src 'self'; ${scriptSource}; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; ${connectSource}; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'${upgrade}`;
    return [{
      source: "/(.*)",
      headers: [
        { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
        { key: "X-Content-Type-Options", value: "nosniff" },
        { key: "X-Frame-Options", value: "DENY" },
        { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
        ...(process.env.AGENTTRUST_HTTPS === "true" ? [{ key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains" }] : []),
        { key: "Content-Security-Policy", value: csp },
      ],
    }];
  },
};

export default nextConfig;
