import type { Metadata } from "next";

import "./globals.css";

export const metadata: Metadata = {
  title: { default: "AgentTrust", template: "%s | AgentTrust" },
  description: "Trust and permission controls for AI agents.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
