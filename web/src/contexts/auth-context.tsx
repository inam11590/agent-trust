"use client";

import { createContext, useContext, useEffect, useState } from "react";
import { useRouter } from "next/navigation";

import { apiRequest, authRequest } from "@/lib/api/client";
import type { Organization, OrganizationRole, User } from "@/types";

type AuthContextValue = {
  user: User;
  organizations: Organization[];
  organization: Organization | null;
  role: OrganizationRole;
  switchOrganization: (id: string | null) => void;
  logout: () => Promise<void>;
};
const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  const [failed, setFailed] = useState(false);
  const [organizations, setOrganizations] = useState<Organization[] | null>(null);
  const [selectedOrganizationId, setSelectedOrganizationId] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    authRequest<User>("session")
      .then(async (value) => {
        const workspaces = await apiRequest<Organization[]>("/organizations");
        const stored = window.localStorage.getItem("agenttrust_organization_id");
        if (stored && !workspaces.some((item) => item.id === stored)) {
          window.localStorage.removeItem("agenttrust_organization_id");
        } else {
          setSelectedOrganizationId(stored);
        }
        if (active) { setUser(value); setOrganizations(workspaces); }
      })
      .catch(() => {
        if (active) {
          setFailed(true);
          router.replace("/login");
        }
      });
    return () => { active = false; };
  }, [router]);

  async function logout() {
    try { await authRequest<void>("logout", {}); } finally {
      setUser(null);
      router.replace("/login");
      router.refresh();
    }
  }

  const organization = organizations?.find((item) => item.id === selectedOrganizationId) ?? null;

  function switchOrganization(id: string | null) {
    if (id) window.localStorage.setItem("agenttrust_organization_id", id);
    else window.localStorage.removeItem("agenttrust_organization_id");
    setSelectedOrganizationId(id);
    router.push("/dashboard");
    router.refresh();
  }

  if (!user || !organizations) {
    return (
      <div className="grid min-h-screen place-items-center bg-[#101b35] text-sm text-slate-300">
        {failed ? "Redirecting to sign in…" : "Opening your secure workspace…"}
      </div>
    );
  }
  return <AuthContext.Provider value={{
    user, organizations, organization, role: organization?.role ?? "owner",
    switchOrganization, logout,
  }}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside AuthProvider");
  return value;
}
