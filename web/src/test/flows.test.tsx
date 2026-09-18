import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { NextRequest } from "next/server";

import LoginPage from "@/app/(auth)/login/page";
import SecurityPage from "@/app/dashboard/security/page";
import SecurityEventsPage from "@/app/dashboard/security/events/page";
import OrganizationSecurityPage from "@/app/dashboard/security/organization/page";
import NewAgentPage from "@/app/dashboard/agents/new/page";
import AgentsPage from "@/app/dashboard/agents/page";
import AgentDetailsPage from "@/app/dashboard/agents/[id]/page";
import { SigningKeys } from "@/components/signing-keys";
import AuditLogsPage from "@/app/dashboard/audit-logs/page";
import DevelopersPage from "@/app/dashboard/developers/page";
import NewPermissionPage from "@/app/dashboard/permissions/new/page";
import PermissionsPage from "@/app/dashboard/permissions/page";
import TeamPage from "@/app/dashboard/team/page";
import NotificationsPage from "@/app/dashboard/notifications/page";
import AuthorizationRequestPage from "@/app/dashboard/authorization-requests/[id]/page";
import RiskPage from "@/app/dashboard/risk/page";
import RiskDetailPage from "@/app/dashboard/risk/[id]/page";
import BillingPage from "@/app/dashboard/billing/page";
import { NotificationBell, notificationHref } from "@/components/notification-bell";
import { DashboardShell } from "@/components/dashboard-shell";
import { StatusBadge } from "@/components/ui";
import { proxy } from "@/proxy";
import { isSameOriginRequest } from "@/lib/security/request";
import type { Agent, APIKey, AuditLog, BillingPlan, BillingSubscription, BillingUsage, Notification, Organization, OrganizationMember, PaginatedAuditLogs, Permission, RiskAssessment, RiskPolicy, User } from "@/types";

const push = vi.fn();
const replace = vi.fn();
const refresh = vi.fn();
const reload = vi.fn();
let pathname = "/dashboard";
let queryValues: Record<string, unknown> = {};

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push, replace, refresh }),
  usePathname: () => pathname,
  useParams: () => ({ id: "item-id" }),
  useSearchParams: () => new URLSearchParams(),
}));

vi.mock("@/hooks/use-api-query", () => ({
  useApiQuery: (path: string) => ({
    data: typeof queryValues[path] === "function" ? (queryValues[path] as () => unknown)() : queryValues[path],
    error: null,
    loading: false,
    reload,
  }),
}));

const user: User = {
  id: "user-1", email: "inam@example.com", full_name: "Inam", is_active: true,
  created_at: "2026-09-12T10:00:00Z", updated_at: "2026-09-12T10:00:00Z",
};
const logout = vi.fn();
let authRole: "owner" | "admin" | "developer" | "viewer" = "owner";
let authOrganization: Organization | null = null;
vi.mock("@/contexts/auth-context", () => ({ useAuth: () => ({
  user, logout, role: authRole, organization: authOrganization,
  organizations: authOrganization ? [authOrganization] : [], switchOrganization: vi.fn(),
}) }));

const agent: Agent = {
  id: "agent-uuid", name: "Travel Assistant", description: "Books approved travel",
  agent_identifier: "agt_1234567890abcdef12345678", owner_id: "user-1",
  organization_id: null, status: "active", created_at: "2026-09-12T10:00:00Z", updated_at: "2026-09-12T10:00:00Z",
};
const permission: Permission = {
  id: "permission-uuid", owner_id: "user-1", agent_id: agent.id, action: "purchase", resource: "flight",
  maximum_amount: "500.0000", currency: "USD", status: "active",
  valid_from: "2026-09-12T10:00:00Z", expires_at: "2026-09-13T10:00:00Z",
  created_at: "2026-09-12T10:00:00Z", updated_at: "2026-09-12T10:00:00Z",
};
const approved: AuditLog = {
  id: "audit-1", request_id: "req_1234567890abcdef12345678", user_id: "user-1", agent_id: agent.id,
  agent_identifier: agent.agent_identifier, permission_id: permission.id, action: "purchase", resource: "flight",
  amount: "420.0000", currency: "USD", decision: "APPROVED", reason: "Permission valid",
  requested_at: "2026-09-12T10:40:00Z", created_at: "2026-09-12T10:40:00Z",
};
const rejected: AuditLog = { ...approved, id: "audit-2", request_id: "req_abcdef1234567890abcdef12", amount: "700.0000", decision: "REJECTED", reason: "Amount exceeds allowed limit" };
const notification: Notification = {
  id: "notification-1", organization_id: null, type: "authorization_pending",
  title: "Approval Required", message: "Travel Assistant wants to purchase a flight for 420 USD.",
  status: "unread", priority: "high", related_request_id: "item-id", related_agent_id: agent.id,
  related_permission_id: permission.id, metadata: { request_id: approved.request_id },
  created_at: "2026-09-14T10:00:00Z", read_at: null,
};
const riskAssessment: RiskAssessment = {
  id: "item-id", request_id: approved.request_id, agent_id: agent.id,
  agent_identifier: agent.agent_identifier, agent_name: agent.name,
  action: "purchase", resource: "flight", amount: "2800", currency: "USD",
  risk_score: 72, risk_level: "HIGH", recommendation: "REQUIRE_APPROVAL",
  reasons: ["Amount is much higher than recent activity", "High request frequency"],
  final_status: "PENDING", model_version: "rules-v1", created_at: notification.created_at,
};
const riskPolicy: RiskPolicy = {
  id: "policy-1", organization_id: null, enabled: true,
  medium_action: "ALLOW", high_action: "REQUIRE_APPROVAL", critical_action: "REJECT",
  amount_anomaly_enabled: true, velocity_enabled: true, rejection_history_enabled: true,
  created_at: notification.created_at, updated_at: notification.created_at,
};
const billingOrganization: Organization = { id: "org-1", name: "SkyTravel", role: "owner", status: "active", created_at: notification.created_at };
const freePlan: BillingPlan = { id: "plan-1", code: "free", name: "Free", description: "For testing AgentTrust with a small team.", monthly_price: "0.00", yearly_price: null, currency: "USD", max_organizations: 1, max_members: 3, max_agents: 3, max_api_keys: 2, max_authorization_requests_monthly: 1000, max_webhooks: 1, risk_engine_enabled: true, advanced_risk_controls: false, advanced_notifications_enabled: false, priority_support: false };
const starterPlan: BillingPlan = { ...freePlan, id: "plan-2", code: "starter", name: "Starter", description: "For startups.", monthly_price: "29.00", max_agents: 10, max_api_keys: 10, max_authorization_requests_monthly: 20000 };
const billingSubscription: BillingSubscription = { organization_id: "org-1", plan: freePlan, status: "active", current_period_start: notification.created_at, current_period_end: "2026-10-01T00:00:00Z", cancel_at_period_end: false, trial_ends_at: null, grace_ends_at: null };
const billingUsage: BillingUsage = { organization_id: "org-1", plan_code: "free", period_start: "2026-09-01", period_end: "2026-10-01", usage: { authorization_requests: { used: 420, limit: 1000 }, agents: { used: 1, limit: 3 }, api_keys: { used: 1, limit: 2 }, team_members: { used: 0, limit: 3 }, webhooks: { used: 0, limit: 1 } } };

function billingData() {
  authOrganization = billingOrganization;
  queryValues["/billing/plans"] = [freePlan, starterPlan];
  queryValues["/billing/subscription"] = billingSubscription;
  queryValues["/billing/usage"] = billingUsage;
}

test("billing asks personal workspace to select an organization", () => {
  render(<BillingPage />); expect(screen.getByText("Select or create an organization")).toBeInTheDocument();
});
test("billing shows the current plan", () => {
  billingData(); render(<BillingPage />); expect(screen.getByText("Current plan")).toBeInTheDocument(); expect(screen.getAllByText("Free").length).toBeGreaterThan(0);
});
test("billing shows authorization usage", () => {
  billingData(); render(<BillingPage />); expect(screen.getByText("Authorization requests")).toBeInTheDocument(); expect(screen.getByText("420 / 1,000")).toBeInTheDocument();
});
test("billing shows resource usage cards", () => {
  billingData(); render(<BillingPage />); expect(screen.getByText("Agents")).toBeInTheDocument(); expect(screen.getByText("API keys")).toBeInTheDocument(); expect(screen.getByText("Webhooks")).toBeInTheDocument();
});
test("billing displays server-provided plan prices", () => {
  billingData(); render(<BillingPage />); expect(screen.getByText("$29")).toBeInTheDocument();
});
test("owner can choose an upgrade plan", () => {
  billingData(); render(<BillingPage />); expect(screen.getByRole("button", { name: "Choose Starter" })).toBeInTheDocument();
});
test("viewer cannot change subscription", () => {
  billingData(); authRole = "viewer"; render(<BillingPage />); expect(screen.queryByRole("button", { name: "Choose Starter" })).not.toBeInTheDocument();
});
test("scheduled cancellation is clearly shown", () => {
  billingData(); queryValues["/billing/subscription"] = { ...billingSubscription, plan: starterPlan, cancel_at_period_end: true }; render(<BillingPage />); expect(screen.getByText(/cancels at period end/)).toBeInTheDocument();
});

function jsonResponse(body: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }));
}

beforeEach(() => {
  vi.clearAllMocks();
  pathname = "/dashboard";
  queryValues = {};
  authRole = "owner";
  authOrganization = null;
});

test("login success redirects to dashboard", async () => {
  vi.stubGlobal("fetch", vi.fn(() => jsonResponse({ authenticated: true })));
  render(<LoginPage />);
  await userEvent.type(screen.getByLabelText("Email address"), "inam@example.com");
  await userEvent.type(screen.getByLabelText("Password"), "a-secure-password");
  await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
  await waitFor(() => expect(push).toHaveBeenCalledWith("/dashboard"));
});

test("login failure shows a friendly message", async () => {
  vi.stubGlobal("fetch", vi.fn(() => jsonResponse({ detail: "Invalid email or password" }, 401)));
  render(<LoginPage />);
  await userEvent.type(screen.getByLabelText("Email address"), "inam@example.com");
  await userEvent.type(screen.getByLabelText("Password"), "wrong");
  await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("email or password is incorrect");
});

test("MFA login waits for a code before opening the dashboard", async () => {
  const fetchMock = vi.fn()
    .mockImplementationOnce(() => jsonResponse({ status: "MFA_REQUIRED", challenge_token: "challenge-1" }))
    .mockImplementationOnce(() => jsonResponse({ authenticated: true }));
  vi.stubGlobal("fetch", fetchMock);
  render(<LoginPage />);
  await userEvent.type(screen.getByLabelText("Email address"), "inam@example.com");
  await userEvent.type(screen.getByLabelText("Password"), "a-secure-password");
  await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
  expect(await screen.findByLabelText("Authenticator or recovery code")).toBeInTheDocument();
  expect(push).not.toHaveBeenCalled();
  await userEvent.type(screen.getByLabelText("Authenticator or recovery code"), "123456");
  await userEvent.click(screen.getByRole("button", { name: "Verify and sign in" }));
  await waitFor(() => expect(push).toHaveBeenCalledWith("/dashboard"));
  expect(fetchMock).toHaveBeenCalledTimes(2);
});

test("security page shows MFA and active sessions", async () => {
  vi.stubGlobal("fetch", vi.fn((input: string) => input.includes("/security/mfa")
    ? jsonResponse({ enabled: true, pending: false, recovery_codes_remaining: 9 })
    : jsonResponse([{ id: "session-1", user_agent_summary: "Chrome on Windows", device_type: "desktop", auth_method: "password+mfa", last_active_at: "2026-09-16T10:00:00Z", expires_at: "2026-09-16T10:15:00Z", current: true }])));
  render(<SecurityPage />);
  expect(await screen.findByText(/Enabled. Use an authenticator/i)).toBeInTheDocument();
  expect(screen.getByText(/Chrome on Windows/)).toBeInTheDocument();
});

test("security page displays a one-time MFA setup QR code", async () => {
  vi.stubGlobal("fetch", vi.fn((input: string) => {
    if (input.endsWith("/security/mfa/setup")) return jsonResponse({ secret: "TESTSECRET", otpauth_uri: "otpauth://totp/test", qr_svg_data_url: "data:image/svg+xml;base64,PHN2Zy8+" });
    if (input.endsWith("/security/mfa")) return jsonResponse({ enabled: false, pending: false, recovery_codes_remaining: 0 });
    return jsonResponse([]);
  }));
  render(<SecurityPage />);
  await userEvent.click(await screen.findByRole("button", { name: "Set up authenticator" }));
  expect(await screen.findByAltText("Authenticator setup QR code")).toHaveAttribute("src", expect.stringContaining("data:image/svg+xml"));
});

test("security events page requests severity filter", async () => {
  const fetchMock = vi.fn((input: string) => { void input; return jsonResponse({ items: [], page: 1, page_size: 20, total: 0 }); });
  vi.stubGlobal("fetch", fetchMock);
  render(<SecurityEventsPage />);
  await userEvent.selectOptions(screen.getByLabelText("Severity"), "warning");
  await waitFor(() => expect(fetchMock.mock.calls.some(([url]) => String(url).includes("severity=warning"))).toBe(true));
});

test("only an owner can open organization security settings", () => {
  authOrganization = billingOrganization;
  authRole = "viewer";
  render(<OrganizationSecurityPage />);
  expect(screen.getByText(/Only an organization owner/)).toBeInTheDocument();
});

test("owner can see policy and SSO connection controls", async () => {
  authOrganization = billingOrganization;
  vi.stubGlobal("fetch", vi.fn((input: string) => input.includes("/sso/connections")
    ? jsonResponse([{ id: "sso-1", name: "Company OIDC", issuer: "https://id.example.com", status: "draft", verified_at: null }])
    : jsonResponse({ require_mfa: false, require_sso: false, session_timeout_minutes: 15,
        max_session_lifetime_minutes: 1440, allowed_email_domains: [], require_manual_approval_above_amount: null, approval_threshold_currency: "USD",
        block_critical_risk: true, require_approval_for_high_risk: true })));
  render(<OrganizationSecurityPage />);
  expect(await screen.findByText("Company OIDC · draft")).toBeInTheDocument();
  expect(screen.getByLabelText("Require MFA for organization work")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Save policy" })).toBeInTheDocument();
});

test("protected dashboard redirects without a session cookie", () => {
  const response = proxy(new NextRequest("http://localhost:3000/dashboard/agents"));
  expect(response.headers.get("location")).toContain("/login?next=%2Fdashboard%2Fagents");
});

test("mutation origin validation rejects a different site", () => {
  const request = new Request("http://localhost:3000/api/backend/agents", {
    method: "POST",
    headers: { Origin: "https://attacker.example" },
  });
  expect(isSameOriginRequest(request)).toBe(false);
});

test("agents list loads real agent data", () => {
  queryValues["/agents"] = [agent];
  render(<AgentsPage />);
  expect(screen.getByText("Travel Assistant")).toBeInTheDocument();
  expect(screen.getByText(agent.agent_identifier)).toBeInTheDocument();
});

test("signing keys show public metadata and reject invalid public key input", async () => {
  queryValues["/agents/agent-uuid/signing-keys"] = [{ id: "key-uuid", key_id: "key_ag_" + "b".repeat(24),
    algorithm: "Ed25519", fingerprint: "a".repeat(64), status: "ACTIVE",
    created_at: "2026-09-12T10:00:00Z", last_used_at: null, expires_at: null }];
  render(<SigningKeys agentId="agent-uuid" />);
  expect(screen.getByText("SHA256: aaaaaaaaaaaa…")).toBeInTheDocument();
  expect(screen.getByText(/Never paste your private key here/)).toBeInTheDocument();
  await userEvent.type(screen.getByLabelText(/Ed25519 public key/), "not-a-key");
  await userEvent.click(screen.getByRole("button", { name: "Add public key" }));
  expect(screen.getByRole("status")).toHaveTextContent(/base64-encoded 32-byte/);
});

test("signing key add, rotate, and revoke call the protected API", async () => {
  const keyId = "key_ag_" + "b".repeat(24);
  queryValues["/agents/agent-uuid/signing-keys"] = [{ id: "key-uuid", key_id: keyId,
    algorithm: "Ed25519", fingerprint: "a".repeat(64), status: "ACTIVE",
    created_at: "2026-09-12T10:00:00Z", last_used_at: null, expires_at: null }];
  const fetchMock = vi.fn<typeof fetch>(() => jsonResponse({ key_id: keyId }));
  vi.stubGlobal("fetch", fetchMock);
  vi.spyOn(window, "confirm").mockReturnValue(true);
  render(<SigningKeys agentId="agent-uuid" />);
  const publicKey = "A".repeat(43) + "=";
  await userEvent.type(screen.getByLabelText(/Ed25519 public key/), publicKey);
  await userEvent.click(screen.getByRole("button", { name: "Add public key" }));
  await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/api/backend/agents/agent-uuid/signing-keys", expect.objectContaining({ method: "POST" })));
  await userEvent.click(screen.getByRole("button", { name: "Rotate" }));
  await userEvent.type(screen.getByLabelText(/Ed25519 public key/), publicKey);
  await userEvent.click(screen.getByRole("button", { name: "Rotate key" }));
  await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(`/api/backend/agents/agent-uuid/signing-keys/${keyId}/rotate`, expect.objectContaining({ method: "POST" })));
  await userEvent.click(screen.getByRole("button", { name: "Revoke" }));
  await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(`/api/backend/agents/agent-uuid/signing-keys/${keyId}/revoke`, expect.objectContaining({ method: "POST" })));
});

test("viewer cannot see signing-key management controls", () => {
  authRole = "viewer";
  queryValues["/agents/item-id"] = agent;
  queryValues["/permissions"] = [];
  queryValues["/agents/item-id/audit-logs?page=1&page_size=5"] = { items: [], total: 0, page: 1, page_size: 5 };
  render(<AgentDetailsPage />);
  expect(screen.getByText("Read-only agent details.")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Add public key" })).not.toBeInTheDocument();
});

test("create agent submits name and description", async () => {
  const fetchMock = vi.fn<typeof fetch>(() => jsonResponse(agent));
  vi.stubGlobal("fetch", fetchMock);
  render(<NewAgentPage />);
  await userEvent.type(screen.getByLabelText("Agent name"), "Travel Assistant");
  await userEvent.type(screen.getByLabelText(/Description/), "Books approved travel");
  await userEvent.click(screen.getByRole("button", { name: "Create Agent" }));
  expect(await screen.findByText("Agent created successfully")).toBeInTheDocument();
  expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toMatchObject({ name: "Travel Assistant", description: "Books approved travel" });
});

test("permissions list loads", () => {
  queryValues["/permissions"] = [permission]; queryValues["/agents"] = [agent];
  render(<PermissionsPage />);
  expect(screen.getByText("Travel Assistant")).toBeInTheDocument();
  expect(screen.getByText("purchase")).toBeInTheDocument();
});

test("create permission sends validated data", async () => {
  queryValues["/agents"] = [agent];
  const fetchMock = vi.fn(() => jsonResponse(permission, 201));
  vi.stubGlobal("fetch", fetchMock);
  render(<NewPermissionPage />);
  await userEvent.selectOptions(screen.getByLabelText("Agent"), agent.id);
  await userEvent.type(screen.getByLabelText("Action"), "purchase");
  await userEvent.type(screen.getByLabelText("Resource"), "flight");
  await userEvent.type(screen.getByLabelText("Maximum amount"), "500");
  await userEvent.click(screen.getByRole("button", { name: "Create Permission" }));
  await waitFor(() => expect(push).toHaveBeenCalledWith(`/dashboard/permissions/${permission.id}?created=1`));
});

test("revoke permission calls the revoke API", async () => {
  queryValues["/permissions"] = [permission]; queryValues["/agents"] = [agent];
  vi.spyOn(window, "confirm").mockReturnValue(true);
  const fetchMock = vi.fn(() => jsonResponse({ ...permission, status: "revoked" }));
  vi.stubGlobal("fetch", fetchMock);
  render(<PermissionsPage />);
  await userEvent.click(screen.getByRole("button", { name: "Revoke" }));
  await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining(`/permissions/${permission.id}/revoke`), expect.objectContaining({ method: "POST" })));
});

test("audit log page displays approved and rejected results", () => {
  queryValues["/agents"] = [agent];
  queryValues["/audit-logs?page=1&page_size=20"] = { items: [approved, rejected], page: 1, page_size: 20, total: 2, total_pages: 1 } satisfies PaginatedAuditLogs;
  render(<AuditLogsPage />);
  expect(screen.getByText("APPROVED")).toBeInTheDocument();
  expect(screen.getByText("REJECTED")).toBeInTheDocument();
});

test("decision badges use readable labels", () => {
  const { rerender } = render(<StatusBadge value="APPROVED" />);
  expect(screen.getByText("APPROVED")).toBeVisible();
  rerender(<StatusBadge value="REJECTED" />);
  expect(screen.getByText("REJECTED")).toBeVisible();
});

test("audit pagination requests the next page", async () => {
  queryValues["/agents"] = [agent];
  queryValues["/audit-logs?page=1&page_size=20"] = { items: [approved], page: 1, page_size: 20, total: 21, total_pages: 2 };
  queryValues["/audit-logs?page=2&page_size=20"] = { items: [rejected], page: 2, page_size: 20, total: 21, total_pages: 2 };
  render(<AuditLogsPage />);
  await userEvent.click(screen.getByRole("button", { name: "Next" }));
  expect(screen.getByText("Page 2 of 2 · 21 records")).toBeInTheDocument();
});

test("logout control clears the session through auth context", async () => {
  pathname = "/dashboard/settings";
  render(<DashboardShell><div>Content</div></DashboardShell>);
  const buttons = screen.getAllByRole("button", { name: "Log out" });
  fireEvent.click(buttons[0]);
  expect(logout).toHaveBeenCalledOnce();
  expect(within(screen.getByRole("navigation")).getByText("Settings")).toBeInTheDocument();
});

test("developer page shows key prefixes and quick start without full secrets", () => {
  const apiKey: APIKey = {
    id: "key-1", organization_id: null, name: "Production Backend", prefix: "at_live_ab12",
    status: "active", created_at: "2026-09-13T10:00:00Z", last_used_at: null,
    expires_at: null, revoked_at: null,
  };
  queryValues["/developer/api-keys"] = [apiKey];
  queryValues["/developer/logs"] = [];
  render(<DevelopersPage />);
  expect(screen.getByText("Production Backend")).toBeInTheDocument();
  expect(screen.getByText(/at_live_ab12/)).toBeInTheDocument();
  expect(screen.getByText("Quick start")).toBeInTheDocument();
  expect(screen.getByText("X-API-Key")).toBeInTheDocument();
  expect(screen.queryByText(/at_live_[a-f0-9]{32}/)).not.toBeInTheDocument();
});

test("viewer sees data without create controls", () => {
  authRole = "viewer";
  queryValues["/agents"] = [agent];
  render(<AgentsPage />);
  expect(screen.getByText("Travel Assistant")).toBeInTheDocument();
  expect(screen.queryByRole("link", { name: "Create Agent" })).not.toBeInTheDocument();
});

test("team page shows organization members and owner controls", () => {
  authOrganization = {
    id: "org-1", name: "SkyTravel", role: "owner", status: "active",
    created_at: "2026-09-14T10:00:00Z",
  };
  const member: OrganizationMember = {
    id: "member-1", organization_id: "org-1", user_id: user.id,
    full_name: user.full_name, email: user.email, role: "owner", status: "active",
    joined_at: "2026-09-14T10:00:00Z", created_at: "2026-09-14T10:00:00Z",
  };
  queryValues["/organizations/org-1/members"] = [member];
  render(<TeamPage />);
  expect(screen.getByText("SkyTravel members and roles.")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Invite Member" })).toBeInTheDocument();
  expect(screen.getByText("inam@example.com")).toBeInTheDocument();
});

test("notification bell displays unread count and latest item", async () => {
  queryValues["/notifications/unread-count"] = { count: 3 };
  queryValues["/notifications?page=1&page_size=5"] = { items: [notification], page: 1, page_size: 5, total: 1, total_pages: 1 };
  render(<NotificationBell />);
  await userEvent.click(screen.getByRole("button", { name: "Notifications, 3 unread" }));
  expect(screen.getByText("Approval Required")).toBeInTheDocument();
});

test("real-time notification event requests fresh bell data", () => {
  let listener: (() => void) | undefined;
  class FakeEventSource { addEventListener(_name: string, value: () => void) { listener = value; } close() {} }
  vi.stubGlobal("EventSource", FakeEventSource);
  queryValues["/notifications/unread-count"] = { count: 0 };
  queryValues["/notifications?page=1&page_size=5"] = { items: [], page: 1, page_size: 5, total: 0, total_pages: 0 };
  render(<NotificationBell />);
  listener?.();
  expect(reload).toHaveBeenCalledTimes(2);
  vi.unstubAllGlobals();
});

test("notification page loads unread notification", () => {
  queryValues["/notifications?page=1&page_size=20"] = { items: [notification], page: 1, page_size: 20, total: 1, total_pages: 1 };
  render(<NotificationsPage />);
  expect(screen.getByText("Approval Required")).toBeInTheDocument();
  expect(screen.getByLabelText("Unread")).toBeInTheDocument();
});

test("notification page marks all as read", async () => {
  queryValues["/notifications?page=1&page_size=20"] = { items: [notification], page: 1, page_size: 20, total: 1, total_pages: 1 };
  const fetchMock = vi.fn(() => jsonResponse({ count: 0 })); vi.stubGlobal("fetch", fetchMock);
  render(<NotificationsPage />);
  await userEvent.click(screen.getByRole("button", { name: /Mark all as read/ }));
  expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining("/notifications/read-all"), expect.objectContaining({ method: "POST" }));
});

test("opening notification marks it read and opens exact request", async () => {
  queryValues["/notifications?page=1&page_size=20"] = { items: [notification], page: 1, page_size: 20, total: 1, total_pages: 1 };
  vi.stubGlobal("fetch", vi.fn(() => jsonResponse({ ...notification, status: "read" })));
  render(<NotificationsPage />);
  await userEvent.click(screen.getByText(notification.message));
  await waitFor(() => expect(push).toHaveBeenCalledWith("/dashboard/authorization-requests/item-id"));
});

test("notification links choose request before other related records", () => {
  expect(notificationHref(notification)).toBe("/dashboard/authorization-requests/item-id");
});

test("authorization request page loads linked request", () => {
  queryValues["/authorization-requests/item-id"] = {
    id: "item-id", request_id: approved.request_id, user_id: user.id, agent_id: agent.id,
    agent_identifier: agent.agent_identifier, agent_name: agent.name, permission_id: permission.id,
    action: "purchase", resource: "flight", amount: "420", currency: "USD", status: "PENDING",
    reason: "Awaiting user approval", created_at: notification.created_at,
    expires_at: "2026-09-14T10:05:00Z", decided_at: null,
  };
  render(<AuthorizationRequestPage />);
  expect(screen.getByText("Travel Assistant")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Approve" })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Reject" })).toBeInTheDocument();
});

test("empty notification response cannot expose another user data", () => {
  queryValues["/notifications?page=1&page_size=20"] = { items: [], page: 1, page_size: 20, total: 0, total_pages: 0 };
  render(<NotificationsPage />);
  expect(screen.getByText("No notifications")).toBeInTheDocument();
});

test("risk overview and table load", () => {
  queryValues["/risk/overview"] = { low: 2, medium: 1, high: 1, critical: 0 };
  queryValues["/risk/assessments?page=1&page_size=20"] = { items: [riskAssessment], page: 1, page_size: 20, total: 1, total_pages: 1 };
  queryValues["/risk/policy"] = riskPolicy;
  render(<RiskPage />);
  expect(screen.getByText("Risk Overview")).toBeInTheDocument();
  expect(screen.getByText("72/100")).toBeInTheDocument();
  expect(screen.getByText("Travel Assistant")).toBeInTheDocument();
});

test("risk detail shows score and understandable reasons", () => {
  queryValues["/risk/assessments/item-id"] = riskAssessment;
  render(<RiskDetailPage />);
  expect(screen.getByText("HIGH RISK")).toBeInTheDocument();
  expect(screen.getByText("Amount is much higher than recent activity")).toBeInTheDocument();
});

test("owner can edit risk policy", async () => {
  queryValues["/risk/overview"] = { low: 0, medium: 0, high: 0, critical: 0 };
  queryValues["/risk/assessments?page=1&page_size=20"] = { items: [], page: 1, page_size: 20, total: 0, total_pages: 0 };
  queryValues["/risk/policy"] = riskPolicy;
  const fetchMock = vi.fn(() => jsonResponse({ ...riskPolicy, high_action: "REJECT" })); vi.stubGlobal("fetch", fetchMock);
  render(<RiskPage />);
  await userEvent.selectOptions(screen.getByLabelText("high risk action"), "REJECT");
  expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining("/risk/policy"), expect.objectContaining({ method: "PATCH" }));
});

test("viewer can see risk policy but cannot edit it", () => {
  authRole = "viewer";
  queryValues["/risk/overview"] = { low: 0, medium: 0, high: 0, critical: 0 };
  queryValues["/risk/assessments?page=1&page_size=20"] = { items: [], page: 1, page_size: 20, total: 0, total_pages: 0 };
  queryValues["/risk/policy"] = riskPolicy;
  render(<RiskPage />);
  expect(screen.getByLabelText("high risk action")).toBeDisabled();
  expect(screen.getByText(/cannot change it/)).toBeInTheDocument();
});

test("risk level and final decision badges display", () => {
  queryValues["/risk/assessments/item-id"] = riskAssessment;
  render(<RiskDetailPage />);
  expect(screen.getByText("HIGH RISK")).toBeVisible();
  expect(screen.getByText("PENDING")).toBeVisible();
});

test("empty risk response does not show another organization data", () => {
  queryValues["/risk/overview"] = { low: 0, medium: 0, high: 0, critical: 0 };
  queryValues["/risk/assessments?page=1&page_size=20"] = { items: [], page: 1, page_size: 20, total: 0, total_pages: 0 };
  queryValues["/risk/policy"] = riskPolicy;
  render(<RiskPage />);
  expect(screen.getByText("No risk assessments yet.")).toBeInTheDocument();
  expect(screen.queryByText("Travel Assistant")).not.toBeInTheDocument();
});

test("pending authorization page shows high-risk warning", () => {
  queryValues["/authorization-requests/item-id"] = {
    id: "item-id", request_id: approved.request_id, user_id: user.id, agent_id: agent.id,
    agent_identifier: agent.agent_identifier, agent_name: agent.name, permission_id: permission.id,
    action: "purchase", resource: "flight", amount: "2800", currency: "USD", status: "PENDING",
    reason: "Manual approval required", created_at: notification.created_at,
    expires_at: "2026-09-14T10:05:00Z", decided_at: null,
    risk_score: 72, risk_level: "HIGH", risk_recommendation: "REQUIRE_APPROVAL",
    risk_reasons: riskAssessment.reasons,
  };
  render(<AuthorizationRequestPage />);
  expect(screen.getByText("HIGH RISK · 72/100")).toBeInTheDocument();
  expect(screen.getByText("High request frequency")).toBeInTheDocument();
});
