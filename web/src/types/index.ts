export type AgentStatus = "active" | "inactive" | "suspended" | "revoked";
export type PermissionStatus = "active" | "expired" | "revoked";
export type Decision = "APPROVED" | "REJECTED" | "PENDING";

export interface User {
  id: string;
  email: string;
  full_name: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export type OrganizationRole = "owner" | "admin" | "developer" | "viewer";

export interface Organization {
  id: string;
  name: string;
  role: OrganizationRole;
  status: "active" | "removed";
  created_at: string;
}

export interface OrganizationMember {
  id: string;
  organization_id: string;
  user_id: string;
  full_name: string;
  email: string;
  role: OrganizationRole;
  status: "active" | "removed";
  joined_at: string;
  created_at: string;
}

export interface Invitation {
  id: string;
  organization_id: string;
  email: string;
  role: OrganizationRole;
  status: "pending" | "accepted" | "expired" | "revoked";
  expires_at: string;
  created_at: string;
  accepted_at: string | null;
  invitation_url: string | null;
}

export interface Agent {
  id: string;
  name: string;
  description: string | null;
  agent_identifier: string;
  owner_id: string;
  organization_id: string | null;
  status: AgentStatus;
  created_at: string;
  updated_at: string;
}

export interface Permission {
  id: string;
  owner_id: string;
  agent_id: string;
  action: string;
  resource: string;
  maximum_amount: string | null;
  currency: string | null;
  valid_from: string;
  expires_at: string;
  status: PermissionStatus;
  created_at: string;
  updated_at: string;
  requires_approval?: boolean;
}

export interface APIKey {
  id: string;
  organization_id: string | null;
  name: string;
  prefix: string;
  environment?: "sandbox" | "production";
  status: "active" | "revoked" | "expired";
  created_at: string;
  last_used_at: string | null;
  expires_at: string | null;
  revoked_at: string | null;
}

export interface CreatedAPIKey extends APIKey {
  api_key: string;
}

export interface DeveloperLog {
  request_id: string;
  status: "APPROVED" | "REJECTED" | "PENDING" | "EXPIRED";
  reason: string;
  agent_id: string;
  action: string;
  resource?: string;
  environment?: "sandbox" | "production";
  api_key_prefix: string;
  created_at: string;
}

export interface AuditLog {
  id: string;
  request_id: string;
  user_id: string;
  agent_id: string | null;
  agent_identifier: string;
  permission_id: string | null;
  action: string;
  resource: string;
  amount: string | null;
  currency: string | null;
  decision: Decision;
  reason: string;
  requested_at: string;
  created_at: string;
}

export interface PaginatedAuditLogs {
  items: AuditLog[];
  page: number;
  page_size: number;
  total: number;
  total_pages: number;
}

export interface AuthorizationResult {
  request_id: string;
  decision: Decision;
  reason: string;
}

export type NotificationType = "authorization_pending" | "authorization_approved" | "authorization_rejected" | "permission_expiring" | "permission_expired" | "agent_suspended" | "agent_revoked" | "api_key_revoked" | "security_alert" | "team_invitation" | "high_risk_approval_required";
export interface Notification {
  id: string; organization_id: string | null; type: NotificationType; title: string;
  message: string; status: "unread" | "read" | "archived";
  priority: "low" | "normal" | "high" | "critical";
  related_request_id: string | null; related_agent_id: string | null;
  related_permission_id: string | null; metadata: Record<string, unknown> | null;
  created_at: string; read_at: string | null;
}
export interface PaginatedNotifications {
  items: Notification[]; page: number; page_size: number; total: number; total_pages: number;
}
export interface NotificationPreferences {
  push_enabled: boolean; email_enabled: boolean; in_app_enabled: boolean;
  security_email_enabled: boolean; approval_push_enabled: boolean;
  approval_email_enabled: boolean; permission_expiry_enabled: boolean;
  general_activity_enabled: boolean; updated_at: string;
}
export interface AuthorizationRequestItem {
  id: string; request_id: string; user_id: string; agent_id: string;
  agent_identifier: string; agent_name: string; permission_id: string;
  action: string; resource: string; amount: string | null; currency: string | null;
  status: "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED";
  reason: string; created_at: string; expires_at: string; decided_at: string | null;
  risk_score?: number | null; risk_level?: RiskLevel | null;
  risk_recommendation?: RiskAction | null; risk_reasons?: string[];
}

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type RiskAction = "ALLOW" | "REQUIRE_APPROVAL" | "REJECT";
export interface RiskAssessment {
  id: string; request_id: string; agent_id: string; agent_identifier: string; agent_name: string;
  action: string; resource: string; amount: string | null; currency: string | null;
  risk_score: number; risk_level: RiskLevel; recommendation: RiskAction;
  reasons: string[]; final_status: string; model_version: string; created_at: string;
}
export interface PaginatedRiskAssessments {
  items: RiskAssessment[]; page: number; page_size: number; total: number; total_pages: number;
}
export interface RiskOverview { low: number; medium: number; high: number; critical: number }
export interface RiskPolicy {
  id: string; organization_id: string | null; enabled: boolean;
  medium_action: RiskAction; high_action: RiskAction; critical_action: RiskAction;
  amount_anomaly_enabled: boolean; velocity_enabled: boolean; rejection_history_enabled: boolean;
  created_at: string; updated_at: string;
}

export interface BillingPlan {
  id: string; code: string; name: string; description: string;
  monthly_price: string | null; yearly_price: string | null; currency: string;
  max_organizations: number | null; max_members: number | null; max_agents: number | null;
  max_api_keys: number | null; max_authorization_requests_monthly: number | null;
  max_webhooks: number | null; risk_engine_enabled: boolean; advanced_risk_controls: boolean;
  advanced_notifications_enabled: boolean; priority_support: boolean;
}
export interface BillingSubscription {
  organization_id: string; plan: BillingPlan; status: string;
  current_period_start: string; current_period_end: string; cancel_at_period_end: boolean;
  trial_ends_at: string | null; grace_ends_at: string | null;
}
export interface BillingUsageItem { used: number; limit: number | null }
export interface BillingUsage {
  organization_id: string; plan_code: string; period_start: string; period_end: string;
  usage: Record<string, BillingUsageItem>;
}

export interface AgentDelegation {
  id: string;
  delegation_id: string;
  organization_id: string;
  parent_agent_id: string;
  child_agent_id: string;
  parent_permission_id: string;
  parent_delegation_id: string | null;
  action: string;
  resource: string;
  maximum_amount: string | null;
  currency: string | null;
  requires_approval: boolean;
  allow_delegation: boolean;
  depth: number;
  status: "active" | "revoked" | "expired";
  created_at: string;
  expires_at: string;
  revoked_at: string | null;
  revocation_reason: string | null;
}

export interface DelegationChainNode {
  depth: number;
  delegation_id: string | null;
  agent_id: string;
  agent_name: string;
  action: string;
  resource: string;
  maximum_amount: string | null;
  currency: string | null;
  requires_approval: boolean;
  allow_delegation: boolean;
  status: string;
  expires_at: string;
}

export interface DelegationChainResponse {
  delegation_id: string;
  is_valid: boolean;
  invalid_reason: string | null;
  effective_action: string;
  effective_resource: string;
  effective_maximum_amount: string | null;
  effective_currency: string | null;
  effective_requires_approval: boolean;
  effective_expires_at: string;
  chain: DelegationChainNode[];
}

export type TrustStatus = "pending" | "active" | "rejected" | "revoked" | "expired";
export type ApprovalStage = "SOURCE" | "TARGET" | "BOTH";
export type CrossOrgRequestStatus = "APPROVED" | "REJECTED" | "PENDING";

export interface OrganizationTrustPolicy {
  allowed_actions?: string[];
  allowed_resources?: string[];
  max_amount_per_request?: number | null;
  currency?: string | null;
  daily_spend_limit?: number | null;
  approval_stage?: ApprovalStage;
  ip_allowlist?: string[];
  custom_conditions?: Record<string, unknown>;
}

export interface OrganizationTrustRelationship {
  id: string;
  source_organization_id: string;
  target_organization_id: string;
  status: TrustStatus;
  notes: string | null;
  created_at: string;
  updated_at: string;
  established_at: string | null;
  revoked_at: string | null;
  revoked_by_user_id: string | null;
  revocation_reason: string | null;
  expires_at: string | null;
  source_policy?: OrganizationTrustPolicy;
  target_policy?: OrganizationTrustPolicy;
  agreed_policy?: OrganizationTrustPolicy;
}

export interface OrganizationPublicProfile {
  id: string;
  organization_id: string;
  display_name: string;
  description: string | null;
  is_verified: boolean;
  contact_email: string | null;
  website_url: string | null;
  capabilities: string[];
  published_at: string;
}

export interface CrossOrganizationApproval {
  id: string;
  cross_org_request_id: string;
  organization_id: string;
  approval_stage: "SOURCE" | "TARGET";
  required_role: string;
  status: "PENDING" | "APPROVED" | "REJECTED";
  decided_by_user_id: string | null;
  decided_at: string | null;
  reason: string | null;
}

export interface CrossOrganizationRequest {
  id: string;
  request_id: string;
  trust_relationship_id: string;
  connection_id: string | null;
  source_organization_id: string;
  target_organization_id: string;
  source_agent_id: string;
  target_agent_id: string;
  action: string;
  resource: string;
  amount: number | null;
  currency: string | null;
  status: CrossOrgRequestStatus;
  decision_reason: string | null;
  created_at: string;
  completed_at: string | null;
  approvals?: CrossOrganizationApproval[];
}

export interface AgentEndpoint {
  id: string;
  organization_id: string;
  agent_id: string;
  endpoint_url: string;
  status: "PENDING" | "VERIFIED" | "DISABLED";
  verification_token: string;
  verified_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface AgentCapability {
  id: string;
  organization_id: string;
  agent_id: string;
  name: string;
  version: string;
  description: string | null;
  input_schema?: Record<string, unknown> | null;
  output_schema?: Record<string, unknown> | null;
  is_active: boolean;
  created_at: string;
}

export interface ATPMessageRecord {
  id: string;
  message_id: string;
  atp_version: string;
  message_type: string;
  source_organization_id: string;
  source_agent_id: string;
  target_organization_id: string;
  target_agent_id: string;
  capability: string;
  status: "PENDING" | "DELIVERING" | "DELIVERED" | "RETRYING" | "FAILED" | "PENDING_APPROVAL";
  decision_reason: string | null;
  attestation_id: string | null;
  created_at: string;
  completed_at: string | null;
}

export interface ATPMessageDelivery {
  id: string;
  message_id: string;
  target_endpoint_id: string | null;
  status: string;
  attempt_count: number;
  last_attempt_at: string | null;
  completed_at: string | null;
  http_status: number | null;
  response_payload?: Record<string, unknown> | null;
  error_message?: string | null;
}

export interface GatewayIdentity {
  issuer: string;
  key_id: string;
  algorithm: string;
  public_key_base64: string;
  public_key_pem: string;
  attestation_ttl_seconds: number;
}

