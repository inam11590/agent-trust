export type AgentStatus =
  | "draft"
  | "registered"
  | "review_required"
  | "approved"
  | "active"
  | "suspended"
  | "retirement_pending"
  | "retired"
  | "inactive"
  | "revoked";

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
  environment?: string;
  created_at: string;
  updated_at: string;
  // Step 28: Governance Attributes
  owner_type?: string;
  team?: string | null;
  purpose?: string | null;
  business_function?: string | null;
  expected_actions?: string[];
  data_access_description?: string | null;
  risk_classification?: string;
  classification_reasons?: string[];
  business_criticality?: string;
  data_classification?: string;
  source?: string;
  external_reference?: string | null;
  tags?: string[];
  last_activity_at?: string | null;
  last_reviewed_at?: string | null;
  next_review_due_at?: string | null;
  certified_until?: string | null;
  certification_status?: string;
}

export interface AgentCertification {
  id: string;
  certification_id: string;
  organization_id: string | null;
  agent_id: string;
  status: "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED";
  reviewer_id: string | null;
  requested_at: string;
  due_at: string | null;
  completed_at: string | null;
  decision: string | null;
  notes: string | null;
  snapshot_reference: Record<string, unknown>;
}

export interface AgentOwnershipHistory {
  id: string;
  agent_id: string;
  organization_id: string | null;
  old_owner_type: string;
  old_owner_id: string;
  new_owner_type: string;
  new_owner_id: string;
  changed_by: string | null;
  reason: string;
  changed_at: string;
}

export interface GovernancePolicy {
  organization_id: string;
  periodic_review_days: number;
  expiry_behavior: string;
  dormancy_days: number;
  enforce_separation_of_duties: boolean;
  require_classification_on_promotion: boolean;
  require_purpose_on_promotion: boolean;
}

export interface DependencyGraph {
  root_agent_id: string;
  root_agent_name: string;
  nodes: Array<{
    id: string;
    type: string;
    label: string;
    identifier?: string;
    status?: string;
    risk_classification?: string;
    is_root?: boolean;
  }>;
  edges: Array<{
    source: string;
    target: string;
    relationship: string;
    status?: string;
    actions?: string[];
  }>;
  metrics: {
    total_nodes: number;
    total_edges: number;
    connected_agents_count: number;
    active_credentials_count: number;
    bound_policies_count: number;
    blast_radius_score: number;
  };
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

export interface IssuerSigningKey {
  key_id: string;
  algorithm: string;
  public_key: string;
  fingerprint: string;
  status: "ACTIVE" | "REVOKED" | "ROTATED";
  created_at: string;
  activated_at: string;
  expires_at: string | null;
  revoked_at: string | null;
  rotated_from_key_id: string | null;
}

export interface CredentialIssuer {
  id: string;
  issuer_id: string;
  organization_id: string;
  name: string;
  status: "ACTIVE" | "SUSPENDED" | "REVOKED";
  created_at: string;
  updated_at: string;
  suspended_at: string | null;
  revoked_at: string | null;
  signing_keys?: IssuerSigningKey[];
}

export interface AgentCredential {
  id: string;
  credential_id: string;
  credential_type: "AgentIdentityCredential" | "AgentCapabilityCredential" | string;
  environment: "production" | "sandbox";
  subject_agent_id: string;
  status: "ACTIVE" | "REVOKED" | "EXPIRED" | "SUSPENDED";
  issued_at: string;
  expires_at: string;
  revoked_at: string | null;
  claims: Record<string, unknown>;
  signing_key_id: string;
}

export interface CredentialVerificationResult {
  verified: boolean;
  credential_id: string;
  credential_type: string;
  issuer: string;
  subject_organization_id: string;
  subject_agent_id: string;
  environment: string;
  expires_at: string;
  claims: Record<string, unknown>;
}

export type GatewayDeploymentType = "SELF_HOSTED_GATEWAY" | "SIDECAR" | "CLOUD_GATEWAY";
export type GatewayStatus = "PENDING_ENROLLMENT" | "ACTIVE" | "OFFLINE" | "SUSPENDED" | "REVOKED";
export type GatewayOfflinePolicy = "FAIL_CLOSED" | "LIMITED_OFFLINE";
export type GatewayEnvironment = "PRODUCTION" | "SANDBOX";

export interface EnterpriseGateway {
  id: string;
  organization_id: string;
  name: string;
  deployment_type: GatewayDeploymentType;
  environment: GatewayEnvironment;
  status: GatewayStatus;
  offline_policy: GatewayOfflinePolicy;
  public_key?: string | null;
  public_key_fingerprint?: string | null;
  current_config_version: number;
  last_heartbeat_at?: string | null;
  heartbeat_data?: Record<string, unknown> | null;
  enrolled_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface GatewayRegistrationResult {
  gateway_id: string;
  name: string;
  deployment_type: GatewayDeploymentType;
  environment: GatewayEnvironment;
  status: GatewayStatus;
  enrollment_token: string;
  enrollment_token_expires_at: string;
  enrollment_command: string;
}

export interface GatewayConfigBundle {
  id: string;
  bundle_id: string;
  organization_id: string;
  version: number;
  environment: GatewayEnvironment;
  signing_key_id: string;
  signature: string;
  hash: string;
  payload: Record<string, unknown>;
  published_at: string;
  created_at: string;
}

export interface GatewayHealthData {
  uptime_seconds?: number;
  evaluations_total?: number;
  evaluations_approved?: number;
  evaluations_rejected?: number;
  cached_policies_count?: number;
  clock_skew_ms?: number;
  cpu_percent?: number;
  memory_mb?: number;
}



