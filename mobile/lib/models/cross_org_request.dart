class CrossOrganizationApprovalSummary {
  const CrossOrganizationApprovalSummary({
    required this.id,
    required this.crossOrgRequestId,
    required this.organizationId,
    required this.approvalStage,
    required this.requiredRole,
    required this.status,
    this.decidedByUserId,
    this.decidedAt,
    this.reason,
  });

  final String id;
  final String crossOrgRequestId;
  final String organizationId;
  final String approvalStage;
  final String requiredRole;
  final String status;
  final String? decidedByUserId;
  final DateTime? decidedAt;
  final String? reason;

  factory CrossOrganizationApprovalSummary.fromJson(Map<String, dynamic> json) =>
      CrossOrganizationApprovalSummary(
        id: json['id'] as String,
        crossOrgRequestId: json['cross_org_request_id'] as String,
        organizationId: json['organization_id'] as String,
        approvalStage: json['approval_stage'] as String,
        requiredRole: json['required_role'] as String,
        status: json['status'] as String,
        decidedByUserId: json['decided_by_user_id'] as String?,
        decidedAt: json['decided_at'] == null
            ? null
            : DateTime.parse(json['decided_at'] as String),
        reason: json['reason'] as String?,
      );
}

class CrossOrganizationRequestSummary {
  const CrossOrganizationRequestSummary({
    required this.id,
    required this.requestId,
    required this.trustRelationshipId,
    required this.sourceOrganizationId,
    required this.targetOrganizationId,
    required this.sourceAgentId,
    required this.targetAgentId,
    required this.action,
    required this.resource,
    required this.status,
    required this.createdAt,
    this.amount,
    this.currency,
    this.decisionReason,
    this.completedAt,
    this.approvals = const [],
  });

  final String id;
  final String requestId;
  final String trustRelationshipId;
  final String sourceOrganizationId;
  final String targetOrganizationId;
  final String sourceAgentId;
  final String targetAgentId;
  final String action;
  final String resource;
  final num? amount;
  final String? currency;
  final String status;
  final String? decisionReason;
  final DateTime createdAt;
  final DateTime? completedAt;
  final List<CrossOrganizationApprovalSummary> approvals;

  factory CrossOrganizationRequestSummary.fromJson(Map<String, dynamic> json) =>
      CrossOrganizationRequestSummary(
        id: json['id'] as String,
        requestId: json['request_id'] as String,
        trustRelationshipId: json['trust_relationship_id'] as String,
        sourceOrganizationId: json['source_organization_id'] as String,
        targetOrganizationId: json['target_organization_id'] as String,
        sourceAgentId: json['source_agent_id'] as String,
        targetAgentId: json['target_agent_id'] as String,
        action: json['action'] as String,
        resource: json['resource'] as String,
        amount: num.tryParse(json['amount']?.toString() ?? ''),
        currency: json['currency'] as String?,
        status: json['status'] as String,
        decisionReason: json['decision_reason'] as String?,
        createdAt: DateTime.parse(json['created_at'] as String),
        completedAt: json['completed_at'] == null
            ? null
            : DateTime.parse(json['completed_at'] as String),
        approvals: (json['approvals'] as List<dynamic>? ?? const [])
            .map((v) => CrossOrganizationApprovalSummary.fromJson(v as Map<String, dynamic>))
            .toList(),
      );
}
