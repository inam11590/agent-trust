class AuthorizationRequest {
  const AuthorizationRequest({
    required this.id,
    required this.requestId,
    required this.agentId,
    required this.agentIdentifier,
    required this.agentName,
    required this.permissionId,
    required this.action,
    required this.resource,
    required this.status,
    required this.reason,
    required this.createdAt,
    required this.expiresAt,
    this.amount,
    this.currency,
    this.delegationId,
    this.parentAgentId,
    this.decidedAt,
    this.riskScore,
    this.riskLevel,
    this.riskRecommendation,
    this.riskReasons = const [],
  });
  final String id;
  final String requestId;
  final String agentId;
  final String agentIdentifier;
  final String agentName;
  final String permissionId;
  final String? delegationId;
  final String? parentAgentId;
  final String action;
  final String resource;
  final num? amount;
  final String? currency;
  final String status;
  final String reason;
  final DateTime createdAt;
  final DateTime expiresAt;
  final DateTime? decidedAt;
  final int? riskScore;
  final String? riskLevel;
  final String? riskRecommendation;
  final List<String> riskReasons;

  factory AuthorizationRequest.fromJson(Map<String, dynamic> json) =>
      AuthorizationRequest(
        id: json['id'] as String,
        requestId: json['request_id'] as String,
        agentId: json['agent_id'] as String,
        agentIdentifier: json['agent_identifier'] as String,
        agentName: json['agent_name'] as String,
        permissionId: json['permission_id'] as String,
        delegationId: json['delegation_id'] as String?,
        parentAgentId: json['parent_agent_id'] as String?,
        action: json['action'] as String,
        resource: json['resource'] as String,
        amount: num.tryParse(json['amount']?.toString() ?? ''),
        currency: json['currency'] as String?,
        status: json['status'] as String,
        reason: json['reason'] as String,
        createdAt: DateTime.parse(json['created_at'] as String),
        expiresAt: DateTime.parse(json['expires_at'] as String),
        decidedAt: json['decided_at'] == null
            ? null
            : DateTime.parse(json['decided_at'] as String),
        riskScore: json['risk_score'] as int?,
        riskLevel: json['risk_level'] as String?,
        riskRecommendation: json['risk_recommendation'] as String?,
        riskReasons: (json['risk_reasons'] as List<dynamic>? ?? const [])
            .map((value) => value.toString()).toList(),
      );
}
