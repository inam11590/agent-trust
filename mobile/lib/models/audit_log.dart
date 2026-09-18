class AuditLog {
  const AuditLog({
    required this.id,
    required this.agentIdentifier,
    required this.action,
    required this.resource,
    required this.decision,
    required this.reason,
    required this.requestedAt,
    this.amount,
    this.currency,
  });
  final String id;
  final String agentIdentifier;
  final String action;
  final String resource;
  final num? amount;
  final String? currency;
  final String decision;
  final String reason;
  final DateTime requestedAt;

  factory AuditLog.fromJson(Map<String, dynamic> json) => AuditLog(
    id: json['id'] as String,
    agentIdentifier: json['agent_identifier'] as String,
    action: json['action'] as String,
    resource: json['resource'] as String,
    amount: num.tryParse(json['amount']?.toString() ?? ''),
    currency: json['currency'] as String?,
    decision: json['decision'] as String,
    reason: json['reason'] as String,
    requestedAt: DateTime.parse(json['requested_at'] as String),
  );
}
