class Permission {
  const Permission({
    required this.id,
    required this.agentId,
    required this.action,
    required this.resource,
    required this.status,
    required this.validFrom,
    required this.expiresAt,
    required this.requiresApproval,
    this.maximumAmount,
    this.currency,
  });
  final String id;
  final String agentId;
  final String action;
  final String resource;
  final num? maximumAmount;
  final String? currency;
  final String status;
  final DateTime validFrom;
  final DateTime expiresAt;
  final bool requiresApproval;

  factory Permission.fromJson(Map<String, dynamic> json) => Permission(
    id: json['id'] as String,
    agentId: json['agent_id'] as String,
    action: json['action'] as String,
    resource: json['resource'] as String,
    maximumAmount: num.tryParse(json['maximum_amount']?.toString() ?? ''),
    currency: json['currency'] as String?,
    status: json['status'] as String,
    validFrom: DateTime.parse(json['valid_from'] as String),
    expiresAt: DateTime.parse(json['expires_at'] as String),
    requiresApproval: json['requires_approval'] as bool? ?? false,
  );
}
