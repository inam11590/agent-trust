class AuthorizationResult {
  const AuthorizationResult({
    required this.requestId,
    required this.decision,
    required this.reason,
  });
  final String requestId;
  final String decision;
  final String reason;

  factory AuthorizationResult.fromJson(Map<String, dynamic> json) =>
      AuthorizationResult(
        requestId: json['request_id'] as String,
        decision: json['decision'] as String,
        reason: json['reason'] as String,
      );
}
