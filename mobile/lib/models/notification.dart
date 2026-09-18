class AppNotification {
  const AppNotification({required this.id, required this.title, required this.message, required this.type, required this.priority, required this.status, required this.createdAt, this.relatedRequestId});
  final String id;
  final String title;
  final String message;
  final String type;
  final String priority;
  final String status;
  final DateTime createdAt;
  final String? relatedRequestId;
  bool get isUnread => status == 'unread';
  factory AppNotification.fromJson(Map<String, dynamic> json) => AppNotification(
    id: json['id'] as String, title: json['title'] as String,
    message: json['message'] as String, type: json['type'] as String,
    priority: json['priority'] as String, status: json['status'] as String,
    createdAt: DateTime.parse(json['created_at'] as String),
    relatedRequestId: json['related_request_id'] as String?,
  );
}

class NotificationPreferences {
  const NotificationPreferences({required this.approvalPush, required this.securityEmail, required this.permissionExpiry, required this.generalActivity});
  final bool approvalPush;
  final bool securityEmail;
  final bool permissionExpiry;
  final bool generalActivity;
  factory NotificationPreferences.fromJson(Map<String, dynamic> json) => NotificationPreferences(
    approvalPush: json['approval_push_enabled'] as bool,
    securityEmail: json['security_email_enabled'] as bool,
    permissionExpiry: json['permission_expiry_enabled'] as bool,
    generalActivity: json['general_activity_enabled'] as bool,
  );
}
