import '../models/agent.dart';
import '../models/audit_log.dart';
import '../models/authorization_request.dart';
import '../models/permission.dart';
import '../models/user.dart';
import '../models/notification.dart';
import '../models/billing.dart';
import '../services/api_client.dart';
import '../services/token_store.dart';

class MfaChallengeRequired implements Exception {
  const MfaChallengeRequired(this.challengeToken);
  final String challengeToken;
}

class AgentTrustRepository {
  AgentTrustRepository(this.api, this.tokens);
  final AgentTrustApi api;
  final TokenStore tokens;

  Future<bool> restoreSession() async {
    final token = await tokens.read();
    if (token == null) return false;
    api.setToken(token);
    try {
      await me();
      return true;
    } on ApiException catch (error) {
      if (error.statusCode == 401) {
        await logout();
        return false;
      }
      rethrow;
    }
  }

  Future<User> login(String email, String password) async {
    late final Map<String, dynamic> response;
    try {
      response = await api.post('/auth/login', {
        'email': email,
        'password': password,
      });
    } on ApiException catch (error) {
      if (error.statusCode == 401) {
        throw const ApiException(
          'The email or password is incorrect.',
          statusCode: 401,
        );
      }
      rethrow;
    }
    if (response['status'] == 'MFA_REQUIRED' && response['challenge_token'] is String) {
      throw MfaChallengeRequired(response['challenge_token'] as String);
    }
    final token = response['access_token'] as String;
    await tokens.write(token);
    api.setToken(token);
    return me();
  }

  Future<User> verifyMfa(String challengeToken, String code) async {
    final response = await api.post('/auth/mfa/verify', {
      'challenge_token': challengeToken, 'code': code,
    });
    final token = response['access_token'] as String;
    await tokens.write(token);
    api.setToken(token);
    return me();
  }

  Future<Map<String, dynamic>> securityStatus() => api.getObject('/security/mfa');

  Future<User> register(String name, String email, String password) async {
    await api.post('/auth/register', {
      'full_name': name,
      'email': email,
      'password': password,
    });
    return login(email, password);
  }

  Future<void> logout() async {
    try { await api.post('/auth/logout'); } catch (_) { /* Local sign-out must still complete offline. */ }
    api.setToken(null);
    await tokens.clear();
  }

  Future<User> me() async => User.fromJson(await api.getObject('/users/me'));
  Future<List<Agent>> agents() async =>
      (await api.getList('/agents'))
          .map((item) => Agent.fromJson(item as Map<String, dynamic>))
          .toList();
  Future<List<Permission>> permissions() async =>
      (await api.getList('/permissions'))
          .map((item) => Permission.fromJson(item as Map<String, dynamic>))
          .toList();
  Future<List<AuditLog>> auditLogs() async {
    final response = await api.getObject('/audit-logs?page=1&page_size=100');
    return (response['items'] as List<dynamic>)
        .map((item) => AuditLog.fromJson(item as Map<String, dynamic>))
        .toList();
  }

  Future<List<AuthorizationRequest>> requests({String? status}) async {
    final query = status == null ? '' : '?status=$status';
    final response = await api.getObject('/authorization-requests$query');
    return (response['items'] as List<dynamic>)
        .map(
          (item) => AuthorizationRequest.fromJson(item as Map<String, dynamic>),
        )
        .toList();
  }

  Future<AuthorizationRequest> request(String id) async =>
      AuthorizationRequest.fromJson(
        await api.getObject('/authorization-requests/$id'),
      );
  Future<AuthorizationRequest> approve(String id) async =>
      AuthorizationRequest.fromJson(
        await api.post('/authorization-requests/$id/approve'),
      );
  Future<AuthorizationRequest> reject(String id) async =>
      AuthorizationRequest.fromJson(
        await api.post('/authorization-requests/$id/reject'),
      );
  Future<List<AppNotification>> notifications() async {
    final response = await api.getObject('/notifications?page=1&page_size=100');
    return (response['items'] as List<dynamic>).map((item) => AppNotification.fromJson(item as Map<String, dynamic>)).toList();
  }
  Future<int> unreadCount() async => (await api.getObject('/notifications/unread-count'))['count'] as int;
  Future<void> readNotification(String id) async { await api.post('/notifications/$id/read'); }
  Future<void> readAllNotifications() async { await api.post('/notifications/read-all'); }
  Future<NotificationPreferences> notificationPreferences() async => NotificationPreferences.fromJson(await api.getObject('/notification-preferences'));
  Future<NotificationPreferences> updateNotificationPreferences(Map<String, bool> changes) async => NotificationPreferences.fromJson(await api.patch('/notification-preferences', changes));
  Future<String> registerDevice(String token, String platform, String? name) async => (await api.post('/devices', {'push_token': token, 'platform': platform, 'device_name': name}))['id'] as String;
  Future<void> revokeDevice(String id) async => api.delete('/devices/$id');
  Future<BillingUsage> billingUsage() async => BillingUsage.fromJson(await api.getObject('/billing/usage'));
}
