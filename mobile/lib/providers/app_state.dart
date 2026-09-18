import 'dart:async';

import 'package:flutter/foundation.dart';

import '../models/agent.dart';
import '../models/audit_log.dart';
import '../models/authorization_request.dart';
import '../models/permission.dart';
import '../models/user.dart';
import '../models/notification.dart';
import '../models/billing.dart';
import '../repositories/agenttrust_repository.dart';
import '../services/api_client.dart';
import '../services/push_notifications.dart';

enum AuthState { checking, signedOut, mfaRequired, signedIn }

class AppState extends ChangeNotifier {
  AppState(this.repository, {MobilePushNotifications? pushNotifications})
      : pushNotifications = pushNotifications ?? const DisabledMobilePushNotifications();
  final AgentTrustRepository repository;
  final MobilePushNotifications pushNotifications;
  StreamSubscription<PushOpen>? _pushSubscription;
  StreamSubscription<void>? _foregroundPushSubscription;
  String? _deviceId;
  AuthState authState = AuthState.checking;
  User? user;
  List<Agent> agents = [];
  List<Permission> permissions = [];
  List<AuditLog> auditLogs = [];
  List<AuthorizationRequest> requests = [];
  List<AppNotification> notifications = [];
  NotificationPreferences? notificationPreferences;
  int unreadNotifications = 0;
  BillingUsage? billingUsage;
  String? pendingRequestId;
  String? pendingMfaChallenge;
  Map<String, dynamic>? securityStatus;
  bool loading = false;
  String? error;

  Future<void> initialize() async {
    try {
      if (await repository.restoreSession()) {
        user = await repository.me();
        authState = AuthState.signedIn;
        await refreshAll();
        await _startPush();
      } else {
        authState = AuthState.signedOut;
      }
    } catch (_) {
      authState = AuthState.signedOut;
    }
    notifyListeners();
  }

  Future<bool> login(String email, String password) async =>
      _authenticate(() => repository.login(email.trim(), password));

  Future<bool> register(String name, String email, String password) async =>
      _authenticate(
        () => repository.register(name.trim(), email.trim(), password),
      );

  Future<bool> verifyMfa(String code) async {
    final challenge = pendingMfaChallenge;
    if (challenge == null) return false;
    final success = await _authenticate(() => repository.verifyMfa(challenge, code));
    if (success) pendingMfaChallenge = null;
    return success;
  }

  void cancelMfa() {
    pendingMfaChallenge = null;
    authState = AuthState.signedOut;
    error = null;
    notifyListeners();
  }

  Future<bool> _authenticate(Future<User> Function() action) async {
    loading = true;
    error = null;
    notifyListeners();
    try {
      user = await action();
      authState = AuthState.signedIn;
      await refreshAll();
      await _startPush();
      return true;
    } catch (exception) {
      if (exception is MfaChallengeRequired) {
        pendingMfaChallenge = exception.challengeToken;
        authState = AuthState.mfaRequired;
        return false;
      }
      error = exception is ApiException
          ? exception.message
          : 'Something went wrong. Please try again.';
      return false;
    } finally {
      loading = false;
      notifyListeners();
    }
  }

  Future<void> logout() async {
    if (_deviceId != null) {
      try { await repository.revokeDevice(_deviceId!); } catch (_) {}
    }
    await _pushSubscription?.cancel();
    await _foregroundPushSubscription?.cancel();
    await pushNotifications.dispose();
    await repository.logout();
    user = null;
    agents = [];
    permissions = [];
    auditLogs = [];
    requests = [];
    notifications = [];
    pendingMfaChallenge = null;
    securityStatus = null;
    unreadNotifications = 0;
    authState = AuthState.signedOut;
    notifyListeners();
  }

  Future<void> refreshAll() async {
    error = null;
    try {
      final values = await Future.wait<dynamic>([
        repository.agents(),
        repository.permissions(),
        repository.auditLogs(),
        repository.requests(),
        repository.notifications(),
        repository.unreadCount(),
        repository.notificationPreferences(),
      ]);
      agents = values[0] as List<Agent>;
      permissions = values[1] as List<Permission>;
      auditLogs = values[2] as List<AuditLog>;
      requests = values[3] as List<AuthorizationRequest>;
      notifications = values[4] as List<AppNotification>;
      unreadNotifications = values[5] as int;
      notificationPreferences = values[6] as NotificationPreferences;
      try { billingUsage = await repository.billingUsage(); } on ApiException catch (exception) {
        // Billing requires an organization workspace; mobile remains usable in a personal workspace.
        if (exception.statusCode != 422 && exception.statusCode != 404) rethrow;
        billingUsage = null;
      }
      try { securityStatus = await repository.securityStatus(); } on ApiException catch (exception) {
        if (exception.statusCode != 404) rethrow;
      }
    } on ApiException catch (exception) {
      error = exception.message;
      if (exception.statusCode == 401) await logout();
    }
    notifyListeners();
  }

  Future<AuthorizationRequest?> loadRequest(String id) async {
    try {
      return await repository.request(id);
    } on ApiException catch (exception) {
      error = exception.message;
      notifyListeners();
      return null;
    }
  }

  Future<String> decide(String id, {required bool approve}) async {
    try {
      final result = approve
          ? await repository.approve(id)
          : await repository.reject(id);
      await refreshAll();
      return result.status == 'APPROVED'
          ? 'Action Approved'
          : 'Action Rejected';
    } on ApiException catch (exception) {
      error = exception.message;
      notifyListeners();
      return exception.message;
    }
  }

  Agent? agentById(String id) {
    for (final agent in agents) {
      if (agent.id == id) return agent;
    }
    return null;
  }

  Future<void> _startPush() async {
    await _pushSubscription?.cancel();
    _pushSubscription = pushNotifications.openedNotifications.listen((opened) async {
      try { await repository.readNotification(opened.notificationId); } catch (_) {}
      pendingRequestId = opened.requestId;
      notifyListeners();
    });
    await _foregroundPushSubscription?.cancel();
    _foregroundPushSubscription = pushNotifications.notificationsReceived.listen((_) => refreshAll());
    final registration = await pushNotifications.initialize();
    if (registration != null) {
      _deviceId = await repository.registerDevice(registration.token, registration.platform, registration.deviceName);
    }
  }

  void clearPendingRequest() { pendingRequestId = null; }

  Future<void> markNotificationRead(AppNotification item) async {
    if (item.isUnread) await repository.readNotification(item.id);
    if (item.relatedRequestId != null) pendingRequestId = item.relatedRequestId;
    await refreshAll();
  }

  Future<void> markAllNotificationsRead() async {
    await repository.readAllNotifications();
    await refreshAll();
  }

  Future<void> setNotificationPreference(String key, bool value) async {
    notificationPreferences = await repository.updateNotificationPreferences({key: value});
    notifyListeners();
  }
}
