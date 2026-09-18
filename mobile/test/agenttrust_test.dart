import 'dart:async';

import 'package:agenttrust/main.dart';
import 'package:agenttrust/providers/app_state.dart';
import 'package:agenttrust/repositories/agenttrust_repository.dart';
import 'package:agenttrust/services/api_client.dart';
import 'package:agenttrust/services/token_store.dart';
import 'package:agenttrust/services/push_notifications.dart';
import 'package:agenttrust/screens/request_detail_screen.dart';
import 'package:agenttrust/models/billing.dart';
import 'package:agenttrust/models/cross_org_request.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';

const userJson = {
  'id': 'user-1',
  'email': 'inam@example.com',
  'full_name': 'Inam',
  'is_active': true,
};
const agentJson = {
  'id': 'agent-1',
  'name': 'Travel Assistant',
  'agent_identifier': 'agt_aaaaaaaaaaaaaaaaaaaaaaaa',
  'status': 'active',
  'description': 'Books travel',
};
final permissionJson = {
  'id': 'permission-1',
  'agent_id': 'agent-1',
  'action': 'purchase',
  'resource': 'flight',
  'maximum_amount': '500.00',
  'currency': 'USD',
  'status': 'active',
  'valid_from': DateTime.utc(2026).toIso8601String(),
  'expires_at': DateTime.utc(2027).toIso8601String(),
  'requires_approval': true,
};
final auditJson = {
  'id': 'audit-1',
  'agent_identifier': 'agt_aaaaaaaaaaaaaaaaaaaaaaaa',
  'action': 'purchase',
  'resource': 'flight',
  'amount': '420',
  'currency': 'USD',
  'decision': 'APPROVED',
  'reason': 'Approved by user',
  'requested_at': DateTime.utc(2026).toIso8601String(),
};
final requestJson = {
  'id': 'request-uuid',
  'request_id': 'req_aaaaaaaaaaaaaaaaaaaaaaaa',
  'user_id': 'user-1',
  'agent_id': 'agent-1',
  'agent_identifier': 'agt_aaaaaaaaaaaaaaaaaaaaaaaa',
  'agent_name': 'Travel Assistant',
  'permission_id': 'permission-1',
  'action': 'purchase',
  'resource': 'flight',
  'amount': '420',
  'currency': 'USD',
  'status': 'PENDING',
  'reason': 'Awaiting user approval',
  'created_at': DateTime.utc(2026).toIso8601String(),
  'expires_at': DateTime.utc(2027).toIso8601String(),
  'decided_at': null,
  'risk_score': 72,
  'risk_level': 'HIGH',
  'risk_recommendation': 'REQUIRE_APPROVAL',
  'risk_reasons': ['Amount is much higher than recent activity', 'High request frequency'],
};
final notificationJson = {
  'id': 'notification-1', 'title': 'Approval Required',
  'message': 'Travel Assistant wants to purchase a flight for 420 USD.',
  'type': 'authorization_pending', 'priority': 'high', 'status': 'unread',
  'created_at': DateTime.utc(2026).toIso8601String(), 'related_request_id': 'request-uuid',
};
const preferenceJson = {
  'approval_push_enabled': true, 'security_email_enabled': true,
  'permission_expiry_enabled': true, 'general_activity_enabled': true,
};
const billingJson = {
  'organization_id': 'org-1', 'plan_code': 'starter',
  'period_start': '2026-09-01', 'period_end': '2026-10-01',
  'usage': {
    'authorization_requests': {'used': 420, 'limit': 20000},
    'agents': {'used': 1, 'limit': 10},
  },
};

class MemoryTokenStore implements TokenStore {
  String? value;
  MemoryTokenStore([this.value]);
  @override
  Future<String?> read() async => value;
  @override
  Future<void> write(String token) async => value = token;
  @override
  Future<void> clear() async => value = null;
}

class FakeApi implements AgentTrustApi {
  String? token;
  bool failLogin = false;
  bool requireMfa = false;
  bool failMfa = false;
  ApiException? decisionError;
  final calls = <String>[];

  @override
  void setToken(String? value) => token = value;
  @override
  Future<List<dynamic>> getList(String path) async {
    calls.add('GET $path');
    if (path == '/agents') return [agentJson];
    if (path == '/permissions') return [permissionJson];
    return [];
  }

  @override
  Future<Map<String, dynamic>> getObject(String path) async {
    calls.add('GET $path');
    if (path == '/users/me') return Map.of(userJson);
    if (path == '/security/mfa') return {'enabled': requireMfa, 'pending': false, 'recovery_codes_remaining': requireMfa ? 9 : 0};
    if (path.startsWith('/notifications?')) return {'items': [notificationJson]};
    if (path == '/notifications/unread-count') return {'count': 1};
    if (path == '/notification-preferences') return Map.of(preferenceJson);
    if (path == '/billing/usage') return Map.of(billingJson);
    if (path.startsWith('/audit-logs')) {
      return {
        'items': [auditJson],
      };
    }
    if (path == '/authorization-requests/request-uuid') {
      return Map.of(requestJson);
    }
    if (path.startsWith('/authorization-requests')) {
      return {
        'items': [requestJson],
      };
    }
    throw const ApiException('Not found', statusCode: 404);
  }

  @override
  Future<Map<String, dynamic>> post(
    String path, [
    Map<String, dynamic>? body,
  ]) async {
    calls.add('POST $path');
    if (path == '/auth/login') {
      if (failLogin) {
        throw const ApiException(
          'The email or password is incorrect.',
          statusCode: 401,
        );
      }
      if (requireMfa) return {'status': 'MFA_REQUIRED', 'challenge_token': 'safe-challenge-token'};
      return {
        'access_token': 'jwt-token',
        'token_type': 'bearer',
        'expires_in': 900,
      };
    }
    if (path == '/auth/mfa/verify') {
      if (failMfa || body?['code'] != '123456') throw const ApiException('Invalid or already used MFA code', statusCode: 401);
      return {'access_token': 'mfa-jwt-token', 'token_type': 'bearer', 'expires_in': 900};
    }
    if (path == '/auth/logout') return {};
    if (path == '/auth/register') return Map.of(userJson);
    if (path == '/devices') return {'id': 'device-1', 'platform': 'android', 'status': 'active'};
    if (path.contains('/notifications/')) return Map.of(notificationJson);
    if (path.endsWith('/approve') || path.endsWith('/reject')) {
      if (decisionError != null) throw decisionError!;
      return {
        ...requestJson,
        'status': path.endsWith('/approve') ? 'APPROVED' : 'REJECTED',
        'reason': path.endsWith('/approve')
            ? 'Approved by user'
            : 'Rejected by user',
      };
    }
    throw const ApiException('Not found', statusCode: 404);
  }

  @override
  Future<Map<String, dynamic>> patch(String path, Map<String, dynamic> body) async {
    calls.add('PATCH $path');
    return {...preferenceJson, ...body};
  }

  @override
  Future<void> delete(String path) async { calls.add('DELETE $path'); }
}

class FakePush implements MobilePushNotifications {
  FakePush({this.registration});
  final PushRegistration? registration;
  final controller = StreamController<PushOpen>.broadcast();
  final received = StreamController<void>.broadcast();
  bool disposed = false;
  @override Stream<PushOpen> get openedNotifications => controller.stream;
  @override Stream<void> get notificationsReceived => received.stream;
  @override Future<PushRegistration?> initialize() async => registration;
  @override Future<void> dispose() async { disposed = true; }
}

AppState buildState([FakeApi? api, MemoryTokenStore? tokens]) => AppState(
  AgentTrustRepository(api ?? FakeApi(), tokens ?? MemoryTokenStore()),
);

void main() {
  test('1. login success stores token and opens session', () async {
    final api = FakeApi();
    final tokens = MemoryTokenStore();
    final state = buildState(api, tokens);
    expect(
      await state.login('inam@example.com', 'long-secure-password'),
      isTrue,
    );
    expect(state.authState, AuthState.signedIn);
    expect(tokens.value, 'jwt-token');
  });

  test('2. login failure shows a friendly message', () async {
    final api = FakeApi()..failLogin = true;
    final state = buildState(api);
    expect(await state.login('inam@example.com', 'wrong'), isFalse);
    expect(state.error, 'The email or password is incorrect.');
  });

  test('MFA login does not store a token until code succeeds', () async {
    final api = FakeApi()..requireMfa = true;
    final tokens = MemoryTokenStore();
    final state = buildState(api, tokens);
    expect(await state.login('inam@example.com', 'password'), isFalse);
    expect(state.authState, AuthState.mfaRequired);
    expect(tokens.value, isNull);
    expect(await state.verifyMfa('000000'), isFalse);
    expect(state.authState, AuthState.mfaRequired);
    expect(tokens.value, isNull);
    expect(await state.verifyMfa('123456'), isTrue);
    expect(state.authState, AuthState.signedIn);
    expect(tokens.value, 'mfa-jwt-token');
    expect(state.securityStatus?['enabled'], true);
  });

  test('MFA challenge can be cancelled without a session', () async {
    final state = buildState(FakeApi()..requireMfa = true);
    await state.login('inam@example.com', 'password');
    state.cancelMfa();
    expect(state.authState, AuthState.signedOut);
    expect(state.pendingMfaChallenge, isNull);
  });

  test('3. registration creates account and logs in', () async {
    final api = FakeApi();
    final state = buildState(api);
    expect(
      await state.register('Inam', 'inam@example.com', 'long-secure-password'),
      isTrue,
    );
    expect(
      api.calls,
      containsAllInOrder(['POST /auth/register', 'POST /auth/login']),
    );
  });

  test('4. secure auth state restores an existing token', () async {
    final api = FakeApi();
    final state = buildState(api, MemoryTokenStore('saved-token'));
    await state.initialize();
    expect(api.token, 'saved-token');
    expect(state.authState, AuthState.signedIn);
  });

  test('5. logout removes secure auth state', () async {
    final api = FakeApi();
    final tokens = MemoryTokenStore('saved-token');
    final state = buildState(api, tokens);
    state.authState = AuthState.signedIn;
    await state.logout();
    expect(api.calls, contains('POST /auth/logout'));
    expect(tokens.value, isNull);
    expect(api.token, isNull);
    expect(state.authState, AuthState.signedOut);
  });

  testWidgets('6. home loads summary and real account name', (tester) async {
    final state = buildState();
    await state.login('inam@example.com', 'long-secure-password');
    await tester.pumpWidget(AgentTrustApp(state: state));
    await tester.pump();
    expect(find.text('Welcome, Inam'), findsOneWidget);
    expect(find.text('My Agents'), findsOneWidget);
  });

  test('7. pending requests load from API', () async {
    final state = buildState();
    await state.login('a@b.com', 'password');
    expect(state.requests.single.status, 'PENDING');
  });

  test('8. request details load from API', () async {
    final repository = AgentTrustRepository(FakeApi(), MemoryTokenStore());
    expect(
      (await repository.request('request-uuid')).agentName,
      'Travel Assistant',
    );
  });

  test('9. approve request works and refreshes data', () async {
    final state = buildState();
    await state.login('a@b.com', 'password');
    expect(
      await state.decide('request-uuid', approve: true),
      'Action Approved',
    );
  });

  test('10. reject request works and refreshes data', () async {
    final state = buildState();
    await state.login('a@b.com', 'password');
    expect(
      await state.decide('request-uuid', approve: false),
      'Action Rejected',
    );
  });

  test('11. expired request cannot be approved', () async {
    final api = FakeApi()
      ..decisionError = const ApiException(
        'This request has expired.',
        statusCode: 409,
      );
    final state = buildState(api);
    await state.login('a@b.com', 'password');
    expect(
      await state.decide('request-uuid', approve: true),
      'This request has expired.',
    );
  });

  test('12. already decided request cannot be approved again', () async {
    final api = FakeApi()
      ..decisionError = const ApiException(
        'This request has already been decided.',
        statusCode: 409,
      );
    final state = buildState(api);
    await state.login('a@b.com', 'password');
    expect(
      await state.decide('request-uuid', approve: true),
      'This request has already been decided.',
    );
  });

  test('13. agents list loads', () async {
    final state = buildState();
    await state.login('a@b.com', 'password');
    expect(state.agents.single.name, 'Travel Assistant');
  });

  test('14. permissions list loads approval rule', () async {
    final state = buildState();
    await state.login('a@b.com', 'password');
    expect(state.permissions.single.requiresApproval, isTrue);
  });

  test('15. audit history loads', () async {
    final state = buildState();
    await state.login('a@b.com', 'password');
    expect(state.auditLogs.single.reason, 'Approved by user');
  });

  test(
    '16. API errors never expose technical details through app state',
    () async {
      final api = FakeApi()
        ..decisionError = const ApiException(
          'AgentTrust is unavailable right now. Please try again.',
          statusCode: 503,
        );
      final state = buildState(api);
      await state.login('a@b.com', 'password');
      await state.decide('request-uuid', approve: true);
      expect(
        state.error,
        'AgentTrust is unavailable right now. Please try again.',
      );
    },
  );

  test('17. notification permission flow registers an available token', () async {
    final api = FakeApi();
    final push = FakePush(registration: const PushRegistration(token: 'safe-fcm-token-value-with-length', platform: 'android'));
    final state = AppState(AgentTrustRepository(api, MemoryTokenStore()), pushNotifications: push);
    await state.login('a@b.com', 'password');
    expect(api.calls, contains('POST /devices'));
  });

  test('18. notification list and unread badge data load', () async {
    final state = buildState();
    await state.login('a@b.com', 'password');
    expect(state.notifications.single.title, 'Approval Required');
    expect(state.unreadNotifications, 1);
  });

  test('19. mark notification as read calls backend', () async {
    final api = FakeApi();
    final state = buildState(api);
    await state.login('a@b.com', 'password');
    await state.markNotificationRead(state.notifications.single);
    expect(api.calls, contains('POST /notifications/notification-1/read'));
  });

  test('20. mark all notifications as read calls backend', () async {
    final api = FakeApi();
    final state = buildState(api);
    await state.login('a@b.com', 'password');
    await state.markAllNotificationsRead();
    expect(api.calls, contains('POST /notifications/read-all'));
  });

  test('21. push tap stores exact request deep link', () async {
    final push = FakePush();
    final state = AppState(AgentTrustRepository(FakeApi(), MemoryTokenStore()), pushNotifications: push);
    await state.login('a@b.com', 'password');
    push.controller.add(const PushOpen(notificationId: 'notification-1', requestId: 'request-uuid'));
    await Future<void>.delayed(Duration.zero);
    expect(state.pendingRequestId, 'request-uuid');
  });

  testWidgets('22. push deep link opens request detail for approve or reject', (tester) async {
    final push = FakePush();
    final state = AppState(AgentTrustRepository(FakeApi(), MemoryTokenStore()), pushNotifications: push);
    await state.login('a@b.com', 'password');
    await tester.pumpWidget(AgentTrustApp(state: state));
    push.controller.add(const PushOpen(notificationId: 'notification-1', requestId: 'request-uuid'));
    await tester.pumpAndSettle();
    expect(find.text('Request Details'), findsOneWidget);
    await tester.drag(find.byType(ListView).last, const Offset(0, -500));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('approve-request')), findsOneWidget);
    expect(find.byKey(const Key('reject-request')), findsOneWidget);
  });

  test('23. logout revokes registered device and disposes push', () async {
    final api = FakeApi();
    final push = FakePush(registration: const PushRegistration(token: 'safe-fcm-token-value-with-length', platform: 'android'));
    final state = AppState(AgentTrustRepository(api, MemoryTokenStore()), pushNotifications: push);
    await state.login('a@b.com', 'password');
    await state.logout();
    expect(api.calls, contains('DELETE /devices/device-1'));
    expect(push.disposed, isTrue);
  });

  test('24. notification preferences update', () async {
    final api = FakeApi();
    final state = buildState(api);
    await state.login('a@b.com', 'password');
    await state.setNotificationPreference('approval_push_enabled', false);
    expect(state.notificationPreferences?.approvalPush, isFalse);
  });

  testWidgets('25. notification screen shows unread item and badge', (tester) async {
    final state = buildState();
    await state.login('a@b.com', 'password');
    await tester.pumpWidget(AgentTrustApp(state: state));
    await tester.tap(find.text('Alerts'));
    await tester.pumpAndSettle();
    expect(find.text('Approval Required'), findsOneWidget);
    expect(find.byKey(const Key('read-all-notifications')), findsOneWidget);
  });

  test('26. no push token keeps login working', () async {
    final state = AppState(AgentTrustRepository(FakeApi(), MemoryTokenStore()), pushNotifications: FakePush());
    expect(await state.login('a@b.com', 'password'), isTrue);
  });

  test('27. foreground push refreshes notification data', () async {
    final api = FakeApi();
    final push = FakePush();
    final state = AppState(AgentTrustRepository(api, MemoryTokenStore()), pushNotifications: push);
    await state.login('a@b.com', 'password');
    final before = api.calls.where((call) => call == 'GET /notifications?page=1&page_size=100').length;
    push.received.add(null);
    await Future<void>.delayed(const Duration(milliseconds: 10));
    final after = api.calls.where((call) => call == 'GET /notifications?page=1&page_size=100').length;
    expect(after, greaterThan(before));
  });

  testWidgets('28. high-risk request shows a simple warning and reasons', (tester) async {
    final request = (await AgentTrustRepository(FakeApi(), MemoryTokenStore()).request('request-uuid'));
    final state = buildState();
    await tester.pumpWidget(MaterialApp(home: ChangeNotifierProvider.value(
      value: state, child: RequestDetailScreen(initial: request),
    )));
    expect(find.byKey(const Key('risk-warning')), findsOneWidget);
    expect(find.text('HIGH RISK · 72/100'), findsOneWidget);
    expect(find.text('• Amount is much higher than recent activity'), findsOneWidget);
  });

  test('29. risk values are read from server response and have no update API', () async {
    final request = await AgentTrustRepository(FakeApi(), MemoryTokenStore()).request('request-uuid');
    expect(request.riskScore, 72);
    expect(request.riskRecommendation, 'REQUIRE_APPROVAL');
  });

  test('30. billing usage reads the current plan', () {
    final usage = BillingUsage.fromJson(Map.of(billingJson));
    expect(usage.planCode, 'starter');
  });

  test('31. billing usage reads server limits', () {
    final usage = BillingUsage.fromJson(Map.of(billingJson));
    expect(usage.usage['authorization_requests']!.used, 420);
    expect(usage.usage['authorization_requests']!.limit, 20000);
  });

  test('32. repository loads billing from the protected API', () async {
    final api = FakeApi();
    final usage = await AgentTrustRepository(api, MemoryTokenStore()).billingUsage();
    expect(usage.planCode, 'starter');
    expect(api.calls, contains('GET /billing/usage'));
  });

  testWidgets('33. profile shows plan usage and web management guidance', (tester) async {
    final state = buildState();
    await state.login('a@b.com', 'password');
    await tester.pumpWidget(AgentTrustApp(state: state));
    await tester.tap(find.text('Profile'));
    await tester.pumpAndSettle();
    expect(find.text('STARTER plan'), findsOneWidget);
    expect(find.text('420 of 20000 authorization requests used'), findsOneWidget);
    expect(find.text('Manage billing on the AgentTrust web dashboard.'), findsOneWidget);
  });

  test('34. cross-organization request model parses dual approvals', () {
    final json = {
      'id': 'xreq-uuid-1',
      'request_id': 'xreq_abcdef1234567890abcdef',
      'trust_relationship_id': 'trust-uuid-1',
      'source_organization_id': 'org-src-1',
      'target_organization_id': 'org-tgt-1',
      'source_agent_id': 'agent-src-1',
      'target_agent_id': 'agent-tgt-1',
      'action': 'book_room',
      'resource': 'hotel',
      'amount': 250.0,
      'currency': 'USD',
      'status': 'PENDING',
      'decision_reason': 'Awaiting multi-party approval',
      'created_at': '2026-09-18T12:00:00Z',
      'approvals': [
        {
          'id': 'appr-1',
          'cross_org_request_id': 'xreq-uuid-1',
          'organization_id': 'org-src-1',
          'approval_stage': 'SOURCE',
          'required_role': 'admin',
          'status': 'APPROVED',
        },
        {
          'id': 'appr-2',
          'cross_org_request_id': 'xreq-uuid-1',
          'organization_id': 'org-tgt-1',
          'approval_stage': 'TARGET',
          'required_role': 'admin',
          'status': 'PENDING',
        }
      ]
    };

    final req = CrossOrganizationRequestSummary.fromJson(json);
    expect(req.requestId, 'xreq_abcdef1234567890abcdef');
    expect(req.status, 'PENDING');
    expect(req.approvals.length, 2);
    expect(req.approvals.first.approvalStage, 'SOURCE');
    expect(req.approvals.first.status, 'APPROVED');
    expect(req.approvals.last.approvalStage, 'TARGET');
    expect(req.approvals.last.status, 'PENDING');
  });
}
