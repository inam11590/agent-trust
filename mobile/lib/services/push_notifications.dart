import 'dart:async';

class PushRegistration {
  const PushRegistration({required this.token, required this.platform, this.deviceName});
  final String token;
  final String platform;
  final String? deviceName;
}

class PushOpen {
  const PushOpen({required this.notificationId, required this.requestId});
  final String notificationId;
  final String requestId;
}

abstract class MobilePushNotifications {
  Stream<PushOpen> get openedNotifications;
  Stream<void> get notificationsReceived;
  Future<PushRegistration?> initialize();
  Future<void> dispose();
}

/// Safe fallback used until Firebase configuration is supplied for this build.
class DisabledMobilePushNotifications implements MobilePushNotifications {
  const DisabledMobilePushNotifications();
  @override
  Stream<PushOpen> get openedNotifications => const Stream.empty();
  @override
  Stream<void> get notificationsReceived => const Stream.empty();
  @override
  Future<PushRegistration?> initialize() async => null;
  @override
  Future<void> dispose() async {}
}
