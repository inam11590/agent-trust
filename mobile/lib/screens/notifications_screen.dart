import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../models/notification.dart';
import '../providers/app_state.dart';
import '../widgets/common.dart';
import 'request_detail_screen.dart';

class NotificationsTab extends StatelessWidget {
  const NotificationsTab({super.key});
  Future<void> _open(BuildContext context, AppNotification item) async {
    final state = context.read<AppState>();
    await state.markNotificationRead(item);
    if (!context.mounted || item.relatedRequestId == null) return;
    final request = await state.loadRequest(item.relatedRequestId!);
    state.clearPendingRequest();
    if (context.mounted && request != null) {
      await Navigator.push(context, MaterialPageRoute(builder: (_) => RequestDetailScreen(initial: request)));
    }
  }
  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    return RefreshIndicator(
      onRefresh: state.refreshAll,
      child: state.notifications.isEmpty ? ListView(children: const [SizedBox(height: 160), PageMessage('No notifications yet.')]) : ListView(
        key: const Key('notifications-list'), padding: const EdgeInsets.all(16),
        children: [
          Align(alignment: Alignment.centerRight, child: TextButton.icon(key: const Key('read-all-notifications'), onPressed: state.unreadNotifications == 0 ? null : state.markAllNotificationsRead, icon: const Icon(Icons.done_all), label: const Text('Mark all read'))),
          ...state.notifications.map((item) => Card(
            color: item.isUnread ? Theme.of(context).colorScheme.primaryContainer.withValues(alpha: .35) : null,
            child: ListTile(
              leading: Icon(item.type == 'authorization_pending' ? Icons.approval : Icons.notifications_outlined),
              title: Text(item.title, style: TextStyle(fontWeight: item.isUnread ? FontWeight.bold : FontWeight.normal)),
              subtitle: Text('${item.message}\n${formatTime(item.createdAt)}'), isThreeLine: true,
              trailing: item.isUnread ? const Badge() : null, onTap: () => _open(context, item),
            ),
          )),
        ],
      ),
    );
  }
}

class NotificationSettings extends StatelessWidget {
  const NotificationSettings({super.key});
  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final settings = state.notificationPreferences;
    if (settings == null) return const SizedBox.shrink();
    return Card(child: ExpansionTile(
      leading: const Icon(Icons.notifications_outlined), title: const Text('Notifications'),
      children: [
        SwitchListTile(title: const Text('Approval Requests'), value: settings.approvalPush, onChanged: (value) => state.setNotificationPreference('approval_push_enabled', value)),
        SwitchListTile(title: const Text('Security Alerts'), value: settings.securityEmail, onChanged: (value) => state.setNotificationPreference('security_email_enabled', value)),
        SwitchListTile(title: const Text('Permission Expiry'), value: settings.permissionExpiry, onChanged: (value) => state.setNotificationPreference('permission_expiry_enabled', value)),
        SwitchListTile(title: const Text('General Activity'), value: settings.generalActivity, onChanged: (value) => state.setNotificationPreference('general_activity_enabled', value)),
      ],
    ));
  }
}
