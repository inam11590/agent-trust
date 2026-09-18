import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../models/agent.dart';
import '../models/permission.dart';
import '../providers/app_state.dart';
import '../widgets/common.dart';
import 'request_detail_screen.dart';
import 'notifications_screen.dart';

class HomeShell extends StatefulWidget {
  const HomeShell({super.key});
  @override
  State<HomeShell> createState() => _HomeShellState();
}

class _HomeShellState extends State<HomeShell> {
  int index = 0;
  static const titles = [
    'Home',
    'Requests',
    'My Agents',
    'Permissions',
    'Notifications',
    'Profile',
  ];
  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final pendingId = state.pendingRequestId;
    if (pendingId != null) {
      WidgetsBinding.instance.addPostFrameCallback((_) async {
        state.clearPendingRequest();
        final request = await state.loadRequest(pendingId);
        if (mounted && request != null) await Navigator.of(this.context).push(MaterialPageRoute(builder: (_) => RequestDetailScreen(initial: request)));
      });
    }
    final pages = [
      const HomeTab(),
      const RequestsTab(),
      const AgentsTab(),
      const PermissionsTab(),
      const NotificationsTab(),
      const ProfileTab(),
    ];
    return Scaffold(
      appBar: AppBar(
        title: Text(titles[index]),
        actions: [
          IconButton(
            tooltip: 'Refresh',
            onPressed: () => context.read<AppState>().refreshAll(),
            icon: const Icon(Icons.refresh),
          ),
        ],
      ),
      body: IndexedStack(index: index, children: pages),
      bottomNavigationBar: NavigationBar(
        selectedIndex: index,
        onDestinationSelected: (value) => setState(() => index = value),
        destinations: [
          const NavigationDestination(
            icon: Icon(Icons.home_outlined),
            selectedIcon: Icon(Icons.home),
            label: 'Home',
          ),
          const NavigationDestination(
            icon: Icon(Icons.approval_outlined),
            selectedIcon: Icon(Icons.approval),
            label: 'Requests',
          ),
          const NavigationDestination(
            icon: Icon(Icons.smart_toy_outlined),
            selectedIcon: Icon(Icons.smart_toy),
            label: 'Agents',
          ),
          const NavigationDestination(
            icon: Icon(Icons.key_outlined),
            selectedIcon: Icon(Icons.key),
            label: 'Permissions',
          ),
          NavigationDestination(
            icon: Badge(isLabelVisible: state.unreadNotifications > 0, label: Text('${state.unreadNotifications}'), child: const Icon(Icons.notifications_outlined)),
            selectedIcon: const Icon(Icons.notifications),
            label: 'Alerts',
          ),
          const NavigationDestination(
            icon: Icon(Icons.person_outline),
            selectedIcon: Icon(Icons.person),
            label: 'Profile',
          ),
        ],
      ),
    );
  }
}

class HomeTab extends StatelessWidget {
  const HomeTab({super.key});
  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final active = state.permissions.where((p) => p.status == 'active').length;
    final approved = state.auditLogs
        .where((a) => a.decision == 'APPROVED')
        .length;
    final rejected = state.auditLogs
        .where((a) => a.decision == 'REJECTED')
        .length;
    return RefreshIndicator(
      onRefresh: state.refreshAll,
      child: ListView(
        key: const Key('home-list'),
        padding: const EdgeInsets.all(16),
        children: [
          Text(
            'Welcome, ${state.user?.fullName ?? ''}',
            style: Theme.of(context).textTheme.headlineSmall
                ?.copyWith(fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 16),
          GridView.count(
            crossAxisCount: MediaQuery.sizeOf(context).width >= 600 ? 4 : 2,
            childAspectRatio: 1.55,
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            mainAxisSpacing: 10,
            crossAxisSpacing: 10,
            children: [
              _Summary(
                'My Agents',
                state.agents.length,
                Icons.smart_toy_outlined,
              ),
              _Summary('Active Permissions', active, Icons.key_outlined),
              _Summary(
                'Approved Requests',
                approved,
                Icons.check_circle_outline,
              ),
              _Summary('Rejected Requests', rejected, Icons.cancel_outlined),
            ],
          ),
          const SizedBox(height: 24),
          Text(
            'Recent Activity',
            style: Theme.of(context).textTheme.titleLarge
                ?.copyWith(fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 10),
          if (state.error != null)
            PageMessage(state.error!, icon: Icons.cloud_off_outlined)
          else if (state.auditLogs.isEmpty)
            const PageMessage('No authorization activity yet.')
          else
            ...state.auditLogs
                .take(10)
                .map(
                  (audit) => Card(
                    margin: const EdgeInsets.only(bottom: 10),
                    child: ListTile(
                      leading: Icon(
                        audit.decision == 'APPROVED'
                            ? Icons.check_circle
                            : Icons.cancel,
                        color: audit.decision == 'APPROVED'
                            ? Colors.green
                            : Colors.red,
                      ),
                      title: Text(
                        '${titleCase(audit.action)} ${titleCase(audit.resource)}',
                      ),
                      subtitle: Text(
                        '${formatMoney(audit.amount, audit.currency)} • ${audit.reason}\n${formatTime(audit.requestedAt)}',
                      ),
                      isThreeLine: true,
                      trailing: StatusBadge(audit.decision),
                    ),
                  ),
                ),
        ],
      ),
    );
  }
}

class _Summary extends StatelessWidget {
  const _Summary(this.label, this.value, this.icon);
  final String label;
  final int value;
  final IconData icon;
  @override
  Widget build(BuildContext context) => Card(
    child: Padding(
      padding: const EdgeInsets.all(14),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(icon, color: Theme.of(context).colorScheme.primary),
          const Spacer(),
          Text(
            '$value',
            style: Theme.of(context).textTheme.headlineSmall
                ?.copyWith(fontWeight: FontWeight.bold),
          ),
          Text(label, maxLines: 1, overflow: TextOverflow.ellipsis),
        ],
      ),
    ),
  );
}

class RequestsTab extends StatelessWidget {
  const RequestsTab({super.key});
  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final items = state.requests;
    return RefreshIndicator(
      onRefresh: state.refreshAll,
      child: items.isEmpty
          ? ListView(
              children: const [
                SizedBox(height: 160),
                PageMessage('No approval requests.'),
              ],
            )
          : ListView.builder(
              key: const Key('requests-list'),
              padding: const EdgeInsets.all(16),
              itemCount: items.length,
              itemBuilder: (context, index) {
                final request = items[index];
                return Card(
                  margin: const EdgeInsets.only(bottom: 12),
                  child: ListTile(
                    contentPadding: const EdgeInsets.all(16),
                    leading: const CircleAvatar(
                      child: Icon(Icons.smart_toy_outlined),
                    ),
                    title: Text(
                      request.agentName,
                      style: const TextStyle(fontWeight: FontWeight.bold),
                    ),
                    subtitle: Text(
                      '${titleCase(request.action)} • ${titleCase(request.resource)}\n${formatMoney(request.amount, request.currency)} • ${formatTime(request.createdAt)}',
                    ),
                    isThreeLine: true,
                    trailing: StatusBadge(request.status),
                    onTap: () => Navigator.of(context).push(
                      MaterialPageRoute(
                        builder: (_) => RequestDetailScreen(initial: request),
                      ),
                    ),
                  ),
                );
              },
            ),
    );
  }
}

class AgentsTab extends StatelessWidget {
  const AgentsTab({super.key});
  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    return RefreshIndicator(
      onRefresh: state.refreshAll,
      child: state.agents.isEmpty
          ? ListView(
              children: const [
                SizedBox(height: 160),
                PageMessage('No agents registered yet.'),
              ],
            )
          : ListView.builder(
              key: const Key('agents-list'),
              padding: const EdgeInsets.all(16),
              itemCount: state.agents.length,
              itemBuilder: (context, index) {
                final agent = state.agents[index];
                return Card(
                  margin: const EdgeInsets.only(bottom: 10),
                  child: ListTile(
                    leading: const CircleAvatar(
                      child: Icon(Icons.smart_toy_outlined),
                    ),
                    title: Text(agent.name),
                    subtitle: Text(agent.identifier),
                    trailing: StatusBadge(agent.status),
                    onTap: () => Navigator.push(
                      context,
                      MaterialPageRoute(
                        builder: (_) => AgentDetailScreen(agent: agent),
                      ),
                    ),
                  ),
                );
              },
            ),
    );
  }
}

class AgentDetailScreen extends StatelessWidget {
  const AgentDetailScreen({required this.agent, super.key});
  final Agent agent;
  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const Text('Agent Details')),
    body: ListView(
      padding: const EdgeInsets.all(20),
      children: [
        Text(agent.name, style: Theme.of(context).textTheme.headlineSmall),
        const SizedBox(height: 12),
        StatusBadge(agent.status),
        const SizedBox(height: 20),
        Text('Public Agent ID\n${agent.identifier}'),
        if (agent.description != null)
          Padding(
            padding: const EdgeInsets.only(top: 18),
            child: Text('Description\n${agent.description}'),
          ),
      ],
    ),
  );
}

class PermissionsTab extends StatelessWidget {
  const PermissionsTab({super.key});
  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    return RefreshIndicator(
      onRefresh: state.refreshAll,
      child: state.permissions.isEmpty
          ? ListView(
              children: const [
                SizedBox(height: 160),
                PageMessage('No permissions granted yet.'),
              ],
            )
          : ListView.builder(
              key: const Key('permissions-list'),
              padding: const EdgeInsets.all(16),
              itemCount: state.permissions.length,
              itemBuilder: (context, index) {
                final permission = state.permissions[index];
                final agent = state.agentById(permission.agentId);
                return Card(
                  margin: const EdgeInsets.only(bottom: 10),
                  child: ListTile(
                    title: Text(agent?.name ?? 'Agent'),
                    subtitle: Text(
                      '${titleCase(permission.action)} ${titleCase(permission.resource)}\nMaximum: ${formatMoney(permission.maximumAmount, permission.currency)} • Approval: ${permission.requiresApproval ? 'Required' : 'Automatic'}',
                    ),
                    isThreeLine: true,
                    trailing: StatusBadge(permission.status),
                    onTap: () => Navigator.push(
                      context,
                      MaterialPageRoute(
                        builder: (_) => PermissionDetailScreen(
                          permission: permission,
                          agentName: agent?.name ?? 'Agent',
                        ),
                      ),
                    ),
                  ),
                );
              },
            ),
    );
  }
}

class PermissionDetailScreen extends StatelessWidget {
  const PermissionDetailScreen({
    required this.permission,
    required this.agentName,
    super.key,
  });
  final Permission permission;
  final String agentName;
  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const Text('Permission Details')),
    body: ListView(
      padding: const EdgeInsets.all(20),
      children: [
        Text(agentName, style: Theme.of(context).textTheme.headlineSmall),
        const SizedBox(height: 12),
        StatusBadge(permission.status),
        const SizedBox(height: 20),
        Text('Action\n${titleCase(permission.action)}'),
        const SizedBox(height: 14),
        Text('Resource\n${titleCase(permission.resource)}'),
        const SizedBox(height: 14),
        Text(
          'Maximum\n${formatMoney(permission.maximumAmount, permission.currency)}',
        ),
        const SizedBox(height: 14),
        Text(
          'Approval\n${permission.requiresApproval ? 'Required' : 'Automatic'}',
        ),
        const SizedBox(height: 14),
        Text('Valid from\n${formatTime(permission.validFrom)}'),
        const SizedBox(height: 14),
        Text('Expires\n${formatTime(permission.expiresAt)}'),
      ],
    ),
  );
}

class ProfileTab extends StatelessWidget {
  const ProfileTab({super.key});
  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final user = state.user;
    if (user == null) return const SizedBox.shrink();
    return ListView(
      key: const Key('profile-list'),
      padding: const EdgeInsets.all(20),
      children: [
        const CircleAvatar(radius: 36, child: Icon(Icons.person, size: 38)),
        const SizedBox(height: 18),
        Text(
          user.fullName,
          textAlign: TextAlign.center,
          style: Theme.of(context).textTheme.headlineSmall,
        ),
        Text(user.email, textAlign: TextAlign.center),
        const SizedBox(height: 14),
        Center(child: StatusBadge(user.isActive ? 'ACTIVE' : 'INACTIVE')),
        const SizedBox(height: 28),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              const Text('Billing', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 17)),
              const SizedBox(height: 8),
              Text(state.billingUsage == null ? 'Organization plan available on the web dashboard' : '${state.billingUsage!.planCode.toUpperCase()} plan'),
              if (state.billingUsage?.usage['authorization_requests'] case final requests?)
                Text('${requests.used} of ${requests.limit ?? 'unlimited'} authorization requests used'),
              const SizedBox(height: 8),
              const Text('Manage billing on the AgentTrust web dashboard.', style: TextStyle(color: Colors.black54)),
            ]),
          ),
        ),
        const SizedBox(height: 16),
        Card(child: Padding(padding: const EdgeInsets.all(16), child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('Account security', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 17)),
            const SizedBox(height: 8),
            Text(state.securityStatus?['enabled'] == true ? 'Two-factor authentication: Enabled' : 'Two-factor authentication: Not enabled'),
            if (state.securityStatus?['enabled'] == true)
              Text('Recovery codes remaining: ${state.securityStatus?['recovery_codes_remaining'] ?? 0}'),
            const Text('Manage authenticator setup and sessions on the AgentTrust web dashboard.', style: TextStyle(color: Colors.black54)),
          ],
        ))),
        const SizedBox(height: 16),
        const NotificationSettings(),
        const SizedBox(height: 16),
        OutlinedButton.icon(
          key: const Key('logout'),
          onPressed: state.logout,
          icon: const Icon(Icons.logout),
          label: const Text('Logout'),
        ),
      ],
    );
  }
}
