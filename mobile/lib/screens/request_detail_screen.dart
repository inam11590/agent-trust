import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../models/authorization_request.dart';
import '../providers/app_state.dart';
import '../widgets/common.dart';

class RequestDetailScreen extends StatefulWidget {
  const RequestDetailScreen({required this.initial, super.key});
  final AuthorizationRequest initial;
  @override
  State<RequestDetailScreen> createState() => _RequestDetailScreenState();
}

class _RequestDetailScreenState extends State<RequestDetailScreen> {
  late AuthorizationRequest request = widget.initial;
  bool busy = false;

  Future<void> _decide(bool approve) async {
    if (request.status != 'PENDING') return;
    final appState = context.read<AppState>();
    if (approve) {
      final confirmed = await showDialog<bool>(
        context: context,
        builder: (context) => AlertDialog(
          title: const Text('Approve this AI action?'),
          content: Text(
            '${request.agentName} wants to ${request.action} ${request.resource}.',
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: () => Navigator.pop(context, true),
              child: const Text('Approve'),
            ),
          ],
        ),
      );
      if (!mounted) return;
      if (confirmed != true) return;
    }
    setState(() => busy = true);
    final message = await appState.decide(request.id, approve: approve);
    if (!mounted) return;
    final refreshed = await appState.loadRequest(request.id);
    if (!mounted) return;
    if (refreshed != null) setState(() => request = refreshed);
    setState(() => busy = false);
    ScaffoldMessenger.of(context)
        .showSnackBar(SnackBar(content: Text(message)));
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const Text('Request Details')),
    body: ListView(
      padding: const EdgeInsets.all(20),
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Expanded(
              child: Text(
                request.agentName,
                style: Theme.of(context).textTheme.headlineSmall
                    ?.copyWith(fontWeight: FontWeight.bold),
              ),
            ),
            StatusBadge(request.status),
          ],
        ),
        const SizedBox(height: 20),
        if (request.riskLevel != null) ...[
          Container(
            key: const Key('risk-warning'),
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: request.riskLevel == 'HIGH' || request.riskLevel == 'CRITICAL'
                  ? Colors.orange.shade50 : Colors.blue.shade50,
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: Colors.orange.shade200),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('${request.riskLevel} RISK · ${request.riskScore}/100',
                    style: const TextStyle(fontWeight: FontWeight.bold)),
                if (request.riskReasons.isNotEmpty) ...[
                  const SizedBox(height: 8),
                  const Text('Why:', style: TextStyle(fontWeight: FontWeight.w600)),
                  ...request.riskReasons.map((reason) => Padding(
                    padding: const EdgeInsets.only(top: 4),
                    child: Text('• $reason'),
                  )),
                ],
              ],
            ),
          ),
          const SizedBox(height: 16),
        ],
        _Detail('Agent ID', request.agentIdentifier),
        _Detail('Action', titleCase(request.action)),
        _Detail('Resource', titleCase(request.resource)),
        _Detail('Amount', formatMoney(request.amount, request.currency)),
        _Detail('Permission', request.permissionId),
        if (request.delegationId != null) _Detail('Delegation ID', request.delegationId!),
        if (request.parentAgentId != null) _Detail('Parent Agent', request.parentAgentId!),
        _Detail('Requested', formatTime(request.createdAt)),
        _Detail('Expires', formatTime(request.expiresAt)),
        _Detail('Reason', request.reason),
        if (request.status == 'PENDING') ...[
          const SizedBox(height: 16),
          FilledButton.icon(
            key: const Key('approve-request'),
            onPressed: busy ? null : () => _decide(true),
            icon: const Icon(Icons.check),
            label: const Text('APPROVE'),
          ),
          const SizedBox(height: 10),
          OutlinedButton.icon(
            key: const Key('reject-request'),
            onPressed: busy ? null : () => _decide(false),
            icon: const Icon(Icons.close),
            label: const Text('REJECT'),
          ),
        ],
      ],
    ),
  );
}

class _Detail extends StatelessWidget {
  const _Detail(this.label, this.value);
  final String label;
  final String value;
  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 9),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label,
          style: Theme.of(context).textTheme.labelMedium
              ?.copyWith(color: Colors.grey.shade700),
        ),
        const SizedBox(height: 3),
        Text(value),
      ],
    ),
  );
}
