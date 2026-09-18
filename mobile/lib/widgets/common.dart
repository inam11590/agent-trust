import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

String titleCase(String value) => value
    .split(RegExp(r'[_:-]'))
    .where((part) => part.isNotEmpty)
    .map((part) => '${part[0].toUpperCase()}${part.substring(1)}')
    .join(' ');

String formatMoney(num? amount, String? currency) => amount == null
    ? 'No amount'
    : '${NumberFormat('#,##0.##').format(amount)} ${currency ?? ''}'.trim();

String formatTime(DateTime value) =>
    DateFormat('MMM d, y • h:mm a').format(value.toLocal());

class StatusBadge extends StatelessWidget {
  const StatusBadge(this.status, {super.key});
  final String status;

  @override
  Widget build(BuildContext context) {
    final upper = status.toUpperCase();
    final color = switch (upper) {
      'APPROVED' || 'ACTIVE' => Colors.green,
      'REJECTED' || 'REVOKED' || 'SUSPENDED' => Colors.red,
      'PENDING' => Colors.orange,
      _ => Colors.grey,
    };
    return Chip(
      visualDensity: VisualDensity.compact,
      label: Text(
        upper,
        style: TextStyle(
          color: color.shade900,
          fontWeight: FontWeight.w700,
          fontSize: 11,
        ),
      ),
      backgroundColor: color.shade50,
      side: BorderSide(color: color.shade200),
    );
  }
}

class PageMessage extends StatelessWidget {
  const PageMessage(this.message, {super.key, this.icon = Icons.info_outline});
  final String message;
  final IconData icon;
  @override
  Widget build(BuildContext context) => Center(
    child: Padding(
      padding: const EdgeInsets.all(32),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 42, color: Theme.of(context).colorScheme.primary),
          const SizedBox(height: 12),
          Text(message, textAlign: TextAlign.center),
        ],
      ),
    ),
  );
}
