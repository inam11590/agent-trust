class BillingUsageItem {
  const BillingUsageItem({required this.used, required this.limit});
  final int used;
  final int? limit;
  factory BillingUsageItem.fromJson(Map<String, dynamic> json) => BillingUsageItem(
    used: json['used'] as int, limit: json['limit'] as int?,
  );
}

class BillingUsage {
  const BillingUsage({required this.planCode, required this.usage});
  final String planCode;
  final Map<String, BillingUsageItem> usage;
  factory BillingUsage.fromJson(Map<String, dynamic> json) => BillingUsage(
    planCode: json['plan_code'] as String,
    usage: (json['usage'] as Map<String, dynamic>).map((key, value) => MapEntry(
      key, BillingUsageItem.fromJson(value as Map<String, dynamic>),
    )),
  );
}
