class Agent {
  const Agent({
    required this.id,
    required this.name,
    required this.identifier,
    required this.status,
    this.description,
  });
  final String id;
  final String name;
  final String identifier;
  final String status;
  final String? description;

  factory Agent.fromJson(Map<String, dynamic> json) => Agent(
    id: json['id'] as String,
    name: json['name'] as String,
    identifier: json['agent_identifier'] as String,
    status: json['status'] as String,
    description: json['description'] as String?,
  );
}
