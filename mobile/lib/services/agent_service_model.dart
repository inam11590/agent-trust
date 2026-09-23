/// AgentTrust Mobile (Flutter): Service Registry and Capability Model (Step 30)

class AgentServiceModel {
  final String id;
  final String serviceId;
  final String name;
  final String? description;
  final String version;
  final String status;
  final String visibility;
  final String environment;
  final int capabilitiesCount;
  final int endpointsCount;

  AgentServiceModel({
    required this.id,
    required this.serviceId,
    required this.name,
    this.description,
    required this.version,
    required this.status,
    required this.visibility,
    required this.environment,
    this.capabilitiesCount = 0,
    this.endpointsCount = 0,
  });

  factory AgentServiceModel.fromJson(Map<String, dynamic> json) {
    return AgentServiceModel(
      id: json['id'] as String,
      serviceId: json['service_id'] as String,
      name: json['name'] as String,
      description: json['description'] as String?,
      version: json['version'] as String? ?? '1.0.0',
      status: json['status'] as String? ?? 'ACTIVE',
      visibility: json['visibility'] as String? ?? 'ORGANIZATION',
      environment: json['environment'] as String? ?? 'production',
      capabilitiesCount: json['capabilities_count'] as int? ?? 0,
      endpointsCount: json['endpoints_count'] as int? ?? 0,
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'service_id': serviceId,
      'name': name,
      'description': description,
      'version': version,
      'status': status,
      'visibility': visibility,
      'environment': environment,
      'capabilities_count': capabilitiesCount,
      'endpoints_count': endpointsCount,
    };
  }
}
