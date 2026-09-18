import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;

class ApiException implements Exception {
  const ApiException(this.message, {this.statusCode});
  final String message;
  final int? statusCode;
  @override
  String toString() => message;
}

abstract class AgentTrustApi {
  void setToken(String? token);
  Future<Map<String, dynamic>> getObject(String path);
  Future<List<dynamic>> getList(String path);
  Future<Map<String, dynamic>> post(String path, [Map<String, dynamic>? body]);
  Future<Map<String, dynamic>> patch(String path, Map<String, dynamic> body);
  Future<void> delete(String path);
}

class HttpAgentTrustApi implements AgentTrustApi {
  HttpAgentTrustApi(this.baseUrl, {http.Client? client})
    : _client = client ?? http.Client();
  final String baseUrl;
  final http.Client _client;
  String? _token;

  @override
  void setToken(String? token) => _token = token;

  Map<String, String> get _headers => {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    if (_token != null) 'Authorization': 'Bearer $_token',
  };

  Uri _uri(String path) => Uri.parse('$baseUrl$path');

  Future<dynamic> _send(Future<http.Response> Function() request) async {
    try {
      final response = await request().timeout(const Duration(seconds: 12));
      final body = response.body.isEmpty ? null : jsonDecode(response.body);
      if (response.statusCode >= 200 && response.statusCode < 300) return body;
      throw ApiException(
        _friendlyMessage(response.statusCode, body),
        statusCode: response.statusCode,
      );
    } on TimeoutException {
      throw const ApiException(
        'The server took too long to respond. Please try again.',
      );
    } on SocketException {
      throw const ApiException(
        'AgentTrust is offline. Check your connection and try again.',
      );
    } on FormatException {
      throw const ApiException('The server returned an invalid response.');
    } on http.ClientException {
      throw const ApiException(
        'AgentTrust is offline. Check your connection and try again.',
      );
    }
  }

  String _friendlyMessage(int status, dynamic body) {
    final detail = body is Map<String, dynamic> ? body['detail'] : null;
    if (status == 401 && detail == 'Invalid or already used MFA code') {
      return 'That code is invalid or was already used. Try a fresh code.';
    }
    if (status == 401 && detail is String && detail.contains('MFA challenge')) {
      return 'This verification request expired. Please sign in again.';
    }
    if (status == 401) return 'Your login has expired. Please log in again.';
    if (status == 409 &&
        detail is String &&
        detail.toLowerCase().contains('expired')) {
      return 'This request has expired.';
    }
    if (status == 409) return 'This request has already been decided.';
    if (status == 400 || status == 401) {
      return 'The email or password is incorrect.';
    }
    if (status == 422) return 'Please check the information you entered.';
    if (status >= 500) {
      return 'AgentTrust is unavailable right now. Please try again.';
    }
    if (detail is String && detail.isNotEmpty) return detail;
    return 'Something went wrong. Please try again.';
  }

  @override
  Future<Map<String, dynamic>> getObject(String path) async =>
      (await _send(() => _client.get(_uri(path), headers: _headers)))
          as Map<String, dynamic>;
  @override
  Future<List<dynamic>> getList(String path) async =>
      (await _send(() => _client.get(_uri(path), headers: _headers)))
          as List<dynamic>;
  @override
  Future<Map<String, dynamic>> post(
    String path, [
    Map<String, dynamic>? body,
  ]) async => (await _send(
    () => _client.post(
      _uri(path),
      headers: _headers,
      body: body == null ? null : jsonEncode(body),
    ),
  )) as Map<String, dynamic>? ?? <String, dynamic>{};

  @override
  Future<Map<String, dynamic>> patch(String path, Map<String, dynamic> body) async =>
      (await _send(() => _client.patch(_uri(path), headers: _headers, body: jsonEncode(body)))) as Map<String, dynamic>;

  @override
  Future<void> delete(String path) async {
    await _send(() => _client.delete(_uri(path), headers: _headers));
  }
}
