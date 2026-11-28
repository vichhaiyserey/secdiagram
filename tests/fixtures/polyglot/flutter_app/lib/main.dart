import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:go_router/go_router.dart';
import 'package:url_launcher/url_launcher.dart';
import 'repositories/profile_repository.dart';
import 'services/storage_service.dart';

final router = GoRouter(
  routes: [
    GoRoute(
      path: '/profile',
      builder: (context, state) {
        final id = state.uri.queryParameters['id'] ?? '';
        ProfileRepository().loadUser(id);
        return const SizedBox();
      },
    ),
  ],
);

Future<void> handleDeepLink(Uri uri) async {
  final userId = uri.queryParameters['id'] ?? '';
  await ProfileRepository().loadUser(userId);
  final target = uri.queryParameters['next'] ?? '';
  await launchUrl(Uri.parse(target));
}

Future<dynamic> handleMethodCall(MethodCall call) async {
  final cmd = call.arguments.toString();
  return Process.run('sh', ['-c', cmd], runInShell: true);
}

HttpClient createInsecureClient() {
  final client = HttpClient();
  client.badCertificateCallback = (X509Certificate cert, String host, int port) => true;
  return client;
}

void main() {
  StorageService().saveSession('demo-token');
}
