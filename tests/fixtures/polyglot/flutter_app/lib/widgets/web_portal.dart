import 'package:flutter/material.dart';
import 'package:flutter_inappwebview/flutter_inappwebview.dart';
import 'package:webview_flutter/webview_flutter.dart';

class WebPortalWidget extends StatelessWidget {
  final WebViewController controller;

  const WebPortalWidget({super.key, required this.controller});

  void onJsMessage(JavaScriptMessage message) {
    controller.runJavaScript("window.handlePayload('${message.message}')");
  }

  InAppWebViewSettings buildSettings() {
    return InAppWebViewSettings(
      javaScriptEnabled: true,
      allowUniversalAccessFromFileURLs: true,
    );
  }

  @override
  Widget build(BuildContext context) {
    return const SizedBox();
  }
}
