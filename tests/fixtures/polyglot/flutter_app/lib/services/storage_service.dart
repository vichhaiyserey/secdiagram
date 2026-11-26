import 'dart:convert';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:shared_preferences/shared_preferences.dart';

class StorageService {
  Future<void> saveSession(String token) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('auth_token', token);
  }

  String generateOtp() {
    final otp = Random().nextInt(999999);
    return otp.toString().padLeft(6, '0');
  }

  String hashLegacy(String value) {
    return md5.convert(utf8.encode(value)).toString();
  }
}
