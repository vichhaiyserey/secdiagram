import 'package:sqflite/sqflite.dart';

class ProfileRepository {
  Database? db;

  Future<List<Map<String, Object?>>> loadUser(String userId) async {
    return db!.rawQuery("SELECT * FROM users WHERE id = '$userId'");
  }

  Future<List<Map<String, Object?>>> loadSafeUser(String userId) async {
    return db!.rawQuery('SELECT * FROM users WHERE id = ?', [userId]);
  }
}
