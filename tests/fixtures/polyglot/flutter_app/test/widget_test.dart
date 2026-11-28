import 'dart:io';

void helperForTests(String input) {
  Process.run('sh', ['-c', input], runInShell: true);
}
