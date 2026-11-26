import 'package:meta/meta.dart';

typedef SSHChannelId = int;

class SSHChannelIdAllocator {
  SSHChannelIdAllocator();

  static const _maxId = 0xFFFF;

  var _nextId = 0;

  final _allocated = <SSHChannelId>{};

  /// The ids currently allocated, so tests can check that none leak.
  @visibleForTesting
  Set<SSHChannelId> get allocatedIds => Set.unmodifiable(_allocated);

  /// Allocates a new channel id. Throw [StateError] if no more channel ids are
  /// available.
  SSHChannelId allocate() {
    if (_allocated.length >= _maxId) {
      throw Exception('No more channel ids available');
    }
    while (_allocated.contains(_nextId)) {
      _nextId++;
      if (_nextId > _maxId) {
        _nextId = 0;
      }
    }
    _allocated.add(_nextId);
    return _nextId++;
  }

  /// Releases [id]. After this call, [id] can be allocated again.
  void release(SSHChannelId id) {
    _allocated.remove(id);
  }
}
