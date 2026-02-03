"""
Thread-safe wrappers for shared data structures.
Used to prevent race conditions when multiple threads access shared dictionaries.
"""

import threading
from collections import UserDict


class ThreadSafeDict(UserDict):
    """Thread-safe dictionary wrapper using a reentrant lock.

    This wrapper provides thread-safe access to dictionary operations,
    preventing race conditions when multiple threads read/write to the
    same dictionary concurrently.
    """

    def __init__(self, *args, **kwargs):
        self._lock = threading.RLock()
        super().__init__(*args, **kwargs)

    def __getitem__(self, key):
        with self._lock:
            return super().__getitem__(key)

    def __setitem__(self, key, value):
        with self._lock:
            super().__setitem__(key, value)

    def __delitem__(self, key):
        with self._lock:
            super().__delitem__(key)

    def __contains__(self, key):
        with self._lock:
            return super().__contains__(key)

    def __len__(self):
        with self._lock:
            return super().__len__()

    def __iter__(self):
        with self._lock:
            return iter(list(self.data.keys()))

    def get(self, key, default=None):
        with self._lock:
            return self.data.get(key, default)

    def pop(self, key, *args):
        with self._lock:
            return self.data.pop(key, *args)

    def setdefault(self, key, default=None):
        with self._lock:
            return self.data.setdefault(key, default)

    def update(self, *args, **kwargs):
        with self._lock:
            self.data.update(*args, **kwargs)

    def items(self):
        with self._lock:
            return list(self.data.items())

    def keys(self):
        with self._lock:
            return list(self.data.keys())

    def values(self):
        with self._lock:
            return list(self.data.values())

    def clear(self):
        with self._lock:
            self.data.clear()

    def copy(self):
        with self._lock:
            return ThreadSafeDict(self.data.copy())
