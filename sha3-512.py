# -*- coding: utf-8 -*-

import _sha3
import binascii
import copy

class _SHA3Base(object):
    digest_size = 64
    _block_size = 72 / 8
    name = 'sha3-512'

    def __init__(self, s=None):
        self._s = _sha3.sha3()
        self._s.init(self.digest_size * 8, self.digest_size * 8)
        if s is not None:
            self._s.update(s)

    def copy(self):
        """Return a copy of the hash object."""
        c = copy.copy(self)
        c._s = self._s.copy()
        return c

    def update(self, s):
        """Update this hash object's state with the provided string."""
        return self._s.update(s)

    def digest(self):
        """Return the digest value as a string of binary data."""
        return self._s.digest()

    def hexdigest(self):
        """Return the digest value as a string of hexadecimal digits."""
        return binascii.hexlify(self.digest())
