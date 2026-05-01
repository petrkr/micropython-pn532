from io import IOBase
from pn532.tags import NFCTag
from micropython import const

AUTH_A = const(0x60)
AUTH_B = const(0x61)
_READ  = const(0x30)
_WRITE = const(0xA0)


class MifareClassic(NFCTag):
    @classmethod
    def matches(cls, *, atqa, sak, uid, ats=None):
        return sak in (0x08, 0x18)

    def authenticate_block(self, block_number, key_number, key):
        params = bytearray(2 + len(key) + len(self.uid))
        params[0] = key_number & 0xFF
        params[1] = block_number & 0xFF
        params[2:2 + len(key)] = key
        params[2 + len(key):] = self.uid
        try:
            self._pn532.in_data_exchange(params, response_length=0, target_number=self.number)
        except RuntimeError:
            return False
        return True

    def read_block(self, block_number):
        response = self._pn532.in_data_exchange(
            bytes([_READ, block_number & 0xFF]), response_length=16, target_number=self.number
        )
        return response if response and len(response) == 16 else None

    def write_block(self, block_number, data):
        assert len(data) == 16
        try:
            self._pn532.in_data_exchange(
                bytes([_WRITE, block_number & 0xFF]) + data, response_length=0, target_number=self.number
            )
        except RuntimeError:
            return False
        return True


class MifareClassicIO(IOBase):
    def __init__(self, tag, key=b'\xff\xff\xff\xff\xff\xff', key_number=AUTH_B):
        self._tag = tag
        self._key = key
        self._key_number = key_number
        self._buffer = bytes()
        self._bufpos = 0
        self._blockpos = 0
        self._blocksize = 16
        self._size = 768  # 48 data blocks × 16 bytes

        sector0 = self.read(self._blocksize * 3)
        if sector0[0:4] != tag.uid[0:4]:
            raise Exception("UID does not match Sector 0!")

    def read(self, count):
        if count < 0:
            raise ValueError("Can not read negative number of bytes")
        if self._bufpos + count > self._size:
            raise ValueError("Can not read more data")
        if self._bufpos + count > len(self._buffer):
            self._read_mifare_block(self._bufpos + count - len(self._buffer))
        pos = self._bufpos
        self._bufpos += count
        return self._buffer[pos:self._bufpos]

    def seek(self, position):
        if position < 0:
            raise ValueError("Can not seek negative number")
        if position > len(self._buffer):
            raise ValueError("Can not seek beyond buffer")
        self._bufpos = position

    def seekable(self):
        return True

    def tell(self):
        return self._bufpos

    def write(self, data):
        raise NotImplementedError()

    def close(self):
        pass

    def _read_mifare_block(self, count):
        ndatablocks = count // self._blocksize
        if count % self._blocksize != 0:
            ndatablocks += 1

        ndatablocksread = 0
        while ndatablocksread < ndatablocks:
            if self._blockpos % 4 == 0:
                if not self._tag.authenticate_block(self._blockpos, self._key_number, self._key):
                    raise ValueError("Authentication failed block {} sector {}".format(
                        self._blockpos, self._blockpos // 4))
            if self._blockpos % 4 != 3:
                data = self._tag.read_block(self._blockpos)
                self._buffer += data
                ndatablocksread += 1
            self._blockpos += 1


NFCTag.register_type(MifareClassic)
