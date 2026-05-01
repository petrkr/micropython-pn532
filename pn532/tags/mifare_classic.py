from io import IOBase
from pn532.tags import NFCTag
from micropython import const

AUTH_A = const(0x60)
AUTH_B = const(0x61)
_READ  = const(0x30)
_WRITE = const(0xA0)
TYPE_1K = const(1)
TYPE_4K = const(4)
_BLOCK_SIZE = const(16)
_CLASSIC_1K_SAK = const(0x08)
_CLASSIC_4K_SAK = const(0x18)
_CLASSIC_1K_SECTOR_COUNT = const(16)
_CLASSIC_4K_SECTOR_COUNT = const(40)
_CLASSIC_1K_BLOCK_COUNT = const(64)
_CLASSIC_4K_BLOCK_COUNT = const(256)
_CLASSIC_1K_DATA_BLOCK_COUNT = const(48)
_CLASSIC_4K_DATA_BLOCK_COUNT = const(216)
_CLASSIC_4K_LARGE_SECTOR_START = const(32)
_CLASSIC_4K_LARGE_BLOCK_START = const(128)
_CLASSIC_SMALL_SECTOR_BLOCKS = const(4)
_CLASSIC_LARGE_SECTOR_BLOCKS = const(16)


class MifareClassic(NFCTag):
    @classmethod
    def matches(cls, *, atqa, sak, uid, ats=None):
        return sak in (_CLASSIC_1K_SAK, _CLASSIC_4K_SAK)

    @property
    def type(self):
        if self.sak == _CLASSIC_1K_SAK:
            return TYPE_1K
        if self.sak == _CLASSIC_4K_SAK:
            return TYPE_4K
        return None

    @property
    def sector_count(self):
        if self.sak == _CLASSIC_1K_SAK:
            return _CLASSIC_1K_SECTOR_COUNT
        if self.sak == _CLASSIC_4K_SAK:
            return _CLASSIC_4K_SECTOR_COUNT
        return 0

    @property
    def block_count(self):
        if self.sak == _CLASSIC_1K_SAK:
            return _CLASSIC_1K_BLOCK_COUNT
        if self.sak == _CLASSIC_4K_SAK:
            return _CLASSIC_4K_BLOCK_COUNT
        return 0

    @property
    def data_block_count(self):
        if self.sak == _CLASSIC_1K_SAK:
            return _CLASSIC_1K_DATA_BLOCK_COUNT
        if self.sak == _CLASSIC_4K_SAK:
            return _CLASSIC_4K_DATA_BLOCK_COUNT
        return 0

    @property
    def size(self):
        return self.data_block_count * _BLOCK_SIZE

    def __repr__(self):
        from ubinascii import hexlify
        type_name = "{}K".format(self.type) if self.type is not None else "unknown"
        return "<{} type={} uid={} atqa={} sak=0x{:02x}{}>".format(
            self.__class__.__name__,
            type_name,
            hexlify(self.uid).decode(),
            hexlify(self.atqa).decode(),
            self.sak,
            " ats={}".format(hexlify(self.ats).decode()) if self.ats else "",
        )

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
        self._blocksize = _BLOCK_SIZE
        self._size = tag.size

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

    def size(self):
        return self._size

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
            if self._is_sector_first_block(self._blockpos):
                if not self._tag.authenticate_block(self._blockpos, self._key_number, self._key):
                    raise ValueError("Authentication failed block {} sector {}".format(
                        self._blockpos, self._block_sector(self._blockpos)))
            if not self._is_sector_trailer(self._blockpos):
                data = self._tag.read_block(self._blockpos)
                self._buffer += data
                ndatablocksread += 1
            self._blockpos += 1

    def _block_sector(self, block_number):
        if self._tag.sak == _CLASSIC_4K_SAK and block_number >= _CLASSIC_4K_LARGE_BLOCK_START:
            return _CLASSIC_4K_LARGE_SECTOR_START + (
                (block_number - _CLASSIC_4K_LARGE_BLOCK_START) // _CLASSIC_LARGE_SECTOR_BLOCKS
            )
        return block_number // _CLASSIC_SMALL_SECTOR_BLOCKS

    def _sector_first_block(self, sector):
        if self._tag.sak == _CLASSIC_4K_SAK and sector >= _CLASSIC_4K_LARGE_SECTOR_START:
            return _CLASSIC_4K_LARGE_BLOCK_START + (
                (sector - _CLASSIC_4K_LARGE_SECTOR_START) * _CLASSIC_LARGE_SECTOR_BLOCKS
            )
        return sector * _CLASSIC_SMALL_SECTOR_BLOCKS

    def _sector_size(self, sector):
        if self._tag.sak == _CLASSIC_4K_SAK and sector >= _CLASSIC_4K_LARGE_SECTOR_START:
            return _CLASSIC_LARGE_SECTOR_BLOCKS
        return _CLASSIC_SMALL_SECTOR_BLOCKS

    def _is_sector_first_block(self, block_number):
        return block_number == self._sector_first_block(self._block_sector(block_number))

    def _is_sector_trailer(self, block_number):
        sector = self._block_sector(block_number)
        return block_number == self._sector_first_block(sector) + self._sector_size(sector) - 1


NFCTag.register_type(MifareClassic)
