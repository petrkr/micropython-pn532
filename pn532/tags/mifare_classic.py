from io import IOBase
from pn532.tags import NFCTag
from micropython import const

AUTH_A = const(0x60)
AUTH_B = const(0x61)
_READ  = const(0x30)
_WRITE = const(0xA0)
BLOCK_SKIP = const(0)
BLOCK_INCLUDE = const(1)
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
    def resolve_type(cls, *, atqa, sak, uid, ats=None):
        if sak in (_CLASSIC_1K_SAK, _CLASSIC_4K_SAK):
            return cls
        return None

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
        uid4 = self.uid[-4:]
        params = bytearray(2 + len(key) + 4)
        params[0] = key_number & 0xFF
        params[1] = block_number & 0xFF
        params[2:2 + len(key)] = key
        params[2 + len(key):] = uid4
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
    def __init__(
        self,
        tag,
        key=b'\xff\xff\xff\xff\xff\xff',
        key_number=AUTH_B,
        *,
        blocks=(),
        block_mode=BLOCK_INCLUDE,
    ):
        self._tag = tag
        self._key = key
        self._key_number = key_number
        self._bufpos = 0
        self._block_filter = tuple(blocks)
        self._block_mode = block_mode
        if not self._block_filter:
            self._size = tag.data_block_count * _BLOCK_SIZE
        elif self._block_mode == BLOCK_INCLUDE:
            self._size = len(self._block_filter) * _BLOCK_SIZE
        else:
            self._size = (tag.data_block_count - len(self._block_filter)) * _BLOCK_SIZE
        self._sector = None
        self._cache = (None, None)

    def read(self, count):
        if count < 0:
            raise ValueError("Can not read negative number of bytes")
        if self._bufpos + count > self._size:
            raise ValueError("Can not read more data")
        if count == 0:
            return b""

        start_logical = self._bufpos // _BLOCK_SIZE
        start_offset  = self._bufpos % _BLOCK_SIZE
        end_logical   = (self._bufpos + count - 1) // _BLOCK_SIZE

        data = bytearray()
        logical_idx = 0
        block_index = start_logical
        for phys in range(1, self._tag.block_count):
            if self._is_sector_trailer(phys) or not self._block_selected(phys):
                continue
            if logical_idx < start_logical:
                logical_idx += 1
                continue
            block_number = phys
            sector = self._block_sector(block_number)
            if sector != self._sector:
                if not self._tag.authenticate_block(block_number, self._key_number, self._key):
                    raise ValueError("Authentication failed block {} sector {}".format(
                        block_number, sector))
                self._sector = sector
            if block_number == self._cache[0]:
                block = self._cache[1]
            else:
                block = self._tag.read_block(block_number)
                if block is None:
                    raise ValueError("Can not read block {}".format(block_number))
                self._cache = (block_number, block)
            if block_index == start_logical:
                block = block[start_offset:]
            if block_index == end_logical:
                block = block[:count - len(data)]
            data.extend(block)
            if block_index == end_logical:
                break
            block_index += 1
            logical_idx += 1

        self._bufpos += count
        return bytes(data)

    def seek(self, position):
        if position < 0:
            raise ValueError("Can not seek negative number")
        if position > self._size:
            raise ValueError("Can not seek beyond data")
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

    def _block_selected(self, block_number):
        if not self._block_filter:
            return True
        if self._block_mode == BLOCK_INCLUDE:
            return block_number in self._block_filter
        if self._block_mode == BLOCK_SKIP:
            return block_number not in self._block_filter
        raise ValueError("Unsupported block mode")

    def _block_sector(self, block_number):
        if self._tag.sak == _CLASSIC_4K_SAK and block_number >= _CLASSIC_4K_LARGE_BLOCK_START:
            return _CLASSIC_4K_LARGE_SECTOR_START + (
                (block_number - _CLASSIC_4K_LARGE_BLOCK_START) // _CLASSIC_LARGE_SECTOR_BLOCKS
            )
        return block_number // _CLASSIC_SMALL_SECTOR_BLOCKS

    def _is_sector_trailer(self, block_number):
        if self._tag.sak == _CLASSIC_4K_SAK and block_number >= _CLASSIC_4K_LARGE_BLOCK_START:
            return (block_number - _CLASSIC_4K_LARGE_BLOCK_START + 1) % _CLASSIC_LARGE_SECTOR_BLOCKS == 0
        return (block_number + 1) % _CLASSIC_SMALL_SECTOR_BLOCKS == 0


NFCTag.register_type(MifareClassic)
