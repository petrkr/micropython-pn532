from io import IOBase

from micropython import const

from pn532.tags import NFCTag

_READ = const(0x30)
_WRITE = const(0xA2)
_NTAG_ATQA = b"\x00\x44"
_NTAG_SAK = const(0x00)
_PAGE_SIZE = const(4)
_CC_PAGE = const(0x03)
_FIRST_DATA_PAGE = const(0x04)
TYPE_213 = const(213)
TYPE_215 = const(215)
TYPE_216 = const(216)
_CC_NTAG213 = b"\xE1\x10\x12\x00"
_CC_NTAG215 = b"\xE1\x10\x3E\x00"
_CC_NTAG216 = b"\xE1\x10\x6D\x00"
_PAGE_COUNT_NTAG213 = const(0x2E)
_PAGE_COUNT_NTAG215 = const(0x88)
_PAGE_COUNT_NTAG216 = const(0xE8)
_RESERVED_PAGE_COUNT = const(10)


class NTAG(NFCTag):
    def __init__(self, pn532, number, atqa, sak, uid, ats=None):
        super().__init__(pn532, number, atqa, sak, uid, ats)
        self.version = self.read_page(_CC_PAGE)

    @classmethod
    def matches(cls, *, atqa, sak, uid, ats=None):
        return bytes(atqa) == _NTAG_ATQA and sak == _NTAG_SAK

    @property
    def page_size(self):
        return _PAGE_SIZE

    @property
    def type(self):
        if self.version == _CC_NTAG213:
            return TYPE_213
        if self.version == _CC_NTAG215:
            return TYPE_215
        if self.version == _CC_NTAG216:
            return TYPE_216
        return None

    @property
    def page_count(self):
        if self.version == _CC_NTAG213:
            return _PAGE_COUNT_NTAG213
        if self.version == _CC_NTAG215:
            return _PAGE_COUNT_NTAG215
        if self.version == _CC_NTAG216:
            return _PAGE_COUNT_NTAG216
        return 0

    def __repr__(self):
        from ubinascii import hexlify
        type_name = str(self.type) if self.type is not None else "unknown"
        return "<{} type={} uid={} atqa={} sak=0x{:02x}{}>".format(
            self.__class__.__name__,
            type_name,
            hexlify(self.uid).decode(),
            hexlify(self.atqa).decode(),
            self.sak,
            " ats={}".format(hexlify(self.ats).decode()) if self.ats else "",
        )

    def read_page(self, page_number):
        response = self._pn532.in_data_exchange(
            bytes([_READ, page_number & 0xFF]),
            response_length=16,
            target_number=self.number,
        )
        if response is None or len(response) < _PAGE_SIZE:
            return None
        return response[:_PAGE_SIZE]

    def write_page(self, page_number, data):
        assert len(data) == _PAGE_SIZE
        try:
            self._pn532.in_data_exchange(
                bytes([_WRITE, page_number & 0xFF]) + data,
                response_length=0,
                target_number=self.number,
            )
        except RuntimeError:
            return False
        return True


class NTAGIO(IOBase):
    def __init__(self, tag):
        self._tag = tag
        self._bufpos = 0
        if not tag.page_count:
            raise ValueError("Unsupported NTAG type")
        self._size = (tag.page_count - _RESERVED_PAGE_COUNT) * _PAGE_SIZE
        self._cache = (None, None)

    def read(self, count):
        if count < 0:
            raise ValueError("Can not read negative number of bytes")
        if self._bufpos + count > self._size:
            raise ValueError("Can not read more data")
        if count == 0:
            return b""

        start_page = self._bufpos // _PAGE_SIZE
        start_offset = self._bufpos % _PAGE_SIZE
        end_page = (self._bufpos + count - 1) // _PAGE_SIZE

        data = bytearray()
        for logical_page in range(start_page, end_page + 1):
            page = self._read_logical_page(logical_page)
            if logical_page == start_page:
                page = page[start_offset:]
            if logical_page == end_page:
                page = page[:count - len(data)]
            data.extend(page)

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
        data = bytes(data)
        if self._bufpos + len(data) > self._size:
            raise ValueError("Can not write more data")
        if not data:
            return 0

        written = 0
        while written < len(data):
            logical_page = self._bufpos // _PAGE_SIZE
            page_offset = self._bufpos % _PAGE_SIZE
            chunk_len = min(_PAGE_SIZE - page_offset, len(data) - written)

            if page_offset == 0 and chunk_len == _PAGE_SIZE:
                page = bytes(data[written:written + _PAGE_SIZE])
            else:
                page = bytearray(self._read_logical_page(logical_page))
                page[page_offset:page_offset + chunk_len] = data[written:written + chunk_len]
                page = bytes(page)

            page_number = self._logical_to_physical_page(logical_page)
            if not self._tag.write_page(page_number, page):
                raise ValueError("Can not write page {}".format(page_number))

            self._cache = (logical_page, page)
            self._bufpos += chunk_len
            written += chunk_len

        return written

    def close(self):
        pass

    def _logical_to_physical_page(self, logical_page):
        return _FIRST_DATA_PAGE + logical_page

    def _read_logical_page(self, logical_page):
        if logical_page == self._cache[0]:
            return self._cache[1]

        page_number = self._logical_to_physical_page(logical_page)
        page = self._tag.read_page(page_number)
        if page is None:
            raise ValueError("Can not read page {}".format(page_number))

        page = bytes(page)
        self._cache = (logical_page, page)
        return page


NFCTag.register_type(NTAG)
