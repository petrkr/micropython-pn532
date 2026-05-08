from micropython import const

from pn532.tags import NFCTag

_READ = const(0x30)
_WRITE = const(0xA2)
_NTAG_ATQA = b"\x00\x44"
_NTAG_SAK = const(0x00)
_PAGE_SIZE = const(4)


class NTAG(NFCTag):
    @classmethod
    def matches(cls, *, atqa, sak, uid, ats=None):
        return bytes(atqa) == _NTAG_ATQA and sak == _NTAG_SAK

    @property
    def page_size(self):
        return _PAGE_SIZE

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


NFCTag.register_type(NTAG)
