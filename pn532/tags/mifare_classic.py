from pn532.tags import NFCTag
from micropython import const

AUTH_A = const(0x60)
AUTH_B = const(0x61)
_READ  = const(0x30)
_WRITE = const(0xA0)


class MifareClassic(NFCTag):

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
