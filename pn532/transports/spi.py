import utime as time

from micropython import const
from pn532.transports import Transport

SPI_STATREAD = const(0x02)
SPI_DATAWRITE = const(0x01)
SPI_DATAREAD = const(0x03)
SPI_READY = const(0x01)


def reverse_bit(num):
    result = 0
    for _ in range(8):
        result <<= 1
        result += (num & 1)
        num >>= 1
    return result


class SPITransport(Transport):
    def __init__(self, spi, ss, *, reset=None, debug=False):
        self.debug = debug
        self._spi = spi
        self._ss = ss
        self._reset_pin = reset

    def wakeup(self):
        if self._reset_pin:
            self._reset_pin.value(1)
            time.sleep(0.01)
        self._ss(0)
        self._spi.write(
            b"\x55\x55\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        self._ss(1)
        if self.debug:
            print("PN532 wake up")

    def wait_ready(self, timeout=1):
        status_query = bytearray([reverse_bit(SPI_STATREAD), 0])
        status = bytearray([0, 0])
        timestamp = time.ticks_ms()
        while time.ticks_diff(time.ticks_ms(), timestamp) < timeout * 1000:
            self._ss(0)
            time.sleep_us(100)
            self._spi.write_readinto(status_query, status)
            self._ss(1)

            if reverse_bit(status[1]) == SPI_READY:
                return True
            time.sleep_ms(1)

        return False

    def read_data(self, count):
        frame = bytearray(count + 1)
        frame[0] = reverse_bit(SPI_DATAREAD)
        self._ss(0)
        time.sleep_us(100)
        self._spi.write_readinto(frame, frame)
        self._ss(1)
        for i in range(len(frame)):
            frame[i] = reverse_bit(frame[i])
        if self.debug:
            print("DEBUG: _read_data: ", [hex(i) for i in frame[1:]])
        return frame[1:]

    def write_data(self, framebytes):
        n = len(framebytes)
        buf = bytearray(n + 1)
        buf[0] = reverse_bit(SPI_DATAWRITE)
        for i in range(n):
            buf[i + 1] = reverse_bit(framebytes[i])
        if self.debug:
            print("DEBUG: _write_data: ", [hex(i) for i in buf[1:]])
        self._ss(0)
        time.sleep_us(100)
        self._spi.write(buf)
        self._ss(1)
