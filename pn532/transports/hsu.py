import utime as time

from pn532 import BusyError
from pn532.transports import Transport


class HSUTransport(Transport):
    def __init__(self, uart, *, reset=None, debug=False):
        self.debug = debug
        self._uart = uart
        self._reset_pin = reset

    def wakeup(self):
        if self._reset_pin:
            self._reset_pin.value(1)
            time.sleep(0.01)

        self._uart.write(
            b"\x55\x55\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        if self.debug:
            print("PN532 wake up")

    def wait_ready(self, timeout=1):
        timestamp = time.ticks_ms()
        while time.ticks_diff(time.ticks_ms(), timestamp) < timeout * 1000:
            if self._uart.any():
                return True
            time.sleep_ms(10)

        if self.debug:
            print("PN532 timed out after", timeout, "s")
        return False

    def read_data(self, count):
        frame = bytearray()
        timestamp = time.ticks_ms()
        while len(frame) < count and time.ticks_diff(time.ticks_ms(), timestamp) < 1000:
            waiting = self._uart.any()
            if waiting:
                chunk = self._uart.read(min(count - len(frame), waiting))
                if chunk:
                    frame.extend(chunk)
                    timestamp = time.ticks_ms()
                    continue
            time.sleep_ms(1)
        if not frame:
            raise BusyError("No data read from PN532")
        if self.debug:
            print("DEBUG: _read_data: ", [hex(i) for i in frame])
        return bytes(frame)

    def write_data(self, framebytes):
        while self._uart.any():
            read = self._uart.read(1)
            if self.debug:
                print("DEBUG: flushing buffer: ", read)
        if self.debug:
            print("DEBUG: _write_data: ", [hex(i) for i in framebytes])
        self._uart.write(framebytes)
