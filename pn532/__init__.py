import time

from micropython import const
from pn532.tags import NFCTag

__version__ = "0.0.0"

PREAMBLE = const(0x00)
STARTCODE1 = const(0x00)
STARTCODE2 = const(0xFF)
POSTAMBLE = const(0x00)

HOSTTOPN532 = const(0xD4)
PN532TOHOST = const(0xD5)

COMMAND_DIAGNOSE = const(0x00)
COMMAND_GETFIRMWAREVERSION = const(0x02)
COMMAND_GETGENERALSTATUS = const(0x04)
COMMAND_READREGISTER = const(0x06)
COMMAND_WRITEREGISTER = const(0x08)
COMMAND_READGPIO = const(0x0C)
COMMAND_WRITEGPIO = const(0x0E)
COMMAND_SETSERIALBAUDRATE = const(0x10)
COMMAND_SETPARAMETERS = const(0x12)
COMMAND_SAMCONFIGURATION = const(0x14)
COMMAND_POWERDOWN = const(0x16)
COMMAND_INDATAEXCHANGE = const(0x40)
COMMAND_INCOMMUNICATETHRU = const(0x42)
COMMAND_INDESELECT = const(0x44)
COMMAND_INJUMPFORPSL = const(0x46)
COMMAND_INPSL = const(0x4E)
COMMAND_INLISTPASSIVETARGET = const(0x4A)
COMMAND_INATR = const(0x50)
COMMAND_INRELEASE = const(0x52)
COMMAND_INSELECT = const(0x54)
COMMAND_INJUMPFORDEP = const(0x56)
COMMAND_RFCONFIGURATION = const(0x32)
COMMAND_RFREGULATIONTEST = const(0x58)
COMMAND_INAUTOPOLL = const(0x60)
COMMAND_TGGETDATA = const(0x86)
COMMAND_TGGETTARGETSTATUS = const(0x8A)
COMMAND_TGINITASTARGET = const(0x8C)
COMMAND_TGRESPONSETOINITIATOR = const(0x90)
COMMAND_TGSETGENERALBYTES = const(0x92)
COMMAND_TGSETMETADATA = const(0x94)
COMMAND_TGSETDATA = const(0x8E)
COMMAND_TGGETINITIATORCOMMAND = const(0x88)

MIFARE_ISO14443A = const(0x00)

ACK = b"\x00\x00\xFF\x00\xFF\x00"
WAKEUP = const(0x55)


class BusyError(Exception):
    pass


class PN532:
    def __init__(self, transport, *, debug=False, irq=None, reset=None):
        self._transport = transport
        self.low_power = True
        self.debug = debug
        self._irq = irq
        self._reset_pin = reset
        self.reset()
        _ = self.firmware_version

    def reset(self):
        if self._reset_pin:
            if self.debug:
                print("Resetting")
            self._reset_pin.value(0)
            time.sleep(0.1)
            self._reset_pin.value(0)
            time.sleep(0.1)
        self._transport.wakeup()
        self.low_power = False

    def _write_frame(self, data):
        assert data is not None and 1 < len(data) < 255, "Data must be array of 1 to 255 bytes."
        length = len(data)
        frame = bytearray(length + 8)
        frame[0] = PREAMBLE
        frame[1] = STARTCODE1
        frame[2] = STARTCODE2
        checksum = sum(frame[0:3])
        frame[3] = length & 0xFF
        frame[4] = (~length + 1) & 0xFF
        frame[5:-2] = data
        checksum += sum(data)
        frame[-2] = ~checksum & 0xFF
        frame[-1] = POSTAMBLE
        if self.debug:
            print("Write frame: ", [hex(i) for i in frame])
        self._transport.write_data(bytes(frame))

    def _read_frame(self, length):
        response = self._transport.read_data(length + 7)
        if self.debug:
            print("Read frame:", [hex(i) for i in response])

        offset = 0
        while response[offset] == 0x00:
            offset += 1
            if offset >= len(response):
                raise RuntimeError("Response frame preamble does not contain 0x00FF!")
        if response[offset] != 0xFF:
            raise RuntimeError("Response frame preamble does not contain 0x00FF!")
        offset += 1
        if offset >= len(response):
            raise RuntimeError("Response contains no data!")

        frame_len = response[offset]
        if (frame_len + response[offset + 1]) & 0xFF != 0:
            raise RuntimeError("Response length checksum did not match length!")

        checksum = sum(response[offset + 2 : offset + 2 + frame_len + 1]) & 0xFF
        if checksum != 0:
            raise RuntimeError("Response checksum did not match expected value: ", checksum)

        return response[offset + 2 : offset + 2 + frame_len]

    def call_function(self, command, response_length=0, params=[], timeout=1):
        if not self.send_command(command, params=params, timeout=timeout):
            return None
        return self.process_response(command, response_length=response_length, timeout=timeout)

    def send_command(self, command, params=[], timeout=1):
        if self.low_power:
            self._transport.wakeup()
            self.low_power = False

        data = bytearray(2 + len(params))
        data[0] = HOSTTOPN532
        data[1] = command & 0xFF
        for i, val in enumerate(params):
            data[2 + i] = val
        try:
            self._write_frame(data)
        except OSError:
            return False
        if not self._transport.wait_ready(timeout):
            return False
        if ACK != self._transport.read_data(len(ACK)):
            raise RuntimeError("Did not receive expected ACK from PN532!")
        return True

    def process_response(self, command, response_length=0, timeout=1):
        if not self._transport.wait_ready(timeout):
            return None
        response = self._read_frame(response_length + 2)
        if not (response[0] == PN532TOHOST and response[1] == (command + 1)):
            raise RuntimeError("Received unexpected command response!")
        return response[2:]

    def power_down(self):
        if self._reset_pin:
            self._reset_pin.value(0)
            self.low_power = True
        else:
            response = self.call_function(COMMAND_POWERDOWN, params=[0xB0, 0x00])
            self.low_power = response[0] == 0x00
        time.sleep(0.005)
        return self.low_power

    @property
    def firmware_version(self):
        response = self.call_function(COMMAND_GETFIRMWAREVERSION, 4, timeout=0.5)
        if response is None:
            raise RuntimeError("Failed to detect the PN532")
        return tuple(response)

    def SAM_configuration(self):
        self.call_function(COMMAND_SAMCONFIGURATION, params=[0x01, 0x14, 0x01])

    def read_passive_target(self, card_baud=MIFARE_ISO14443A, timeout=1):
        response = self.listen_for_passive_target(card_baud=card_baud, timeout=timeout)
        if not response:
            return None
        return self.get_passive_target(timeout=timeout)

    def listen_for_passive_target(self, card_baud=MIFARE_ISO14443A, timeout=1):
        try:
            response = self.send_command(
                COMMAND_INLISTPASSIVETARGET,
                params=[0x01, card_baud],
                timeout=timeout,
            )
        except BusyError:
            return False
        return response

    def get_passive_target(self, timeout=1):
        response = self.process_response(
            COMMAND_INLISTPASSIVETARGET,
            response_length=64,
            timeout=timeout,
        )
        if response is None or response[0] != 0x01 or len(response) < 6:
            return None
        uid_len = response[5]
        return NFCTag(
            self,
            response[1],
            response[2:4],
            response[4],
            response[6:6 + uid_len],
            response[6 + uid_len:],
        )

    def read_tag(self, card_baud=MIFARE_ISO14443A, timeout=1):
        if not self.listen_for_passive_target(card_baud=card_baud, timeout=timeout):
            return None
        return self.get_passive_target(timeout=timeout)

    def in_data_exchange(self, data, response_length=0, timeout=1, target_number=1):
        params = bytearray(1 + len(data))
        params[0] = target_number & 0xFF
        params[1:] = data
        response = self.call_function(
            COMMAND_INDATAEXCHANGE,
            params=params,
            response_length=response_length + 1,
            timeout=timeout,
        )
        if response is None:
            return None
        if response[0] != 0x00:
            raise RuntimeError("InDataExchange failed with status 0x{:02x}".format(response[0]))
        return response[1:]
