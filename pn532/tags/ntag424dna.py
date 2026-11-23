from io import IOBase

from micropython import const
from ubinascii import hexlify

from pn532.tags.isodep import IsoDepTag

_WRAP_CLA = const(0x90)
_ISO_CLA = const(0x00)
_ISO_SELECT = const(0xA4)
_GET_VERSION = const(0x60)
_GET_FILE_SETTINGS = const(0xF5)
_READ_DATA = const(0xAD)
_ADDITIONAL_FRAME = const(0xAF)
_STATUS_OK = const(0x00)
_NTAG_PRODUCT_TYPE = const(0x04)
_MAX_READ_SIZE = const(48)
_DF_NAME = b"\xD2\x76\x00\x00\x85\x01\x01"
_FILE_IDS = (1, 2, 3)


class Ntag424DnaFile(IOBase):
    def __init__(self, application, file_id, settings):
        self._application = application
        self.file_id = file_id
        self.file_type = settings.get("file_type")
        self.comm_mode = settings.get("comm_mode")
        self.access_rights = settings.get("access_rights", b"")
        self.size = settings.get("file_size", 0)
        self.settings = settings
        self._offset = 0

    def __repr__(self):
        return "<{} id={} type={} size={} comm_mode={} access_rights={}>".format(
            self.__class__.__name__,
            self.file_id,
            self.file_type,
            self.size,
            self.comm_mode,
            hexlify(self.access_rights).decode(),
        )

    def read(self, count=-1):
        self._application._select()
        if count is None or count < 0:
            count = self.size - self._offset
        if self._offset + count > self.size:
            count = self.size - self._offset
        data = self._application._tag._read_file_data(self.file_id, self._offset, count)
        self._offset += len(data)
        return data

    def seek(self, offset):
        if offset < 0 or offset > self.size:
            raise ValueError("Invalid seek offset")
        self._offset = offset

    def tell(self):
        return self._offset

    def seekable(self):
        return True

    def close(self):
        pass


class Ntag424DnaApplication:
    df_name = _DF_NAME

    def __init__(self, tag):
        self._tag = tag

    def __repr__(self):
        return "<{} df_name={}>".format(
            self.__class__.__name__, hexlify(self.df_name).decode()
        )

    @property
    def files(self):
        self._select()
        return [
            Ntag424DnaFile(self, file_id, self._tag._get_file_settings(file_id))
            for file_id in _FILE_IDS
        ]

    def _select(self):
        self._tag._select_application()


class Ntag424DnaTag(IsoDepTag):
    def __init__(self, pn532, number, atqa, sak, uid, ats=None):
        super().__init__(pn532, number, atqa, sak, uid, ats)
        self.version = b""

    @classmethod
    def probe(cls, tag):
        version = cls._native_command(tag, _GET_VERSION)
        if len(version) < 2 or version[1] != _NTAG_PRODUCT_TYPE:
            return None
        return version

    def _set_probe_data(self, version):
        self.version = bytes(version)

    def __repr__(self):
        return "<{} uid={} atqa={} sak=0x{:02x}{}>".format(
            self.__class__.__name__,
            hexlify(self.uid).decode(),
            hexlify(self.atqa).decode(),
            self.sak,
            " ats={}".format(hexlify(self.ats).decode()) if self.ats else "",
        )

    @property
    def applications(self):
        return [Ntag424DnaApplication(self)]

    def _select_application(self):
        response = self.transceive_apdu(
            _ISO_CLA, _ISO_SELECT, p1=0x04, p2=0x0C, data=_DF_NAME
        )
        if len(response) < 2 or response[-2:] != b"\x90\x00":
            raise ValueError("NTAG 424 DNA application select failed")

    def _get_file_settings(self, file_id):
        data = self._native_command(self, _GET_FILE_SETTINGS, bytes([file_id & 0xFF]))
        settings = {
            "file_type": data[0] if len(data) > 0 else None,
            "comm_mode": data[1] if len(data) > 1 else None,
            "access_rights": bytes(data[2:4]) if len(data) >= 4 else b"",
            "raw": bytes(data),
        }
        if len(data) >= 7:
            settings["file_size"] = data[4] | (data[5] << 8) | (data[6] << 16)
        return settings

    def _read_file_data(self, file_id, offset, length):
        data = bytearray()
        remaining = length
        while remaining > 0:
            chunk_size = min(remaining, _MAX_READ_SIZE)
            params = bytearray(7)
            params[0] = file_id & 0xFF
            params[1] = offset & 0xFF
            params[2] = (offset >> 8) & 0xFF
            params[3] = (offset >> 16) & 0xFF
            params[4] = chunk_size & 0xFF
            params[5] = (chunk_size >> 8) & 0xFF
            params[6] = (chunk_size >> 16) & 0xFF
            data.extend(self._native_command(self, _READ_DATA, params))
            offset += chunk_size
            remaining -= chunk_size
        return bytes(data)

    @staticmethod
    def _native_command(tag, ins, data=b""):
        response = tag.transceive_apdu(_WRAP_CLA, ins, data=data)
        payload = bytearray()

        while True:
            if len(response) < 2:
                raise ValueError("NTAG 424 DNA response too short")

            payload.extend(response[:-2])
            if response[-2] != 0x91:
                raise ValueError("Unexpected NTAG 424 DNA status frame")

            status = response[-1]
            if status == _STATUS_OK:
                return bytes(payload)
            if status != _ADDITIONAL_FRAME:
                raise ValueError(
                    "NTAG 424 DNA command failed with status 0x{:02x}".format(status)
                )

            response = tag.transceive_apdu(_WRAP_CLA, _ADDITIONAL_FRAME)


IsoDepTag.register_type(Ntag424DnaTag)
