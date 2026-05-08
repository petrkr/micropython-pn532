from micropython import const
from ubinascii import hexlify

from pn532.tags.isodep import IsoDepTag

_DESFIRE_ATQA = b"\x03\x44"
_DESFIRE_SAK = const(0x20)
_WRAP_CLA = const(0x90)
_GET_APPLICATION_IDS = const(0x6A)
_SELECT_APPLICATION = const(0x5A)
_GET_FILE_IDS = const(0x6F)
_GET_FILE_SETTINGS = const(0xF5)
_READ_DATA = const(0xBD)
_ADDITIONAL_FRAME = const(0xAF)
_STATUS_OK = const(0x00)
_MAX_READ_SIZE = const(48)


class DesfireFile:
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


class DesfireApplication:
    def __init__(self, tag, aid):
        self._tag = tag
        self.aid = bytes(aid)

    def __repr__(self):
        return "<{} aid={}>".format(
            self.__class__.__name__,
            hexlify(self.aid).decode(),
        )

    @property
    def files(self):
        self._select()
        file_ids = self._tag._get_file_ids()
        return [DesfireFile(self, file_id, self._tag._get_file_settings(file_id)) for file_id in file_ids]

    def _select(self):
        self._tag._select_application(self.aid)


class DesfireTag(IsoDepTag):
    @classmethod
    def resolve_type(cls, *, atqa, sak, uid, ats=None):
        if bytes(atqa) == _DESFIRE_ATQA and sak == _DESFIRE_SAK and bool(ats):
            return cls
        return None

    def __repr__(self):
        type_name = "EV2" if self.atqa == _DESFIRE_ATQA else "unknown"
        return "<{} type={} uid={} atqa={} sak=0x{:02x}{}>".format(
            self.__class__.__name__,
            type_name,
            hexlify(self.uid).decode(),
            hexlify(self.atqa).decode(),
            self.sak,
            " ats={}".format(hexlify(self.ats).decode()) if self.ats else "",
        )

    @property
    def applications(self):
        data = self._desfire_command(_GET_APPLICATION_IDS)
        return [DesfireApplication(self, data[idx:idx + 3]) for idx in range(0, len(data), 3)]

    def _select_application(self, aid):
        if len(aid) != 3:
            raise ValueError("AID must be 3 bytes")
        self._desfire_command(_SELECT_APPLICATION, aid)

    def _get_file_ids(self):
        data = self._desfire_command(_GET_FILE_IDS)
        return [file_id for file_id in data]

    def _get_file_settings(self, file_id):
        data = self._desfire_command(_GET_FILE_SETTINGS, bytes([file_id & 0xFF]))
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
            chunk_size = remaining
            if chunk_size > _MAX_READ_SIZE:
                chunk_size = _MAX_READ_SIZE
            params = bytearray(7)
            params[0] = file_id & 0xFF
            params[1] = offset & 0xFF
            params[2] = (offset >> 8) & 0xFF
            params[3] = (offset >> 16) & 0xFF
            params[4] = chunk_size & 0xFF
            params[5] = (chunk_size >> 8) & 0xFF
            params[6] = (chunk_size >> 16) & 0xFF
            data.extend(self._desfire_command(_READ_DATA, params))
            offset += chunk_size
            remaining -= chunk_size
        return bytes(data)

    def _desfire_command(self, ins, data=b""):
        response = self._transceive_apdu(ins, data)
        payload = bytearray()

        while True:
            if len(response) < 2:
                raise ValueError("DESFire response too short")

            payload.extend(response[:-2])
            if response[-2] != 0x91:
                raise ValueError("Unexpected DESFire status frame")

            status = response[-1]
            if status == _STATUS_OK:
                return bytes(payload)
            if status != _ADDITIONAL_FRAME:
                raise ValueError("DESFire command failed with status 0x{:02x}".format(status))

            response = self._transceive_apdu(_ADDITIONAL_FRAME)

    def _transceive_apdu(self, ins, data=b""):
        if data:
            apdu = bytearray(6 + len(data))
            apdu[0] = _WRAP_CLA
            apdu[1] = ins & 0xFF
            apdu[2] = 0x00
            apdu[3] = 0x00
            apdu[4] = len(data) & 0xFF
            apdu[5:5 + len(data)] = data
            apdu[-1] = 0x00
        else:
            apdu = bytes([_WRAP_CLA, ins & 0xFF, 0x00, 0x00, 0x00])

        response = self.transceive(apdu)
        if response is None:
            raise ValueError("Empty DESFire response")
        return response

IsoDepTag.register_type(DesfireTag)
