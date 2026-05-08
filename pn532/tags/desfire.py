from micropython import const

from pn532.tags.isodep import IsoDepTag

_DESFIRE_ATQA = b"\x03\x44"
_DESFIRE_SAK = const(0x20)
_WRAP_CLA = const(0x90)
_GET_APPLICATION_IDS = const(0x6A)
_SELECT_APPLICATION = const(0x5A)
_GET_FILE_IDS = const(0x6F)
_GET_FILE_SETTINGS = const(0xF5)
_ADDITIONAL_FRAME = const(0xAF)
_STATUS_OK = const(0x00)


class DesfireTag(IsoDepTag):
    @classmethod
    def resolve_type(cls, *, atqa, sak, uid, ats=None):
        if bytes(atqa) == _DESFIRE_ATQA and sak == _DESFIRE_SAK and bool(ats):
            return cls
        return None

    def list_applications(self):
        data = self._desfire_command(_GET_APPLICATION_IDS)
        applications = []
        for idx in range(0, len(data), 3):
            applications.append(bytes(data[idx:idx + 3]))
        return applications

    def select_application(self, aid):
        if len(aid) != 3:
            raise ValueError("AID must be 3 bytes")
        self._desfire_command(_SELECT_APPLICATION, aid)
        return True

    def get_file_ids(self):
        data = self._desfire_command(_GET_FILE_IDS)
        return [file_id for file_id in data]

    def get_file_settings(self, file_id):
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

        self.last_apdu_tx = bytes(apdu)
        response = self.transceive(apdu)
        if response is None:
            raise ValueError("Empty DESFire response")
        self.last_apdu_rx = bytes(response)
        return response

IsoDepTag.register_type(DesfireTag)
