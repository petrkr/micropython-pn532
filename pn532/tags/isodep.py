from pn532.tags import NFCTag


class IsoDepTag(NFCTag):
    _registry = []

    @classmethod
    def register_type(cls, tag_cls):
        cls._registry.append(tag_cls)

    @classmethod
    def resolve_type(cls, *, atqa, sak, uid, ats=None):
        if not (sak == 0x20 and bool(ats)):
            return None
        return cls

    def _resolve_active_type(self):
        for tag_cls in self._registry:
            try:
                probe_data = tag_cls.probe(self)
            except (RuntimeError, ValueError):
                continue
            if probe_data is not None:
                return tag_cls, probe_data
        return None

    def transceive(self, data, response_length=255):
        response = self._pn532.in_data_exchange(
            bytes(data),
            response_length=response_length,
            target_number=self.number,
        )
        return bytes(response) if response is not None else None

    def transceive_apdu(self, cla, ins, p1=0x00, p2=0x00, data=b""):
        data = bytes(data)
        if len(data) > 0xFF:
            raise ValueError("APDU data is too long")
        if data:
            apdu = bytearray(6 + len(data))
            apdu[0] = cla & 0xFF
            apdu[1] = ins & 0xFF
            apdu[2] = p1 & 0xFF
            apdu[3] = p2 & 0xFF
            apdu[4] = len(data)
            apdu[5:-1] = data
            apdu[-1] = 0x00
        else:
            apdu = bytes([cla & 0xFF, ins & 0xFF, p1 & 0xFF, p2 & 0xFF, 0x00])
        response = self.transceive(apdu)
        if response is None:
            raise ValueError("Empty ISO-DEP response")
        return response


NFCTag.register_type(IsoDepTag)
