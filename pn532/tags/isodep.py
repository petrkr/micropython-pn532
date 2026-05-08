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
        for tag_cls in cls._registry:
            resolved_cls = tag_cls.resolve_type(atqa=atqa, sak=sak, uid=uid, ats=ats)
            if resolved_cls is not None:
                return resolved_cls
        return cls

    def transceive(self, data, response_length=255):
        response = self._pn532.in_data_exchange(
            bytes(data),
            response_length=response_length,
            target_number=self.number,
        )
        return bytes(response) if response is not None else None


NFCTag.register_type(IsoDepTag)
