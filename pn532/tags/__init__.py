class NFCTag:
    _registry = []

    def __init__(self, pn532, number, atqa, sak, uid, ats=None):
        self._pn532 = pn532
        self.number = number
        self.atqa = bytes(atqa)
        self.sak = sak
        self.uid = bytes(uid)
        self.ats = bytes(ats or b"")

    @classmethod
    def register_type(cls, tag_cls):
        cls._registry.append(tag_cls)

    @classmethod
    def _resolve_type(cls, pn532, number, atqa, sak, uid, ats=None):
        for tag_cls in cls._registry:
            resolved_cls = tag_cls.resolve_type(atqa=atqa, sak=sak, uid=uid, ats=ats)
            if resolved_cls is not None:
                tag = resolved_cls(pn532, number, atqa, sak, uid, ats)
                active_type = getattr(tag, "_resolve_active_type", None)
                if active_type is not None:
                    resolved = active_type()
                    if resolved is not None:
                        resolved_cls, probe_data = resolved
                        tag = resolved_cls(pn532, number, atqa, sak, uid, ats)
                        tag._set_probe_data(probe_data)
                return tag
        return cls(pn532, number, atqa, sak, uid, ats)

    @classmethod
    def resolve_type(cls, *, atqa, sak, uid, ats=None):
        return None

    def __repr__(self):
        from ubinascii import hexlify
        return "<{} uid={} atqa={} sak=0x{:02x}{}>".format(
            self.__class__.__name__,
            hexlify(self.uid).decode(),
            hexlify(self.atqa).decode(),
            self.sak,
            " ats={}".format(hexlify(self.ats).decode()) if self.ats else "",
        )
