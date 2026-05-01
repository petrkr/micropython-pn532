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
    def resolve_type(cls, pn532, number, atqa, sak, uid, ats=None):
        for tag_cls in cls._registry:
            if tag_cls.matches(atqa=atqa, sak=sak, uid=uid, ats=ats):
                return tag_cls(pn532, number, atqa, sak, uid, ats)
        return cls(pn532, number, atqa, sak, uid, ats)

    @classmethod
    def matches(cls, *, atqa, sak, uid, ats=None):
        return False

    def __repr__(self):
        from ubinascii import hexlify
        return "<{} uid={} atqa={} sak=0x{:02x}{}>".format(
            self.__class__.__name__,
            hexlify(self.uid).decode(),
            hexlify(self.atqa).decode(),
            self.sak,
            " ats={}".format(hexlify(self.ats).decode()) if self.ats else "",
        )
