class NFCTag:
    def __new__(cls, pn532, number, atqa, sak, uid, ats=None):
        if cls is NFCTag:
            if sak in (0x08, 0x18):
                from pn532.tags.mifare_classic import MifareClassic
                return MifareClassic(pn532, number, atqa, sak, uid, ats)
            # elif sak == 0x20:
            #     from pn532.tags.desfire import DESFire
            #     return DESFire(pn532, number, atqa, sak, uid, ats)
        return object.__new__(cls)

    def __init__(self, pn532, number, atqa, sak, uid, ats=None):
        self._pn532 = pn532
        self.number = number
        self.atqa = bytes(atqa)
        self.sak = sak
        self.uid = bytes(uid)
        self.ats = bytes(ats or b"")

    def __repr__(self):
        from ubinascii import hexlify
        return "<{} uid={} atqa={} sak=0x{:02x}{}>".format(
            self.__class__.__name__,
            hexlify(self.uid).decode(),
            hexlify(self.atqa).decode(),
            self.sak,
            " ats={}".format(hexlify(self.ats).decode()) if self.ats else "",
        )
