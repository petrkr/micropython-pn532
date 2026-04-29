class PassiveTarget:
    def __init__(self, number, atqa, sak, uid, ats=None):
        self.number = number
        self.atqa = bytes(atqa)
        self.sak = sak
        self.uid = bytes(uid)
        self.ats = bytes(ats or b"")

    @classmethod
    def from_bytes(cls, data):
        if not data:
            return None
        if data[0] != 0x01:
            raise RuntimeError("More than one target detected!")
        if len(data) < 6:
            raise RuntimeError("Incomplete target response!")
        uid_len = data[5]
        if uid_len > 10:
            raise RuntimeError("Found target with unexpectedly long UID!")

        uid_start = 6
        uid_end = uid_start + uid_len
        if len(data) < uid_end:
            raise RuntimeError("Incomplete target UID!")

        return cls(
            data[1],
            data[2:4],
            data[4],
            data[uid_start:uid_end],
            data[uid_end:],
        )

    @property
    def dep(self):
        return bool(self.sak & 0x20)

    @property
    def classic(self):
        return self.sak in (0x08, 0x18)

    @property
    def random_uid(self):
        return len(self.uid) == 4 and self.uid[0] == 0x08

    def __repr__(self):
        return (
            "PassiveTarget(number={}, atqa={!r}, sak=0x{:02x}, "
            "uid={!r}, ats={!r})"
        ).format(self.number, self.atqa, self.sak, self.uid, self.ats)
