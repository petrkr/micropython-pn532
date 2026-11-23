from time import sleep
from ubinascii import hexlify

from machine import UART, freq

from pn532 import PN532
from pn532.tags.desfire import DesfireTag
from pn532.tags.isodep import IsoDepTag
from pn532.transports.hsu import HSUTransport


NFC_TX = 17
NFC_RX = 16


def format_hex(data):
    return hexlify(data).decode() if data else ""


def probe_desfire(tag):
    print("Desfire probe START")
    print("ATQA={}".format(format_hex(tag.atqa)))
    print("SAK=0x{:02x}".format(tag.sak))
    print("UID={}".format(format_hex(tag.uid)))
    print("ATS={}".format(format_hex(tag.ats)))

    if not isinstance(tag, DesfireTag):
        print("Desfire unsupported")
        print("Desfire probe FINISH")
        return

    try:
        applications = tag.applications
        print("Applications:", len(applications))
        for app in applications:
            print(app)
    except Exception as e:
        print("Desfire ERR {} {}".format(type(e).__name__, e))

    print("Desfire probe FINISH")


freq(240000000)

uart = UART(2, 115200)
uart.init(baudrate=115200, tx=NFC_TX, rx=NFC_RX, timeout=100)

transport = HSUTransport(uart)
pn532 = PN532(transport)

last_uid = None

while True:
    tag = pn532.read_tag(timeout=0.5)
    if tag is None:
        if last_uid is not None:
            print("Card removed:", format_hex(last_uid))
            last_uid = None
        sleep(0.1)
        continue

    if not isinstance(tag, IsoDepTag):
        continue

    if last_uid == tag.uid:
        continue

    last_uid = tag.uid
    print("Found target:", tag)
    probe_desfire(tag)
