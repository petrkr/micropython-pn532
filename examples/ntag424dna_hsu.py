from time import sleep
from ubinascii import hexlify

from machine import UART, freq

from pn532 import PN532
from pn532.tags.ntag424dna import Ntag424DnaTag
from pn532.transports.hsu import HSUTransport


NFC_TX = 17
NFC_RX = 16

FILE_NAMES = {
    1: "CC",
    2: "NDEF",
    3: "proprietary",
}


def format_hex(data):
    return hexlify(data).decode() if data else ""


def probe_ntag424dna(tag):
    print("NTAG 424 DNA")
    print("UID={}".format(format_hex(tag.uid)))
    print("ATS={}".format(format_hex(tag.ats)))
    print("Version={}".format(format_hex(tag.version)))

    try:
        applications = tag.applications
    except Exception as e:
        print("Applications ERR {} {}".format(type(e).__name__, e))
        return

    for application in applications:
        print("DF name={}".format(format_hex(application.df_name)))
        for file in application.files:
            name = FILE_NAMES.get(file.file_id, "unknown")
            print(
                "File {:02x} ({}) size={} settings={}".format(
                    file.file_id, name, file.size, file.settings
                )
            )
            try:
                file.seek(0)
                data = file.read()
                print("  Data={}".format(format_hex(data)))
            except Exception as e:
                print("  Read ERR {} {}".format(type(e).__name__, e))


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
            print("Card removed: {}".format(format_hex(last_uid)))
            last_uid = None
        sleep(0.1)
        continue

    if last_uid == tag.uid:
        continue

    last_uid = tag.uid
    print("Found target:", tag)

    if not isinstance(tag, Ntag424DnaTag):
        print("Unsupported tag")
        continue

    probe_ntag424dna(tag)
