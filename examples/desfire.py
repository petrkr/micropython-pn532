from time import sleep
from ubinascii import hexlify

from machine import Pin, SPI

from pn532 import PN532
from pn532.tags.desfire import DesfireTag
from pn532.transports.spi import SPITransport


spi = SPI(1, baudrate=1_000_000, polarity=0, phase=0)
ss = Pin(10, Pin.OUT, value=1)

transport = SPITransport(spi, ss)
pn532 = PN532(transport)
pn532.configure_sam()

last_uid = None


def format_hex(data):
    return hexlify(data).decode() if data else ""


while True:
    tag = pn532.read_tag(timeout=0.5)
    if tag is None:
        if last_uid is not None:
            print("Card removed:", format_hex(last_uid))
            last_uid = None
        sleep(0.1)
        continue

    if not isinstance(tag, DesfireTag):
        continue

    if last_uid == tag.uid:
        continue

    last_uid = tag.uid
    print("Found target:", tag)

    applications = tag.applications
    print("Applications:", applications)
    if not applications:
        continue

    files = applications[0].files
    print("Files:", files)
    for desfire_file in files:
        print("File {} first 8: {}".format(
            desfire_file.file_id,
            format_hex(desfire_file.read(8)),
        ))
