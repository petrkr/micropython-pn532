from machine import Pin, SPI

from pn532 import PN532
from pn532.transports.spi import SPITransport


spi = SPI(1, baudrate=1_000_000, polarity=0, phase=0)
ss = Pin(10, Pin.OUT, value=1)

transport = SPITransport(spi, ss)
pn532 = PN532(transport)
pn532.configure_sam()


while True:
    tag = pn532.read_tag(timeout=0.5)
    if tag is None:
        continue

    print("Found target:", tag)
    print("ATQA:", tag.atqa)
    print("SAK: 0x{:02x}".format(tag.sak))
    print("UID:", tag.uid)
    print("ATS:", tag.ats)
