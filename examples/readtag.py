from machine import Pin, SPI, UART

from pn532 import PN532
from pn532.transports.spi import SPITransport
from pn532.transports.hsu import HSUTransport

NFC_TX = 17
NFC_RX = 16

# SPI
#spi = SPI(1, baudrate=1_000_000, polarity=0, phase=0)
#ss = Pin(10, Pin.OUT, value=1)
#transport = SPITransport(spi, ss)

# UART
hsu = UART(2, 115200, tx=NFC_TX, rx=NFC_RX)
transport = HSUTransport(hsu)

pn532 = PN532(transport)
print(pn532.firmware_version)


while True:
    tag = pn532.read_tag(timeout=0.5)
    if tag is None:
        continue

    print("Found target:", tag)
    print("ATQA:", tag.atqa)
    print("SAK: 0x{:02x}".format(tag.sak))
    print("UID:", tag.uid)
    print("ATS:", tag.ats)
