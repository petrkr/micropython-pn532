# micropython-pn532

Small PN532 library for MicroPython.

Current scope:
- PN532 core
- SPI transport
- single-target ISO14443A discovery
- generic `NFCTag`
- typed `MifareClassic`
- `MifareClassicIO` for linear Mifare Classic data-block reads

Out of scope:
- UART/I2C transport
- multi-target inventory
- DESFire
- Type 4
- generic NDEF abstraction

`read_tag()` returns:
- `MifareClassic` for supported Classic tags
- `NFCTag` for unknown tags

Example:

```python
from machine import Pin, SPI

from pn532 import PN532
from pn532.transports.spi import SPITransport

spi = SPI(1, baudrate=1_000_000, polarity=0, phase=0)
ss = Pin(5, Pin.OUT, value=1)
reset = Pin(4, Pin.OUT, value=0)

transport = SPITransport(spi, ss, reset=reset)
pn532 = PN532(transport)
pn532.configure_sam()

while True:
    tag = pn532.read_tag(timeout=0.5)
    if tag is not None:
        print(tag)
```

Limitations:
- tested only over SPI
- `MifareClassicIO` is a raw linear stream over user data blocks
- 7-byte UID Mifare Classic auth is not resolved yet
