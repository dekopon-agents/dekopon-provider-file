`pixel.png` is an original generated 1×1 black RGB PNG, not a photograph or downloaded fixture.
The fixture is dedicated to the public domain under CC0-1.0:
https://creativecommons.org/publicdomain/zero/1.0/

Generation (Python standard library):
```python
import struct, zlib
chunk = lambda t, b: struct.pack('>I', len(b)) + t + b + struct.pack('>I', zlib.crc32(t + b))
png = (b'\x89PNG\r\n\x1a\n'
       + chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0))
       + chunk(b'IDAT', zlib.compress(b'\0\0\0\0'))
       + chunk(b'IEND', b''))
open('pixel.png', 'wb').write(png)
```

PNG specification: https://www.w3.org/TR/png-3/
Other test vectors are original synthetic signature/box bytes in `src/identify_tests.rs`,
not complete JPEG/PDF/ZIP/HEIC/AVIF files. They intentionally exercise identification
without claiming to prove full-file or decoder validity. Test source is dual MIT/Apache-2.0.
