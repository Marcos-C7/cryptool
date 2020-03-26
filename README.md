# cryptool

Simplified interface for encrypting and decrypting: raw bytes, text, files and directories.

---

Import the Cryptool class with:
```python
from cryptool import Cryptool
```

We can create a Cryptool object with:
```python
ct = Cryptool()
```

We can obtain the hash of a raw bytes string or a text string. For text strings, they will be
encoded to raw bytes with the encoding defined in `ct.encoding`. The result is a `bytes` object
of size `ct.hash_algorithm.digest_size`:
```python
hash = ct.getHash(b"bytes string")
hash = ct.getHash("text string")
```


