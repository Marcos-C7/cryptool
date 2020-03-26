# cryptool

Simplified interface for encrypting and decrypting: raw bytes, text, files and directories.

Read full documentation [here](https://marcos-c7.github.io/cryptool/html/classcryptool_1_1cryptool_1_1Cryptool.html)

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

We can create a credentials card based on a password that contains a salt and a key.
We can chose the size in bytes of the generated key. If no size is given then the size
will be `ct.key_length`. A salt of size `ct.key_length` can be given or it will be 
ramdomly generated.
```python
cred = ct.getCredentialsFromPassword("my password", 32)
key, salt = cred["key"], cred["salt"]
recovered_cred = ct.getCredentialsFromPassword("my password", 32, salt)
```

We can encrypt a raw bytes string message or a text string message using a password. For text strings, 
they will be encoded to raw bytes with the encoding defined in `ct.encoding`. We can include information
about the source of the data so that we know what to do after decrypting the data in the future. 
The possible values for `source` are `"bytes"`, `"str"`, `"file"` or `"dir"`.
The result is an encryption card in form of dictionary with entries `"status"` and `"signed_data"`.
The status is `"OK"` if the encryption went well, otherwise it will report an error. The signed data
is the encrypted and authenticated (signed) data.
```python
enc_card = ct.encryptMsg("my secret", "my password", source="str")
if enc_card["status"] == "OK":
	#... do something with enc_card["signed_data"] ...
```

If we encrypted a message using `ct.encryptMsg`, we can decrypt it with `ct.decryptMsg`.
The result will be a decryption card in form of dictionray with entires: `"status"` equal
to `"OK"` if the decryption went well, `"msg"` the decrypted message, `"source"` the source
tag used during encryption, and `"enc_time"` the time when the message was encrypted.
```python
dec_card = ct.decryptMsg(enc_card, "my password")
if dec_card["status"] == "OK":
	#... do something with dec_card["msg"] ...
```

We can directly encrypt a file and append a source tag to the encryption.
The encrypted file will have name given by the ouput name and extension 
as defined in `ct.extension`. The only entry in the response is `"status"`.
```python
res = ct.encryptFile("my password", "input/file", "output/name", source="file")
```

We can directly encrypt a directory into a single encrypted file.
The encrypted file will have name given by the ouput name and extension 
as defined in `ct.extension`. The only entry in the response is `"status"`.
```python
res = ct.encryptDir("my password", "input/path", "output/name")
```

We can decrypt an encrypted file. If the content of the file is a single file,
then the name of the decrypted file will have name given by the output path.
If the content is a directory then its content will be placed in the directory
given by the output path. The only entry in the response is `"status"`.
```python
res = ct.decryptFile("my password", "input/path", "output/path")
```
