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
___

We can obtain the hash of a message given by either a raw bytes string or a text string:
```python
h = ct.getHash(b"message")
h = ct.getHash("message")
```
We can sign a message via an HMAC authenication code:
```python
signed_msg = ct.signMsg(b"message")
```
We can validate a message signed by the previous method:
```python
validation = ct.validateSgnatureMsg(signed_msg)
```
___

We can encrypt and sign a message using a password. We can include a `source` tag that will be
returned when we decrypt the message in the future. The possible tags are 
`"bytes"`, `"str"`, `"file"` or `"dir"`:
```python
enc_card = ct.encryptMsg("message", "my password", source="str")
if enc_card["status"] == "OK":
	#... do something with enc_card["signed_data"] ...
```
We can decrypt a message encrypted by the previous method:
```python
dec_card = ct.decryptMsg(enc_card, "my password")
if dec_card["status"] == "OK":
	#... do something with dec_card["msg"] ...
```
___

We can directly encrypt a file, and append a source tag to the encryption to cover the
the case when a file is an intermediate step when encrypting a different source of data:
```python
res = ct.encryptFile("my password", "input/file.ext", "output/name", source="file")
```

We can directly encrypt a directory into a single encrypted file:
```python
res = ct.encryptDir("my password", "input/directory", "output/name")
```

We can directly decrypt a file encrypted by either of the previous functions. 
If the encryption corresponds to a directory then its content will be placed in the directory
given by the output path parameter:
```python
res = ct.decryptFile("my password", "input/path", "output/path")
```
