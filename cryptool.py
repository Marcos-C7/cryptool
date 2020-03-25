#!/usr/bin/env python
# -*- coding: utf8 -*-

#import hmac
#import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC

import base64
import os
import time
import struct
import pdb




class Cryptool:
	def __init__(self):
		# The default encoding when we encode/decode between 'str' and 'bytes'.
		self.encoding = "utf8"
		# The hash algorithm used in all the procedures (length in bytes can be obtained with '.digest_size').
		self.hash_algorithm = hashes.SHA3_512()
		# The length of the keys used to encrypt/decrypt.
		self.key_length = 32
		# The number of iterations when using a Key Derivation Function (KDF).
		self.kdf_iterations = 1000000
		# Function to generate salts (as raw bytes).
		self.salt = lambda: os.urandom(self.key_length)
	#

	# This function should be used to obtain the default Key Derivation Function (KDF).
	def getKDF(self, salt, length=None):
		if length is None: length = self.key_length
		return PBKDF2HMAC(algorithm=self.hash_algorithm, length=length, salt=salt, iterations=self.kdf_iterations, backend=default_backend())
	#

	def getCipherAlgorithm(self, key):
		return algorithms.AES(key)
	#

	# If the message is not a 'bytes' object then it is assumed to be an 'str' object.
	def msgToBytes(self, msg, enc=None):
		if enc == None: enc = self.encoding
		return msg if type(msg) == bytes else msg.encode(enc)
	#

	# Returns the hash as raw bytes.
	def getHash(self, msg):
		msg = self.msgToBytes(msg)
		hasher = hashes.Hash(self.hash_algorithm, backend=default_backend())
		hasher.update(msg)
		return hasher.finalize()
	#

	# Returns the key and the used salt as raw bytes. You can specify the 'length' of the key in Bytes.
	# The returned key is not for storage.
	def getCredentialsFromPassword(self, password, length=None, salt=None):
		password = self.msgToBytes(password)
		if salt is None: salt = self.salt()
		kdf = self.getKDF(salt, length)
		return {"key":kdf.derive(password), "salt":salt}
	#

	# Output: ||b"\x80"||   salt   ||time||          iv               ||                   secret                         ||       signature
	# Sizes:  ||   1   ||key_length|| 8  ||cipher algorithm block size||padded msg multiple of cipher algorithm block size||digest size of hash algorithm
	# Only gets signed the parts between the [[ and ]].
	# We include the time just in case we want to do something with it like data expiration.
	def encryptMsg(self, msg, password):
		msg = self.msgToBytes(msg)
		# Generat keys for encryption and one for autentication at once derived from the same password.
		credentials = self.getCredentialsFromPassword(password, length=self.key_length + self.hash_algorithm.digest_size)
		key_enc = credentials["key"][:self.key_length]
		key_aut = credentials["key"][self.key_length:]
		# The block cipher algorithm.
		algorithm = self.getCipherAlgorithm(key_enc)
		# The mode of encryption (the iv must be the same size as the block size of the cipher algorithm in Bytes).
		iv = os.urandom(algorithm.block_size // 8)
		mode = modes.CBC(iv)
		# Create the cipher.
		cipher = Cipher(algorithm, mode, backend=default_backend()).encryptor()
		# In order to use the CBC mode, we need padding in the message.
		padder = padding.PKCS7(algorithm.block_size).padder()
		padded_msg = padder.update(msg) + padder.finalize()
		# Encrypt the data.
		secret = cipher.update(padded_msg) + cipher.finalize()
		# Merge all the components that need to be signed.
		current_time = int(time.time())
		data = b"\x80" + credentials["salt"] + struct.pack(">Q", current_time) + iv + secret
		# Generate the signature. The signature will have the same size as the used hash algorithm.
		signer = HMAC(key_aut, self.hash_algorithm, backend=default_backend())
		signer.update(data)
		hmac = signer.finalize()
		
		return data + hmac
	#
	
		
	def decryptMsg(self, signed_data, password):
		# Validate the first byte of the signed_data.
		if signed_data[0] != 0x80:
			return {"status":"Error: invalid or corrupted data"}
		# Separate the data from the signature.
		data = signed_data[:-self.hash_algorithm.digest_size]
		hmac = signed_data[-self.hash_algorithm.digest_size:]

		# Get some parts of the data.
		pos = 1
		salt = data[pos:pos + self.key_length]
		pos += self.key_length
		enc_time = struct.unpack(">Q", data[pos:pos + 8])
		pos += 8
		
		# Obtain the credentials.
		credentials = self.getCredentialsFromPassword(password, length=self.key_length + self.hash_algorithm.digest_size, salt=salt)
		key_enc = credentials["key"][:self.key_length]
		key_aut = credentials["key"][self.key_length:]

		# Validate the signature.
		signer = HMAC(key_aut, self.hash_algorithm, backend=default_backend())
		signer.update(data)
		try:
			signer.verify(hmac)
		except InvalidSignature:
			return {"status":"Error: invalid or corrupted data"}
		
		# The block cipher algorithm.
		algorithm = self.getCipherAlgorithm(key_enc)

		# Get the other parts of the data.
		iv = data[pos:pos + algorithm.block_size // 8]
		pos += algorithm.block_size // 8
		secret = data[pos:]
		
		# The mode of encryption (the iv must be the same size as the block size of the cipher algorithm in Bytes).
		mode = modes.CBC(iv)
		# Decrypt the message.
		decipher = Cipher(algorithm, mode, backend=default_backend()).decryptor()
		padded_msg = decipher.update(secret)
		try:
			padded_msg += decipher.finalize()
		except ValueError:
			return {"status":"Error: invalid or corrupted data"}
		
		# Remove padding
		unpadder = padding.PKCS7(algorithm.block_size).unpadder()
		msg = unpadder.update(padded_msg)
		try:
			msg += unpadder.finalize()
		except ValueError:
			return {"status":"Error: invalid or corrupted data"}
		
		return {"status":"OK", "msg":msg, "enc_time":time.localtime(enc_time)}
	#
#

if __name__ == "__main__":
	ct = Cryptool()
	#k = Fernet.generate_key()
	#x = ct.getCredentialsFromPassword("Jamás")
	k = ct.getCredentialsFromPassword("Hola", 3)
	s = ct.encryptMsg("Hola Jamas", "hola")
	p = ct.decryptMsg(s, "hola")
#

'''
# Used by fernet.
base64.urlsafe_b64encode(bytes)	: bytes -> base64 representation.
base64.urlsafe_b64decode(bytes)	: base64 representation -> bytes. (if there are padding problems, just append b"====" to the input)

base64.b64encode(bytes)	: bytes -> base64 representation.
base64.b64decode(bytes)	: base64 representation -> bytes. (if there are padding problems, just append b"====" to the input)

bytes.fromhex(hex)		: hex_str -> bytes.
bytes.hex()				: bytes -> hex_str.

Fernet.generate_key()	: generates rantom 32-Byte/256-bit key.
os.urandom(bytes_size)	: random unpredictable bytes-string of the given size.
'''