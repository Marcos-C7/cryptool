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
	'''
	Class to simplify the encryption and decryption of data presented either in text strings, raw bytes or files.
	'''
	def __init__(self):
		# The default text encoding when we encode/decode between 'str' and 'bytes'.
		self.encoding = "utf8"
		# The hash algorithm used in all the procedures 
		# The output length in Bytes can be obtained with '.digest_size'.
		self.hash_algorithm = hashes.SHA3_512()
		# The length in Bytes of the keys used to encrypt/decrypt.
		self.key_length = 32
		# The number of iterations when using a Key Derivation Function (KDF).
		self.kdf_iterations = 1000000
		# Function to generate salts (as raw bytes).
		self.salt = lambda: os.urandom(self.key_length)
		# The file extension used to save encrypted files.
		self.extension = "ctl"
	#
	
	def getKDF(self, salt, length=None):
		'''
		Defines a Key Derivation Function (KDF). This is useful to generate secure cryptographic keys from
		a simpler phrase like a password. Never generate two keys using the same pair (salt, password).
		This function is used in all the functions that use a KDF.
		Parameters:
		- salt [bytes]: raw bytes string of size 'self.key_length', use 'self.salt()' to obtain a secure salt..
		- length [int]: all the keys generated with the returned KDF will have this size in Bytes.
		Return:
		- A key derivation function.
		Usage:
		 - kdf = self.getKDF(salt, length)
		   key = kdf.derive(password)
		'''
		if length is None: length = self.key_length
		return PBKDF2HMAC(algorithm=self.hash_algorithm, length=length, salt=salt, iterations=self.kdf_iterations, backend=default_backend())
	#

	def getCipherAlgorithm(self, key):
		'''
		Defines a cipher algorithm used in a Cipher Object to encrypt data using the given key.
		This function is used in all the functions that use an encryption algorithm.
		Parameters:
		- key [bytes]: raw bytes string of size 'self.key_length' bytes used to encrypt the data.
		Return:
		- The encryption algorithm.
		Usage:
		- alg = self.getCipherAlgorithm(key)
		  cipher = Cipher(alg, mode, backend=default_backend()).encryptor()
		  decipher = Cipher(alg, mode, backend=default_backend()).decryptor()
		'''
		return algorithms.AES(key)
	#

	def msgToBytes(self, msg, enc=None):
		'''
		The cryptographic methods work on raw bytes. In order to simplify the usage of
		text strings, this function checks if the message is already in raw bytes and
		if not, then it is assumed to be a text string and encodes to raw bytes.
		Parameters:
		- msg [byes/str]: the message to safely convert to raw bytes.
		- enc [srt]: the encoding used to encode string objects, de default is 'self.encoding'.
		Return:
		- [bytes]: The raw bytes string.
		Usage:
		- msg = msgToBytes(msg)
		- msg = msgToBytes(msg, "cp1252")
		'''
		if enc == None: enc = self.encoding
		return msg if type(msg) == bytes else msg.encode(enc)
	#

	def getHash(self, msg):
		'''
		Generate a secure hash (no key used) of the given message. The hash algorithm is defined
		in 'self.hash_algorithm'. The resulting hash will have size 'self.hash_algorithm.digest_size'
		in bytes.
		Parameters:
		msg [bytes/str]: message to hash.
		Return:
		[bytes]: the raw bytes hash.
		Usage:
		- hash = self.getHash(msg)
		'''
		msg = self.msgToBytes(msg)
		hasher = hashes.Hash(self.hash_algorithm, backend=default_backend())
		hasher.update(msg)
		return hasher.finalize()
	#

	def getCredentialsFromPassword(self, password, length=None, salt=None):
		'''
		Creates a credentials card derived from the given 'password'. The credentials include a 
		cryptograhic key of the given 'length' and the salt used to generate the key from the 
		password. An optional 'salt' will can be provided to recover previously generated credentials.
		Remember that in order to generate the same password we need the same pair password-salt.
		Parameters:
		- password [bytes/str]: the password to derive the key.
		- length [int]: the lenght of the derived key, in bytes. The default is 'self.key_length'.
		- salt [bytes]: the salt used to generate the key. If not give, a new one will be generated.
		Return:
		[dict]: the credentials in the form of a dictionary with entries:
		- "key" [bytes]: the derived cryptographic key.
		- "salt" [bytes]: the salt used in combination with the password to generatet the key.
		Usage:
		- cred = self.getCredentialsFromPassword(password)
		  old_cred = self.getCredentialsFromPassword(password, cred["salt"])
		'''
		password = self.msgToBytes(password)
		if salt is None: salt = self.salt()
		kdf = self.getKDF(salt, length)
		return {"key":kdf.derive(password), "salt":salt}
	#

	def encryptMsg(self, msg, password):
		'''
		Encrypts the given message using the given password. The encrypted data is autenticated via a MAC
		signature. The result will be given in the form of an encryption card containing relevant information 
		about the encryption procedure and the result.
		Prameters:
		- msg [bytes/str]: the message to encrypt.
		- password [bytes/str]: the password used for the encryption.
		Return:
		[dict]: The encryption card in the form of a dictionary, with the following entries:
		- "status" [str]: "OK" if everyhing went well, otherwise an error message.
		- "signed_data" [bytes]: the encrypted message.
		Usage:
		- enc_card = self.encryptMsg(msg, password)
		  if enc_card["status"] == "OK": ... do something with enc_card["signed_data"] ...
		'''
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
		
		# data: ||b"\x80"||   salt   ||time||          iv               ||                   secret                         ||       signature             ||
		# size: ||   1   ||key_length|| 8  ||cipher algorithm block size||padded msg multiple of cipher algorithm block size||digest size of hash algorithm||
		# We include the time just in case we want to do something with it like expiration time.
		return {"status":"OK", "signed_data":data + hmac}
	#
	
	def decryptMsg(self, enc_card, password):
		'''
		Attempts to decrypt the data given in the encryption card, with the given password.
		If the encryted data is corrupted or the password is wrong, then an "invalid or 
		corrupted data" error will be returned. An encryption card is generated with the 
		'self.encryptMsg' method. Message authentication will be verified. The result will 
		be given in the form of a decryption card containing relevant information about the 
		decryption procedure and the result.
		Parameters:
		- enc_card [dict]: the card with the encrypted data.
		- password [bytes/str]: the password to use in the decryption.
		Return:
		[dict]: The decryption card in the form of a dictionary, with the following entries:
		- "status" [str]: "OK" if everyhing went well, otherwise an error message.
		- "msg" [bytes]: the dectypted message.
		- "enc_time" [struct_time]: the time when the message was encrypted.
		'''
		signed_data = enc_card["signed_data"]
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
		enc_time = struct.unpack(">Q", data[pos:pos + 8])[0]
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
		
		# The cipher algorithm.
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

	def encryptFile(self, password, input_path, output_name=None):
		'''
		Encripts the file given in 'input_path' and saves the resulting encrypted data
		to the file with path name given in 'output_name' but appending the extension
		'self.extension'.
		Parameters:
		- password [bytes/str]: the password used for the encryption.
		- input_path [str]: the absolute/relative path to the target file.
		- output_name [str]: the extension 'self.extension' will be appended to this path name.
		  The default output name is equal to 'input_path'.
		Return:
		[dict]: relevant data about the procedure, in the form of a dictionray with the entries:
		- "status" [str]: "OK" if everyhing went well, otherwise an error message.
		Usage:
		- res = self.encryptFile(password, "input/file", "output/name")
		'''
		# Default ouput file name.
		if output_name is None: output_name = input_path

		# Load the file as raw bytes.
		file = open(input_path, "rb")
		msg = file.read()
		file.close()

		# Encrypt the file bytes.
		enc_card = self.encryptMsg(msg, password)
		if enc_card["status"] != "OK":
			return {"status":enc_card["status"]}
		
		# Save the encrypted data to a file with extension 'self.extension'.
		file = open("%s.%s" % (output_name, self.extension), "wb")
		file.write(enc_card["signed_data"])
		file.close()

		return {"status":"OK"}
	#

	def decryptFile(self, password, input_path, output_path=None):
		# Separate the input path in the path name and the file extension.
		file_name, file_extension = os.path.splitext(input_path)
		# Default output file path.
		if output_path == None:
			if file_extension[1:] == self.extension:
				output_path = file_name
			else: return {"status":"Error: if the file has no extension '.%s' then 'output_path' must be given" % (self.extension)}
		
		# Load the encrypted file as raw bytes.
		file = open(input_path, "rb")
		signed_data = file.read()
		file.close()

		# Decrypt the file bytes.
		decrypted = self.decryptMsg(signed_data, password)
		if decrypted["status"] != "OK":
			return {"status":enc_card["status"]}

		# Save the decrypted data to a file.
		file = open(output_path, "wb")
		file.write(decrypted["msg"])
		file.close()

		return {"status":"OK"}
	#
#

if __name__ == "__main__":
	ct = Cryptool()
	#ct.encryptFile("Wallpapers.zip", "ZXCVBNM")
	#ct.decryptFile("Wallpapers.zip.ctl", "ZXCVBNM")
#

'''
# Used by fernet.
base64.urlsafe_b64encode(bytes)	: bytes -> base64 representation.
base64.urlsafe_b64decode(bytes)	: base64 representation -> bytes. (if there are padding problems, just append b"====" to the input)

base64.b64encode(bytes)	: bytes -> base64 representation.
base64.b64decode(bytes)	: base64 representation -> bytes. (if there are padding problems, just append b"====" to the input)

bytes.fromhex(hex)		: hex_str -> bytes.
bytes.hex()				: bytes -> hex_str.
'''