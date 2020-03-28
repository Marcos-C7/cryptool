#!/usr/bin/env python
# -*- coding: utf8 -*-


#import base64
import os
import time
import struct
import shutil
import getpass
import pdb


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.exceptions import InvalidSignature



class Cryptool:
	'''
	Class to simplify the encryption and decryption of data presented either in raw bytes, text strings, files or directories.
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

		# In case we change the encrypted data structure in the future, we will append to the encrypted message
		# an encryption version. In this way we can support compatibility with data enctypted with old versions.
		self._enc_version = 1
		# TAGS used to determine how to process the decrypted data.
		# bytes:raw bytes string | str:text string | file:a file | dir:a directory
		self._sources = {"bytes":1, "str":2, "file":3, "dir":4}
		# The reverse mapping of the sources.
		self._sources_r = {v:k for k,v in self._sources.items()}
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

	def getKDF(self, salt, length=None):
		'''
		Defines a Key Derivation Function (KDF). This is useful to generate secure cryptographic keys from
		a simpler phrase like a password. The same pair password-salt always generates the same password of
		the given length. This function is used in all the functions that use a KDF.
		Parameters:
		- salt [bytes]: raw bytes string of size 'self.key_length', use 'self.salt()' to obtain a secure salt.
		- length [int]: the key generated with the returned KDF will have this size in Bytes.
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

	def signMsg(self, msg, password):
		'''
		Signs the given message. This procedure ensures that a message can not be altered without
		detecting it.
		Parameters:
		- msg [bytes/str]: the message to sign.
		- password [bytes/str]: the password to use for signing the message.
		Return:
		[bytes]: the raw bytes string that contains both the messsage and the signature.
		Usage:
		- signed_msg = self.signMsg("my message", "my password")
		'''
		msg = self.msgToBytes(msg)
		cred = self.getCredentialsFromPassword(password, length=self.hash_algorithm.digest_size)
		data = b"\x80" + cred["salt"] + msg
		# Generate the signature. The signature will have the same size as the hash algorithm digest.
		signer = HMAC(cred["key"], self.hash_algorithm, backend=default_backend())
		signer.update(data)
		signature = signer.finalize()
		return data + signature
	#

	def validateSgnature(self, signed_data, password):
		'''
		Validates a signature created by 'self.signMsg'.
		Prameters:
		- signed_data [bytes]: the signed message to authenticate.
		- password [bytes/str]: the password used for signing the message.
		Return:
		[dict]: relevant data about the validation, in the form of a dictionray with the entries:
		- "status" [str]: "OK" if the message got successfully authenticated, otherwise an error message.
		- "msg" [bytes]: the raw bytes string containing the original message.
		Usage:
		- validation = self.validateSgnature(signed_data, "my password")
		  if validation["status"] == "OK": ... do something with validation["msg"] ...
		'''
		# Check that the string starts well.
		if signed_data[0] != 0x80:
			return {"status":"Error: invalid or corrupted data"}

		# Split the signed message.
		salt = signed_data[1:1 + self.key_length]
		data = signed_data[:-self.hash_algorithm.digest_size]
		signature = signed_data[-self.hash_algorithm.digest_size:]

		# Verify the signature.
		cred = self.getCredentialsFromPassword(password, length=self.hash_algorithm.digest_size, salt=salt)
		signer = HMAC(cred["key"], self.hash_algorithm, backend=default_backend())
		signer.update(data)
		try:
			signer.verify(signature)
		except InvalidSignature:
			return {"status":"Error: invalid or corrupted data"}
		
		return {"status":"OK", "msg":data[1 + self.key_length:]}
	#

	def encryptMsg(self, msg, password, source="bytes"):
		'''
		Encrypts the given message using the given password. The encrypted data is autenticated via a MAC
		signature. We can tell the 'source' where the data comes from, so that we can determine 
		when we decrypt data if a special post-processing is needed. The diferent sources are:
		"bytes":raw bytes string | "str":text string | "file":a file | "dir":a directory
		The result will be given in the form of an encryption card containing relevant information about 
		the encryption procedure and the result.
		Prameters:
		- msg [bytes/str]: the message to encrypt.
		- password [bytes/str]: the password to use for the encryption.
		- source [str]: "bytes", "str", "file" or "dir". The default is "bytes".
		Return:
		[dict]: The encryption card in the form of a dictionary, with the following entries:
		- "status" [str]: "OK" if everyhing went well, otherwise an error message.
		- "coded_data" [bytes]: the encrypted message.
		Usage:
		- enc_card = self.encryptMsg(msg, password)
		  if enc_card["status"] == "OK": ... do something with enc_card["coded_data"] ...
		'''
		msg = self.msgToBytes(msg)
		# Generat keys for the encryption of the msg.
		credentials = self.getCredentialsFromPassword(password, length=self.key_length)
		
		# The block cipher algorithm.
		algorithm = self.getCipherAlgorithm(credentials["key"])
		# In order to use the CBC mode, we need padding in the message.
		padder = padding.PKCS7(algorithm.block_size).padder()
		padded_msg = padder.update(msg) + padder.finalize()
		# The mode of encryption (the iv must be the same size as the block size of the cipher algorithm in Bytes).
		iv = os.urandom(algorithm.block_size // 8)
		mode = modes.CBC(iv)
		# Create the cipher and encrypt the padded message.
		cipher = Cipher(algorithm, mode, backend=default_backend()).encryptor()
		secret = cipher.update(padded_msg) + cipher.finalize()

		# Merge all the components that need to be signed.
		current_time = int(time.time())
		source_flag = struct.pack(">Q", self._sources.get(source, "bytes"))
		enc_version_flag = struct.pack(">Q", self._enc_version)
		# data: version||source||   salt   ||time||          iv               ||                   secret                         ||
		# size:    8   ||   8  ||key_length|| 8  ||cipher algorithm block size||padded msg multiple of cipher algorithm block size||
		data = enc_version_flag + source_flag + credentials["salt"] + struct.pack(">Q", current_time) + iv + secret

		# Sign the data.
		coded_data = self.signMsg(data, password)
		
		# We include the time just in case we want to do something with it like expiration time.
		return {"status":"OK", "coded_data":coded_data}
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
		- enc_card [dict]: the card with the encrypted data, must have at least the entry
		  "coded_data" mapping to the raw bytes string to decrypt.
		- password [bytes/str]: the password to use in the decryption.
		Return:
		[dict]: The decryption card in the form of a dictionary, with the following entries:
		- "status" [str]: "OK" if everyhing went well, otherwise an error message.
		- "msg" [bytes]: the dectypted message.
		- "source" [str]: the 'source' where the data comes from, one of "bytes", "str", 
		  "file" or "dir". See the documentation of 'self.encryptMsg' for more information.
		- "enc_time" [struct_time]: the time when the message was encrypted.
		'''
		# Validate the signature.
		validation = self.validateSgnature(enc_card["coded_data"], password)
		if validation["status"] != "OK":
			return {"status":"Error: invalid or corrupted data"}
		data = validation["msg"]

		# Get some parts of the data.
		pos = 0
		enc_version = struct.unpack(">Q", data[pos:pos + 8])[0]
		pos += 8
		source_id = struct.unpack(">Q", data[pos:pos + 8])[0]
		pos += 8
		salt = data[pos:pos + self.key_length]
		pos += self.key_length
		enc_time = struct.unpack(">Q", data[pos:pos + 8])[0]
		pos += 8

		# Obtain the credentials.
		credentials = self.getCredentialsFromPassword(password, length=self.key_length, salt=salt)
		# The cipher algorithm.
		algorithm = self.getCipherAlgorithm(credentials["key"])

		# We need the algorithm before separating the remaining parts.
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
		
		source = self._sources_r[source_id]
		return {"status":"OK", "msg":msg, "source":source, "enc_time":time.localtime(enc_time)}
	#

	def encryptFile(self, password, input_path, output_name=None, source="file"):
		'''
		Encripts the file given in 'input_path' and saves the resulting encrypted data
		to the file with path name given in 'output_name' but appending the extension
		'self.extension'. Is not output name is given then 'input_path' will be used.
		We can change the tag of the 'source' of the data, in case we want to use files
		as intermediate steps during encryption of other type of sources.
		Parameters:
		- password [bytes/str]: the password to use for the encryption.
		- input_path [str]: the absolute/relative path to the target file.
		- output_name [str]: the extension 'self.extension' will be appended to this path name.
		  The default output name is equal to 'input_path'.
		- source [str]: "bytes", "str", "file" or "dir". The default is "file". See the 
		  documentation of 'self.encryptMsg' for more information.
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
		enc_card = self.encryptMsg(msg, password, source)
		if enc_card["status"] != "OK":
			return {"status":enc_card["status"]}
		
		# Save the encrypted data to a file with extension 'self.extension'.
		file = open("%s.%s" % (output_name, self.extension), "wb")
		file.write(enc_card["coded_data"])
		file.close()

		return {"status":"OK"}
	#

	def encryptDir(self, password, input_path, output_name=None):
		'''
		Encripts the directory (with all its content) given in 'input_path' and saves 
		the resulting encrypted data to the file with path name given in 'output_name'
		but appending the extension 'self.extension'.
		Parameters:
		- password [bytes/str]: the password to use for the encryption.
		- input_path [str]: the absolute/relative path to the target directory.
		- output_name [str]: the extension 'self.extension' will be appended to this path name.
		  The default output name is equal to 'input_path'.
		Return:
		[dict]: relevant data about the procedure, in the form of a dictionray with the entries:
		- "status" [str]: "OK" if everyhing went well, otherwise an error message.
		Usage:
		- res = self.encryptFile(password, "input/file", "output/name")
		'''
		# Make sure the input path is a directory.
		if not os.path.isdir(input_path):
			return {"status":"Error: the input path is not a directory"}
		
		# Default ouput file name.
		if output_name is None: output_name = input_path
		
		# Compress the directory to a temporal file.
		shutil.make_archive(output_name, "zip", root_dir=input_path)
		
		# Encrypt the compresed file.
		res = self.encryptFile(password, output_name + ".zip", output_name, "dir")
		if res["status"] != "OK":
			return {"status":res["status"]}

		# Remove the compressed file.
		os.remove(output_name + ".zip")

		return {"status":"OK"}
	#

	def decryptFile(self, password, input_path, output_path=None):
		'''
		Decripts the file given in 'input_path' and saves the resulting decrypted data
		to the file with path name given in 'output_path'. If the encrypted data corresponds
		to a directory, then its content will be placed in the directory 'output_path'.
		If no output path is given, then it is necessary that the input file has extension
		'self.extension' in order to take the input path as the output path without such 
		extension. If the output path/directory already exists, it will be replaced.
		Parameters:
		- password [bytes/str]: the password to use for the decryption.
		- input_path [str]: the absolute/relative path to the target file.
		- output_path [str]: the path of the output file.
		Return:
		[dict]: relevant data about the procedure, in the form of a dictionray with the entries:
		- "status" [str]: "OK" if everyhing went well, otherwise an error message.
		Usage:
		- res = self.decryptFile(password, "input/file", "output/file")
		'''
		# Separate the input path in the path name and the file extension.
		file_name, file_extension = os.path.splitext(input_path)
		# Default output file path.
		if output_path == None:
			if file_extension[1:] == self.extension:
				output_path = file_name
			else: return {"status":"Error: if the file has no extension '.%s' then 'output_path' must be given" % (self.extension)}
		
		# Load the encrypted file as raw bytes.
		file = open(input_path, "rb")
		coded_data = file.read()
		file.close()

		# Decrypt the file bytes.
		decrypted = self.decryptMsg({"coded_data":coded_data}, password)
		if decrypted["status"] != "OK":
			return {"status":decrypted["status"]}

		# Save the decrypted data.
		output_path_final = output_path + (".zip" if decrypted["source"] == "dir" else "")
		file = open(output_path_final, "wb")
		file.write(decrypted["msg"])
		file.close()

		# Check if the data corresponds to a directory, to zip it and decompress 
		# it to the folder 'output_path'.
		if decrypted["source"] == "dir":
			shutil.unpack_archive(output_path_final, output_path, "zip")
			os.remove(output_path_final)

		return {"status":"OK"}
	#
#

def main():
	ct = Cryptool()
	# Present the options.
	options = {"1":"Encrypt file/directory", "2":"Decrypt file/directory"}
	options_str = "\n".join(["(%s) %s" % (i,v) for i,v in options.items()])
	option = input("Select an option:\n\n%s\n\nSelection: " % options_str)
	print("-" * 20)
	
	# Make sure a valid option was selected.
	if option not in options.keys():
		return {"status":"Error: the selected option is not valid. Valid options: {%s}\n" % ", ".join(options.keys())}

	# Get the input path and make sure it exists.
	input_path = input("File/directory path: ")
	input_path = input_path.strip().strip('"')
	if not os.path.exists(input_path):
		return {"status":"Error: the specified path does not exist\n"}
	
	if option == "1":
		# Get the ouput name and check if it exists, if it does confirm for replace.
		print("\nEnter the encrypted file name (.%s will be appended)." % ct.extension)
		print("The default is '%s'" % input_path)
		output_name = input("Name: ") or input_path
		output_name_ext = "%s.%s" % (output_name, ct.extension)
		if os.path.exists(output_name_ext):
			replace = input("File %s already exists. Replace? (y/n): " % output_name_ext)
			if replace[0].lower() == "n": return {"status":"Warning: output file already exists, won't replace."}
		# Get the password securely.
		password = getpass.getpass("Password (won't echo): ")
		# Encrypt depending if the path corresponds to a file or a directory.
		if os.path.isfile(input_path):
			res = ct.encryptFile(password, input_path, output_name)
		else:
			res = ct.encryptDir(password, input_path, output_name)
	else:
		# Get the ouput path and check if it exists, if it does confirm for replace.
		print("\nEnter the decrypted file/directory path.")
		input_name, input_ext = os.path.splitext(input_path)
		if input_ext[1:] == ct.extension:
			print("The default is '%s'" % input_name)
			output_path = input("Name: ") or input_name
		else: output_path = input("Name: ")
		if os.path.exists(output_path):
			replace = input("File '%s' already exists. Replace? (y/n): " % output_path)
			if replace[0].lower() == "n": return {"status":"Warning: output path already exists, won't replace."}
		# Get the password securely.
		password = getpass.getpass("Password (won't echo): ")
		# Decrypt.
		res = ct.decryptFile(password, input_path, output_path)
	return {"status":res["status"]}
#

if __name__ == "__main__":
	res = main()
	print(res["status"])
	#ct = Cryptool()
#

'''
base64.urlsafe_b64encode(bytes)	: bytes -> base64 representation.
base64.urlsafe_b64decode(bytes)	: base64 representation -> bytes. (if there are padding problems, just append b"====" to the input)

base64.b64encode(bytes)	: bytes -> base64 representation.
base64.b64decode(bytes)	: base64 representation -> bytes. (if there are padding problems, just append b"====" to the input)

bytes.fromhex(hex)		: hex_str -> bytes.
bytes.hex()				: bytes -> hex_str.
'''