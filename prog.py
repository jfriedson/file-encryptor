import base64
from getpass import getpass
import os
import sys

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC



rawFilePath = ""
encFilePath = ""

rawExtMaxLen = 8    # maximum character length for raw file extension before truncation

saltLength = 16 # bytes

hashAlgorithm = hashes.SHA256()
hashLength = 32 # bytes
hashIterations = 450000


def encrypt(password, fileExt):
	salt = os.urandom(saltLength)

	kdf = PBKDF2HMAC(
		algorithm = hashAlgorithm,
		length = hashLength,
		salt = salt,
		iterations = hashIterations )

	key = base64.urlsafe_b64encode(kdf.derive(password))

	f = Fernet(key)

	try:
		rawFileStream = open(rawFilePath, "rb")
	except Exception as e:
		print("error opening raw file...\n", repr(e))
		sys.exit()

	try:
		encFileStream = open(encFilePath, "wb")
	except Exception as e:
		print("error opening encoded file...\n", repr(e))
		rawFileStream.close()
		sys.exit()

	with rawFileStream:
		with encFileStream:
			encFileStream.write(salt)
			encFileStream.write(f.encrypt(fileExt + rawFileStream.read()))

	encFileStream.close()
	rawFileStream.close()
	sys.exit()


def decrypt(password):
	global rawFilePath

	try:
		encFileStream = open(encFilePath, "rb")
	except Exception as e:
		print("error opening encoded file...\n", repr(e))
		sys.exit()

	with encFileStream:
		salt = encFileStream.read(saltLength)

		kdf = PBKDF2HMAC(
			algorithm = hashAlgorithm,
			length = hashLength,
			salt = salt,
			iterations = hashIterations )

		key = base64.urlsafe_b64encode(kdf.derive(password))

		f = Fernet(key)

		try:
			rawData = f.decrypt(encFileStream.read())

			rawFilePath += rawData[:8].decode()
			rawFilePath = rawFilePath[:rawFilePath.find('*')]

			try:
				rawFileStream = open(rawFilePath, "wb")
			except Exception as e:
				print("error opening raw file...\n", repr(e))
				encFileStream.close()
				sys.exit()

			with rawFileStream:
				rawFileStream.write(rawData[8:])

		except:
			# awlays treat exception as invalid password
			encFileStream.close()
			print("invalid password")
			return

	rawFileStream.close()
	encFileStream.close()
	sys.exit()


def getFilePath(direction):
	global rawFilePath
	global encFilePath
	if(direction == 0):
		while(True):
			rawFilePath = input("file to encrypt: ")
			if(os.path.isfile(rawFilePath)):
				if(rawFilePath[rawFilePath.rfind('.') + 1:] == "secure"):
					print("file is already encrypted")
					continue
				encFilePath = rawFilePath[:rawFilePath.rfind('.') + 1] + "secure"
				return rawFilePath[rawFilePath.rfind('.') + 1:].ljust(rawExtMaxLen, '*')[:rawExtMaxLen]    # provide encryption function with 8 char extension
			else:
				print("file does not exist")
	else:
		while(True):
			encFilePath = input("file to decrypt: ")
			if(os.path.isfile(encFilePath)):
				if(encFilePath[encFilePath.rfind('.') + 1:] != "secure"):
					print("file is not encrypted")
					continue
				rawFilePath = encFilePath[:encFilePath.rfind('.') + 1]
				return
			else:
				print("file does not exist")


while(True):
	direction = input("(e)ncrypt or (d)ecrypt? ")

	if direction.lower() == 'e':
		fileExt = getFilePath(0)
		password = getpass("password: ")
		encrypt(str.encode(password), str.encode(fileExt))

	elif direction.lower() == 'd':
		getFilePath(1)
		while(True):
			password = getpass("password: ")
			decrypt(str.encode(password))

	else:
		print("not a valid entry. try again\n")
