from Crypto.Cipher import AES
from termcolor import colored
import array

class NokeDecryptor:

	def __init__(self):
		self.aes_key = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
		self.random_numbers01 = None
		self.random_numbers02 = None		
		self.session_key = None

	def addArray(self):
		key = [x for x in self.aes_key]
		offset = 5
		for i in range(4):
			b1 = ord(self.session_key[i])
			b2 = ord(key[offset + i])
			key[offset + i] = chr(b1 + b2)
		self.aes_key = ''.join(key)
		print colored('[+] NEW AES KEY: %s' % (self.hexToStr(self.aes_key)), 'blue')

	def decrypt(self, payload):
		if self.session_key:
			self.addArray()

		aes = AES.new(self.aes_key, AES.MODE_ECB)
		decrypted = aes.decrypt(payload)
		print '[*] Decrypted payload: %s' % decrypted.encode('hex') 

		return decrypted

	def hexToStr(self, data):
		return ['%02x' % ord(x) for x in data]

	def createSessionKey(self):
		self.session_key = []
		for i in range(4):
			r1 = ord(self.random_numbers01[i].decode('hex'))
			r2 = ord(self.random_numbers02[i].decode('hex'))
			xor = r1 ^ r2
			self.session_key.append(chr(xor))
		print colored('[+] NEW SESSION KEY: %s' % self.hexToStr(self.session_key), 'blue')

	def extractHeaders(self, packet):
		print '[*] Extracting headers'

		payload = packet.replace(':', '')
		payload = payload.decode('hex')
		payload = self.decrypt(payload)
		payload = self.hexToStr(payload)

		headers = {}
		headers['type'] = payload[0:3]
		headers['random_numbers']  = payload[3:7]
		headers['checksum'] = payload[7]

		print '[*] Packet type: %s' % headers['type']

		if headers['type'] == ['7e', '08', '01']:
			print '[*] Packet Found: createSessionStartPacket'
			print '[*] Random numbers: %s' % headers['random_numbers']
			self.random_numbers01 = headers['random_numbers']
		elif headers['type'] == ['7e', '08', '02']:
			print '[*] Packet Found: createSessionStartConfPacket'
			print '[*] Random numbers: %s' % headers['random_numbers']
			self.random_numbers02 = headers['random_numbers']
			self.createSessionKey()				
		else:
			headers['checksum'] = payload[9]
			lock_key = payload[3:9]
			print '[*] Packet Found: createUnlockPacket'
			print colored('[+] PADLOCK SECRET FOUND: %s' % lock_key, 'green')
 		print '[*] Checksum: %s' % headers['checksum']

		return headers	

	def start(self):	
		packet01 = "93:54:21:3a:85:b0:7f:46:e3:e3:b5:9d:bd:1b:19:84"
		packet02 = "02:e7:b8:48:9f:69:ad:4f:36:f3:f7:00:d4:5b:ed:34"
		packet03 = "3d:c5:d4:3b:4f:c9:91:a7:a7:9f:1d:b9:71:17:cc:aa"

		packets = [packet01, packet02, packet03]

		for packet in packets:
			print '[*] Packet: %s' % packet
			headers = self.extractHeaders(packet)
			print ''

noke = NokeDecryptor()
noke.start()
