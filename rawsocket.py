import select
import socket
import struct
import binascii
import time

_TIMEOUT = 15
_ICMP_ECHO = 8


class RawSocket:

	def __init__(self, host):
		self.sock = None
		self.host = host
		self.ip = self.get_ip()
		self.ttl = 1
		self.port = 33435
		self.id = 6735
		self.seq_number = 0
		self.trace = list()
		self.sent = None

	def create_socket(self):
		try:
			self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
		except socket.error:
			print("Failed to build socket. Shutting down...")
			self.sock = None
			exit(1)

	def get_ip(self):
		return socket.gethostbyname(self.host)

	@staticmethod
	def checksum(packet):
		even_length = (int(len(packet) / 2)) * 2
		checksum = 0
		for count in range(0, even_length, 2):  # handle two bytes each time
			checksum = checksum + (packet[count + 1] * 256 + packet[count]) #low byte is at [count]

		if even_length < len(packet):  # if handle last byte if odd-number of bytes
			checksum += packet[-1]  # get last byte

		checksum &= 0xffffffff  # Truncate checksum to 32 bits (a variance from ping.c)
		checksum = (checksum >> 16) + (checksum & 0xffff)  # Add high 16 bits to low 16 bits
		checksum += (checksum >> 16)  # Add carry from above (if any)
		checksum = ~checksum & 0xffff  # Invert and truncate to 16 bits
		return socket.htons(checksum)

	def send_ping(self, ttl):
		""" Create an icmp packet first, then use raw socket to sendto this packet """
		# Header has 8 bytes: type (8), code (8), checksum (16), id (16), sequence (16)
		checksum = 0  # initialize checksum to 0
		# Make a dummy header with a 0 checksum.
		header = struct.pack("!BBHHH", _ICMP_ECHO, 0, checksum, self.id, self.seq_number)
		data = bytes(64)  # bytes of zeros
		packet = header + data
		checksum = self.checksum(packet)  # compute checksum, in network order
		# Now that we have the right checksum, put that in. Create a new header
		header = struct.pack("!BBHHH", _ICMP_ECHO, 0, checksum, self.id, self.seq_number)
		packet = header + data  # Packet ready
		self.ttl = ttl
		self.sock.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)

		try:
			self.sent = time.time()
			num = self.sock.sendto(packet, (self.ip, self.port))
			# print("bytes sent: ", num)  # print msg for debugging!!!!
			# print(binascii.hexlify(packet))
		except socket.error as e:
			print("Socket Error", e)
			print(binascii.hexlify(packet))

	def recv_ping(self, attempts=3):
		"""Set timeout on receiving reply, call recvfrom(),
		interpret header info return True if reach destination """
		self.sock.setblocking(0)
		data_ready = select.select([self.sock], [], [], _TIMEOUT)
		if not data_ready[0]:  # Timeout
			if attempts > 0:
				return self.recv_ping(attempts - 1)
			else:
				print("recvfrom Timeout!")
				return 0, 0, 0, 0

		recPacket = b''  # empty bytes
		recPacket, addr = self.sock.recvfrom(576)
		# print("bytes received: ", len(recPacket))  # print for debugging!!!
		# first 20 bytes in recv pkt are IP header that contains router/destination IP
		ipHeader = recPacket[:20]
		iphSrcIP = [0] * 4
		iphVersion, iphTypeOfSvc, iphLength, \
		iphID, iphFlags, iphTTL, iphProtocol, \
		iphChecksum, iphSrcIP[0], iphSrcIP[1], iphSrcIP[2], iphSrcIP[3], iphDestIP = struct.unpack("!BBHHHBBHBBBBI", ipHeader)
		# next 8 bytes are ICMP reply header
		icmpHeader = recPacket[20:28]
		icmpType, icmpCode, icmpChecksum, \
		icmpPacketID, icmpSeqNumber = struct.unpack("!BBHHH", icmpHeader)
		# print("icmpType = ", icmpType)  # for bebugging!!
		# print("icmpCode = ", icmpCode)
		src_ip = '.'.join(map(str, iphSrcIP))
		# print(src_ip)
		return self.get_host(src_ip), src_ip, (time.time() - self.sent), 4 - attempts

	@staticmethod
	def get_host(ip):
		try:
			return socket.gethostbyaddr(ip)[0]
		except socket.error:
			return "<no dns entry>"
