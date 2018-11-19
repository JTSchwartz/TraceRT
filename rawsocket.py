import select
import socket
import struct


class RawSocket:

	def __init__(self, host):
		self.sock = None
		self.entry = host
		self.host = self.get_ip()
		self.ttl = 3
		self.port = 33435
		self.id = 6735
		self.seq_number = 0
		self.trace = list()

	def create_socket(self):
		try:
			self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
		except socket.error:
			print("Failed to build socket. Shutting down...")
			self.sock = None
			exit(1)

	def get_ip(self):
		return socket.gethostbyname(self.entry)

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

	def sendPing(self, ttl):
		""" Create an icmp packet first, then use raw socket to sendto this packet """
		# Header has 8 bytes: type (8), code (8), checksum (16), id (16), sequence (16)
		checksum = 0  # initialize checksum to 0
		# Make a dummy header with a 0 checksum.
		header = struct.pack("!BBHHH", 8, 0, checksum, self.id, self.seq_number)
		data = bytes(556)  # bytes of zeros
		packet = header + data
		checksum = self.checksum(packet)  # compute checksum, in network order
		# Now that we have the right checksum, put that in. Create a new header
		header = struct.pack(…, checksum, …)  # fill in …
		packet = header + data  # Packet ready
		self.ttl = ttl
		self.sock.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)

		try:
			num = self.sock.sendto(packet, (self.ip, self.port))
			print("bytes sent: ", num)  # print msg for debugging!!!!
		except socket.error:
			return None

	def recv_ping(self):
		"""Set timeout on receiving reply, call recvfrom(),
		interpret header info return True if reach destination """
		self.sock.setblocking(0)
		data_ready = select.select([self.sock], [], [], TIMEOUT)
		if not data_ready[0]:  # Timeout
			print("recvfrom Timeout!")
			return False

		recPacket = b''  # empty bytes
		recPacket, addr = self.sock.recvfrom(ICMP_MAX_RECV)
		print("bytes received: ", len(recPacket))  # print for debugging!!!
		# first 20 bytes in recv pkt are IP header that contains router/destination IP
		ipHeader = recPacket[:20]
		iphVersion, iphTypeOfSvc, iphLength, \
		iphID, iphFlags, iphTTL, iphProtocol, \
		iphChecksum, iphSrcIP, iphDestIP = struct.unpack("!BBHHHBBHII", ipHeader)
		# next 8 bytes are ICMP reply header
		icmpHeader = recPacket[20:28]
		icmpType, icmpCode, icmpChecksum, \
		icmpPacketID, icmpSeqNumber = struct.unpack("!BBHHH", icmpHeader)
		print("icmpType = ", icmpType)  # for bebugging!!
		print("icmpCode = ", icmpCode)
