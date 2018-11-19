# tracert.py

from rawsocket import RawSocket
import sys


def main(host):
	connection = RawSocket(host)
	connection.create_socket()
	print("Tracing route to {}".format(connection.host))

	for line in range(0, len(connection.trace), 1):
		print("{}\t{}".format(line + 1, connection.trace[line]))


if __name__ == '__main__':
	main(sys.argv[1])
