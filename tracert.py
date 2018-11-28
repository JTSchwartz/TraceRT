# tracert.py
import time

from rawsocket import RawSocket
import sys


def main(host):
	start_time = time.time()
	connection = RawSocket(host)
	print("Tracing route to {}".format(connection.ip))

	for hop in range(1, 31):
		connection.create_socket()
		connection.send_ping(hop)
		dns, ip, rtt, probes = connection.recv_ping()
		if probes == 0:
			break  # TODO: Retransmit packets

		print(f"{hop}\t{dns}\t({ip})\t{rtt:.3f}ms\t({probes})")

		if ip == connection.ip:
			break

	print("Total execution time: {0:.3f}ms".format(time.time() - start_time))


if __name__ == '__main__':
	main(sys.argv[1])
