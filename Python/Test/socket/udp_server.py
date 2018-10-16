#!/usr/bin/env python3.5

import socket

print("This is Python UDP Server!")

local_addr = ("10.10.10.102",18080)

lsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
lsock.bind(local_addr)

while True:
    data, remote_addr = lsock.recvfrom(1024)
    print("Recv:", data);
    response = "Got ya"
    lsock.sendto(response.encode("utf-8"), remote_addr)
lsock.close()
