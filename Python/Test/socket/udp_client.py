#!/usr/bin/env python3.5

import time
import socket

print("This is Python UDP Client!")

server_addr = ("10.10.10.102",18080)

lsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
lsock.connect(server_addr)

while True:
    request = "Hello!"
    lsock.send(request.encode("utf-8"));
    data = lsock.recv(1024)
    print("Recv: ", data)
    time.sleep(1)
lsock.close()
