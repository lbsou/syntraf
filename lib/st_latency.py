import socket
import time
import logging
import struct
import sys

log = logging.getLogger("syntraf." + __name__)
buffersize = 1024
platform = sys.platform


def udp_server(port=17000, ip="127.0.0.1"):
    print("UDPSERVER STARTED")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ip, port))

    while True:
        try:
            msg, address = s.recvfrom(buffersize)
            sent = s.sendto(msg, address)
        except Exception as exc:
            print("server", exc)


def udp_client(port=17001, timeout=1000, ip="23.250.5.250", interval=1):
    print("UDPCLIENT STARTED")

    server_address = (ip, port)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)

    sequence_number = 0.0
    while True:
        sequence_number_bin = bytearray(struct.pack("f", sequence_number))
        try:
            timer_begin_monotonic = get_monotonic_time()

            s.sendto(sequence_number_bin, server_address)
            value, server_address_recv = s.recvfrom(buffersize)
            # Did we receive a datagram from the right IP?
            if server_address == server_address_recv:
                # Did we receive the right packet sequence number?
                if value == sequence_number_bin:
                    timer_end_monotonic = get_monotonic_time()
                else:
                    continue
            else:
                continue
        except socket.timeout as exc:
            print("clientA", exc)
        except OSError as exc:
            print("clientB", exc)
        except Exception as exc:
            print("clientC", exc)
        else:
            latency_monotonic = (timer_end_monotonic - timer_begin_monotonic)*1000
            print("%.0fms" % ((timer_end_monotonic - timer_begin_monotonic)*1000))
        time.sleep(interval)
        sequence_number += 1


def tcp_ping(host="23.250.5.250", port=8086, timeout=2, max_count=1, interval=1):
    count = 0
    loss = 0
    success = False

    while count < max_count:
        # socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # timeout
        s.settimeout(timeout)

        # timer
        timer_begin = time.monotonic_ns()

        try:
            s.connect((host, port))
            s.shutdown(socket.SHUT_RD)
            success = True

        # Connection Timed Out
        except socket.timeout:
            loss += 1
        except OSError as e:
            loss += 1

        # Stop Timer
        timer_end = time.monotonic_ns()

        if success:
            latency = "%.2f" % (1000 * (timer_end - timer_begin))
            log.debug(f"success! latency:{latency}")
        else:
            log.debug(f"loss!")

        count += 1
        time.sleep(interval)


#https://bugs.python.org/issue44328
def get_monotonic_time():
    if platform == "win32":
        return time.perf_counter()
    else:
        return time.monotonic()