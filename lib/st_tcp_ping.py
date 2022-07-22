import socket
from timeit import default_timer as timer


def tcp_ping(dst_ip, dst_port, ping_interval, ping_timeout):

    while True:
        success = False
        try:
            # Preparing the socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)

            # Starting the timer
            ts_start = timer()

            # connecting
            s.connect((dst_ip, dst_port))
            s.shutdown(socket.SHUT_RD)
            success = True

        # All the same for now, but eventually, might want to report that in the logs
        except (ConnectionRefusedError, ConnectionResetError) as exc:
            success = False
        except OSError as exc:
            # Network is unreachable
            if exc.errno == 101:
                success = False
        except Exception as exc:
            success = False

            # Stop Timer
        ts_stop = timer()
        runtime = "%.2f" % (1000 * (ts_stop - ts_start))

        if success:
            print(runtime)

        time.sleep(ping_interval)

