import sys
import signal
import psutil
import time
import threading
from lib.st_global import *
from lib.st_logging import *
import logging
log = logging.getLogger("syntraf." + __name__)


# RETURN TRUE IF PID EXIST
def check_pid(pid):
    try:
        pid_exist = psutil.pid_exists(pid)
        if pid_exist:
            return True
        else:
            return False
    except Exception as exc:
        log.error(f"check_pid:{type(exc).__name__}:{exc}", exc_info=True)
        return False


# def init_reload():
#     '''
#     Running syntraf instance regularly check for the presence of his pid file. If the content is changed for "reload", it means someone asked for a reload. : syntraf.py -r
#     init_reload modify the pid file and insert the word "reload"
#     '''
#
#     try:
#
#         pid_file = pathlib.Path(DefaultValues.SYNTRAF_PID_FILE)
#         if pid_file.is_file():
#             # If syntraf is running, update the pid file
#             with open(pid_file_path, 'r') as f:
#                 pid = int(f.readline())
#                 is_running = check_pid(pid)
#
#
#
#
#     except Exception as exc:
#         print("CANNOT SEND A RELOAD SIGNAL, SYNTRAF IS NOT RUNNING")
#     sys.exit()


def signal_handler_init():
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)
    if sys.platform == "win32":
        signal.signal(signal.SIGBREAK, handler)


def handler(signum, frame):
    if sys.platform == 'win32':
        if signum == signal.SIGBREAK:
            print_sys("SIGBREAK RECEIVED: ")
    if signum == signal.SIGINT:
        print_sys("SIGINT RECEIVED: ")
    elif signum == signal.SIGKILL:
        print_sys("SIGKILL RECEIVED: ")
    elif signum == signal.SIGTERM:
        print_sys("SIGTERM RECEIVED: ")
    sys.exit()


def start_loading_thread(text):
    thr_run = threading.Thread(target=loading_animation, args=(text,), daemon=True)
    thr_run.name = str("LOADING")
    thr_run.start()
    return thr_run


def onclose(p, threads_n_processes, config):
    config['GLOBAL']['LOG_LEVEL'] = "CRITICAL"
    print_sys("SHUTTING DOWN SYNTRAF NOW!")
    try:
        try:
            p.unlink()
        except Exception as exc:
            pass
        for thr in threads_n_processes:
            thr.close()
    except Exception as exc:
        log.critical(f"onclose:{type(exc).__name__}:{exc}", exc_info=True)


def print_sys(text):
    sys.stdout.write(text)
    sys.stdout.flush()


def loading_animation(text):
    while True:
        print_sys("[/] ")
        time.sleep(0.03)
        print_sys("\r")

        print_sys("[-] ")
        time.sleep(0.03)
        print_sys("\r")

        print_sys("[|] ")
        time.sleep(0.03)
        print_sys("\r")

        print_sys("[\\] ")
        time.sleep(0.03)
        print_sys("\r")

        print_sys("[|] ")
        time.sleep(0.03)
        print_sys("\r")
