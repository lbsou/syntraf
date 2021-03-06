import sys
import signal
import psutil
import time
from multiprocessing import shared_memory
import threading
from lib.st_global import *
from lib.st_logging import *
import logging
log = logging.getLogger(__name__)


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


def init_reload():
    '''
    Running syntraf instance regularly check for the presence of his pid file. If the content is changed for "reload", it means someone asked for a reload. : syntraf.py -r
    init_reload modify the pid file and insert the word "reload"
    '''

    try:

        pid_file = pathlib.Path(DefaultValues.SYNTRAF_PID_FILE)
        if pid_file.is_file():
            # If syntraf is running, update the pid file
            with open(pid_file_path, 'r') as f:
                pid = int(f.readline())
                is_running = check_pid(pid)




    except Exception as exc:
        print("CANNOT SEND A RELOAD SIGNAL, SYNTRAF IS NOT RUNNING")
    sys.exit()







    '''
    try:
        shared_mem = shared_memory.SharedMemory("syntraf_reload_signal")
        shared_mem.buf[0] = 1
        print("RELOAD FLAG SET. SYNTRAF WILL RELOAD ON NEXT WATCHDOG_CHECK_RATE")
    except Exception as exc:
        print("CANNOT SEND A RELOAD SIGNAL, SYNTRAF IS NOT RUNNING")
        sys.exit()
    '''

    return shared_mem


def pid_and_reload_flag_init(pid_file, pid_file_path):
    try:
        # If opening the shared var is ok, goto else because unclean shutdown or already running
        shared_mem = shared_memory.SharedMemory("syntraf_reload_signal")
    except Exception as exc:
        # if we cannot open the var, program was shutdown cleanly, so create new var.
        shared_mem = shared_memory.SharedMemory(name="syntraf_reload_signal", create=True, size=1)
        shared_mem.buf[0] = 0
    # possible unclean shutdown or already running
    else:
        try:
            # if pid file, still a probable unclean shutdown or running
            if pid_file.is_file():
                # open pid file and check if pid is running
                with open(pid_file_path, 'r') as f:
                    pid = int(f.readline())
                    is_running = check_pid(pid)
                    # if SYNTRAF is not running, remove the shared var
                    if not is_running:
                        shared_mem.close()
                        # TODO
                        try:
                            shared_mem.unlink()
                        except Exception as exc:
                            pass
            else:
                shared_mem.close()
                # TODO
                try:
                    shared_mem.unlink()
                except Exception as exc:
                    pass
        except Exception as exc:
            log.error(f"pid_and_reload_flag_init:{type(exc).__name__}:{exc}", exc_info=True)
    return shared_mem


def signal_handler_init():
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)
    if sys.platform == "win32":
        signal.signal(signal.SIGBREAK, handler)


def handler(signum, frame):
    if sys.platform == 'win32':
        if signum == signal.SIGBREAK:
            print("")
            print("SIGBREAK RECEIVED!")
    if signum == signal.SIGINT:
        print("")
        print("SIGINT RECEIVED!")
    elif signum == signal.SIGKILL:
        print("")
        print("SIGKILL RECEIVED!")
    elif signum == signal.SIGTERM:
        print("")
        print("SIGTERM RECEIVED!")
    sys.exit()


def start_loading_thread(text):
    thr_run = threading.Thread(target=loading_animation, args=(text,), daemon=True)
    thr_run.name = str("LOADING")
    thr_run.start()
    return thr_run


def onclose(p, threads_n_processes, shared_mem, config):
    config['GLOBAL']['LOG_LEVEL'] = "CRITICAL"
    set_log_level(config)
    try:
        text = "REMOVING RELOAD_FLAG"
        thr_animation = start_loading_thread(text)
        shared_mem.close()
        try:
            shared_mem.unlink()
        except Exception as exc:
            pass
        time.sleep(0.01)
        thr_animation.join(0.01)
        print_sys("\r")
        print_sys("[X] " + text)
        print_sys("\n\r")

        text = "REMOVING PID_FILE"
        thr_animation = start_loading_thread(text)
        try:
            p.unlink()
        except Exception as exc:
            pass
        time.sleep(0.01)
        thr_animation.join(0.01)
        print_sys("\r")
        print_sys("[X] " + text)
        print_sys("\n\r")

        for thr in threads_n_processes:
            text = "TERMINATING " + thr.syntraf_instance_type + " '" + thr.name + "'"
            thr_animation = start_loading_thread(text)
            time.sleep(0.01)
            # TO REPLACE WITH EXIT_BOOLEAN = TRUE + JOIN
            # CANT DO THAT RIGHT NOW BECAUSE MESH SERVER SOCKET ACCEPT IS BLOCKING. WILL HAVE TO WAIT FOR IMPLEMENTING SELECTORS
            thr.close()
            thr_animation.join(0.00001)
            print_sys("\r")
            print_sys("[X] " + text)
            print_sys("\n\r")
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
