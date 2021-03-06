#!/usr/bin/env python3
########################################
# Version 2021-06-15
# Louis-Berthier Soullière
# shadow131@hotmail.com
# Indentation of 4 spaces
########################################

# SYNTRAF GLOBAL IMPORT
from lib.st_global import DefaultValues, CompilationOptions
#from lib.st_class_winsvc import SMWinservice

# BUILTIN IMPORT
import sys
import argparse
import atexit
import queue
import logging
import os
from multiprocessing import shared_memory

try:
    # SYNTRAF modules
    #from lib.st_mesh import *
    #from lib.st_global import *
    from lib.st_logging import *
    #from lib.st_conf_validation import *
    #from lib.st_iperf import *
    from lib.st_clean_close import *
    from lib.st_process_and_thread import *
    from lib.st_system_stats import system_stats

except Exception as exc:
    print("MISSING MODULE: " + str(exc))
    sys.exit()

log = logging.getLogger(__name__)


#################################################################################
### MAIN
#################################################################################
def run():
    # ready to forward TERM, INT and BREAK to handler
    signal_handler_init()

    # READING ARGUMENTS
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', "--config_file", action='store', dest='config_file',
                        help='You  must provide the path of a SYNTRAF config file', required=True)
    parser.add_argument('-l', "--log-dir", action='store', dest='log_dir',
                        help='You  must provide a directory for logging', required=True)
    parser.add_argument('-r', "--reload", action='store_true',
                        help='Trigger a reload of configuration on already running SYNTRAF instance', required=False)
    parser.add_argument('-v', action='version', version='%(prog)s 21.04.29.1')
    results = parser.parse_args()

    # creating pid file var
    pid_file_path = DefaultValues.SYNTRAF_PID_FILE
    pid_file = pathlib.Path(pid_file_path)

    is_dir_create_on_fail(results.log_dir, "LOG_DIR")

    print(f"SYNTRAF v{DefaultValues.SYNTRAF_VERSION}")

    '''
    Mechanism to reload SYNTRAF using a memshared flag.
    If the user ask for a reload, first we try to access the memshared var and set it to 1.
    If it fail, it's because SYNTRAF is not running.
    If we are running SYNTRAF, we try to access the memshared var in case of unclean shutdown. In that
    case, we close and unlink it. 
    If it doesn't exist, we create it and set it to 0.
    '''

    '''
    At startup : 
        If pid file exist it's either because syntraf is already running or it did not clause gracefully
            check if process id exist with correct name, if it's the case, exit the starting syntraf instance, as only one instance can run at the same time.
            if it does not exist, syntraf has previously crashed, we need to remove the pid file, create a new one and start syntraf
            
    At shutdown :
        remove the pid file
        
    Reload flag :
        Running syntraf instance regularly check for the presence of his pid file. If the content is changed for "reload", it means someone asked for a reload. : syntraf.py -r
    '''
    try:
        if results.reload:
            shared_mem = init_reload()
        else:
            if pid_file.is_file():
                # If syntraf is already running, exit
                with open(pid_file_path, 'r') as f:
                    pid = int(f.readline())
                    is_running = check_pid(pid)
                    if is_running:
                        print("ERROR: ONLY ONE INSTANCE OF SYNTRAF MAY BE RUN AT A TIME")
                        sys.exit()
                    else:
                        print("WARNING : ON PREVIOUS RUN, SYNTRAF WAS UNABLE TO SHUTDOWN GRACEFULLY.")
                        shared_mem = pid_and_reload_flag_init(pid_file, pid_file_path)
            else:
                shared_mem = pid_and_reload_flag_init(pid_file, pid_file_path)
    except Exception as exc:
        log.error(f"AN ERROR OCCURED WHILE VALIDATING IF SYNTRAF IS ALREADY RUNNING")
        log.error(exc)
        sys.exit()

    # Initializing logs
    log_init(results)

    # Validation of configuration
    bool_config_valid, config, _dict_by_node_generated_config, _dict_by_group_of_generated_tuple_for_map = validate_config(results)

    if bool_config_valid: config['GLOBAL']['LOGDIR'] = results.log_dir

    if not bool_config_valid:
        log.error(f"CONFIGURATION VALIDATION FAILED")
        sys.exit()

    conn_db = []
    # initializing database

    if "SERVER" in config:
        for database in config['DATABASE']:
            conn_db.append(InfluxObj(config, database['DB_UID']))

    try:
        with open(pid_file, 'w') as f:
            f.write(str(os.getpid()))
    except Exception as exc:
        log.error(f"AN ERROR OCCURED WHILE OPENING THE PID_FILE")
        log.error(exc)

    # To keep the thread and the exit_boolean associated
    threads_n_processes = []

    # To keep the subprocess (iperf3 client and server)
    subprocess_iperf_dict = {}

    '''
    If program exit with sys.exit() or with SIGINT/SIGBREAK (handler call sys.exit()). 
    Try to shut things down smoothly.
    '''
    atexit.register(onclose, pid_file, threads_n_processes, shared_mem, config)

    # SERVER, This object keep track of all the client resources
    stats_dict_for_webui = {}
    dict_of_clients = {}

    # CLIENT, This object keep track of the local resources
    obj_stats = system_stats(config)

    # CLIENT, Will contain the metric that will be send to the server
    dict_data_to_send_to_server = {}

    # Use by webui to provide message to the server that will be transmitted to client: ie : restart
    # A dictionary in which the key is the client_uid and the value is an array of command
    # dict_of_commands_for_network_clients = {"DATACENTER": ["RESTART","PAUSE"]}
    dict_of_commands_for_network_clients = {}

    dict_of_client_pending_acceptance = {}

    # WATCHDOG
    while True:
        reload_flag = False

        # launch iperf_listeners, iperf_connectors read_log, client, server
        threads_n_processes, subprocess_iperf_dict = launch_and_respawn_workers(config, threads_n_processes, stats_dict_for_webui, obj_stats, dict_of_clients, dict_data_to_send_to_server, dict_of_commands_for_network_clients, _dict_by_node_generated_config, _dict_by_group_of_generated_tuple_for_map, dict_of_client_pending_acceptance, results.config_file, conn_db, subprocess_iperf_dict)

        # Validate if reload flag has been set by user with another instance of the script (-r)
        try:
            shared_mem = shared_memory.SharedMemory("syntraf_reload_signal")
        except Exception as e:
            pass

        if shared_mem.buf[0] == 1:
            print("RELOAD WAS ASKED BY USER")
            shared_mem.buf[0] = 0
            reload_flag = True

        time.sleep(int(config['GLOBAL']['WATCHDOG_CHECK_RATE']))


# class windows_service(SMWinservice):
#     def start(self):
#         self.isrunning = True
#
#     def stop(self):
#         self.isrunning = False
#
#     def main(self):
#         run()

#################################################################################
### RUN
#################################################################################
if __name__ == '__main__':
    if sys.platform == "win32":
        run()
        #windows_service.parse_command_line()
    else:
        run()