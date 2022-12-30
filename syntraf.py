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

log = logging.getLogger("syntraf")

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
    # parser.add_argument('-r', "--reload", action='store_true',
    #                     help='Trigger a reload of configuration on already running SYNTRAF instance', required=False)
    parser.add_argument('-v', action='version', version=f'%(prog)s {DefaultValues.SYNTRAF_VERSION}')
    cli_parameters = parser.parse_args()

    # creating pid file var
    pid_file_path = DefaultValues.SYNTRAF_PID_FILE
    pid_file = pathlib.Path(pid_file_path)

    is_dir_create_on_fail(cli_parameters.log_dir, "LOG_DIR")

    print(f"SYNTRAF v{DefaultValues.SYNTRAF_VERSION}")

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
        if pid_file.is_file():
            # If syntraf is already running, exit
            with open(pid_file_path, 'r') as f:
                pid = int(f.readline())
                is_running = check_pid(pid)
                if is_running:
                    print("ERROR: THIS SYNTRAF INSTANCE IS ALREADY RUNNING.")
                    sys.exit()
                else:
                    print("WARNING: ON PREVIOUS RUN, SYNTRAF WAS UNABLE TO SHUTDOWN GRACEFULLY.")
    except Exception as exc:
        log.error(f"ERROR: UNABLE TO VALIDATE IF SYNTRAF IS ALREADY RUNNING.")
        log.error(exc)
        sys.exit()

    # Initializing logs before config validation
    bool_config_valid, config = read_conf(cli_parameters.config_file)
    if not bool_config_valid:
        log.error(f"CONFIGURATION VALIDATION FAILED")
        sys.exit()
    validate_purge_logs(config)
    log_init(cli_parameters, config)

    # HANDLER TO OUTPUT CRITICAL ONLY TO STDOUT
    ch = logging.StreamHandler()
    ch.setLevel(logging.CRITICAL)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    log.addHandler(ch)

    # Validation of configuration
    bool_config_valid, config, _dict_by_node_generated_config, _dict_by_group_of_generated_tuple_for_map = validate_config(cli_parameters)

    if bool_config_valid: config['GLOBAL']['LOGDIR'] = cli_parameters.log_dir

    if not bool_config_valid:
        log.error(f"CONFIGURATION VALIDATION FAILED")
        sys.exit()

    # initializing database
    conn_db = []
    flag_at_least_one_db_online = False
    if "SERVER" in config:
        if "DATABASE" in config:
            for database in config['DATABASE']:
                new_conn = InfluxObj(config, database['DB_UID'])
                conn_db.append(new_conn)
                if new_conn.status == "ONLINE":
                    flag_at_least_one_db_online = True

    if not flag_at_least_one_db_online and "SERVER" in config:
        # Print a warning that all data will be volatile because there is no available database
        log.warning(f"**********************************************************************************************")
        log.warning(f"NO DATABASES CONFIGURED OR ONLINE AT THE MOMENT, DATA WILL BE VOLATILE")
        log.warning(f"DEPENDING ON YOUR CONFIGURATION, SOME DATA COULD BE RECORDED WHEN DATABASE WILL BE BACK ONLINE")
        log.warning(f"**********************************************************************************************")

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
    atexit.register(onclose, pid_file, threads_n_processes, config)

    # SERVER, This object keep track of all the client resources
    dict_of_clients = {}

    # CLIENT, This object keep track of the local resources
    obj_stats = system_stats(config)

    # CLIENT, Will contain the metric that will be send to the server
    dict_data_to_send_to_server = {}

    # Use by webui to provide message to the server that will be transmitted to client: ie : restart
    # A dictionary in which the key is the client_uid and the value is an array of command
    # dict_of_commands_for_network_clients = {"DATACENTER": ["RESTART","PAUSE"]}
    dict_of_commands_for_network_clients = {}

    # Using a public key mechanism, we have a list of client that are waiting acceptance
    dict_of_client_pending_acceptance = {}

    # WATCHDOG
    while True:
        reload_flag = False

        # launch iperf_listeners, iperf_connectors read_log, client, server
        threads_n_processes, subprocess_iperf_dict = launch_and_respawn_workers(config, cli_parameters, threads_n_processes, obj_stats, dict_of_clients, dict_data_to_send_to_server, dict_of_commands_for_network_clients, _dict_by_node_generated_config, _dict_by_group_of_generated_tuple_for_map, dict_of_client_pending_acceptance, cli_parameters.config_file, conn_db, subprocess_iperf_dict)

        # WHILE WEBUI DOWN, DUMP CLIENT STATUS TO FILE
        f = open(os.path.join(DefaultValues.SYNTRAF_ROOT_DIR, "client_status.txt"), "w")

        lst_client = []
        lst_client.append(
            ["CLIENT", "STATUS", "STATUS_SINCE", "STATUS_EXPLANATION", "CLIENT_UID", "CLIENT_DYNAMIC_IP", "CLIENT_PORT",
             "CLIENT_IP"])
        for k, v in dict_of_clients.items():
            lst_client.append(
                [k, v.status, v.status_since, v.status_explanation, v.client_uid, v.bool_dynamic_client, v.tcp_port,
                 v.ip_address])
        f.write(tabulate(lst_client))
        f.close()


        # WHILE WEBUI DOWN, DUMP THREAD STATUS TO FILE
        f = open(os.path.join(DefaultValues.SYNTRAF_ROOT_DIR, "thread_status.txt"), "w")

        lst_thread = []
        lst_thread.append(
            ["NAME", "TYPE", "PID", "RUNNING", "STARTTIME", "LAST_ACTIVITY", "PORT", "BIDIR_SRC_PORT", "BIDIR_LADDR"])

        for thr in threads_n_processes:
            lst_thread.append(
                [thr.name, thr.syntraf_instance_type, thr.pid, thr.getstatus(), thr.starttime, thr.last_activity, thr.port, thr.bidir_src_port, thr.bidir_local_addr])
        f.write(tabulate(lst_thread))
        f.write("\n")
        f.close()


        # # Validate if reload flag has been set by user with another instance of the script (-r)
        # try:
        #     shared_mem = shared_memory.SharedMemory("syntraf_reload_signal")
        # except Exception as e:
        #     pass
        #
        # if shared_mem.buf[0] == 1:
        #     print("RELOAD WAS ASKED BY USER")
        #     shared_mem.buf[0] = 0
        #     reload_flag = True

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