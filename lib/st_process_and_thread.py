# SYNTRAF GLOBAL IMPORT
from copy import copy

from lib.st_global import DefaultValues

from lib.st_obj_process_n_thread import *
from lib.st_conf_validation import *
from lib.st_system_stats import *
from lib.st_obj_cc_client import cc_client
from lib.st_mesh import client, server

# SYNTRAF SERVER IMPORT
if not CompilationOptions.client_only:
    from lib.web_ui_kindafixed2 import create_app

    # from gevent import monkey
    # monkey.patch_all()
    from gevent.pywsgi import WSGIServer

    from werkzeug.serving import run_simple
    from werkzeug.middleware.profiler import ProfilerMiddleware
    from gevent.pool import Pool
# BUILTIN IMPORT
import logging
from datetime import datetime
import time
import os
import threading

# from lib.st_covariance import *
log = logging.getLogger("syntraf." + __name__)
platform = sys.platform
if platform == "linux":
    import pyprctl


## Monkeypatch to catch gevent webserver events directed at stderr
# class writer(object):
#     def write(self, data):
#         log.error("STDERR:" + data)
#
#     def flush(self): pass
#
#
# logger = writer()
# sys.stderr = logger


#################################################################################
### DO THE INITIAL LAUNCH AND WATCHDOG OF (LISTENERS, CONNECTORS, CLIENT AND SERVER)
#################################################################################
def launch_and_respawn_workers(config, cli_parameters, threads_n_processes, obj_stats, dict_of_clients,
                               dict_data_to_send_to_server, dict_of_commands_for_network_clients,
                               _dict_by_node_generated_config, _dict_by_group_of_generated_tuple_for_map,
                               dict_of_client_pending_acceptance, config_file_path, conn_db,
                               subprocess_iperf_dict=dict()):
    try:
        # STATS
        list = [thr for thr in threads_n_processes if getattr(thr, 'syntraf_instance_type') == "STATS"]
        if not list:
            thr_stats = threading.Thread(target=launch_stats,
                                         args=(config, obj_stats),
                                         daemon=True)
            thr_stats.name = "STATS"
            thr_stats.start()
            thread_or_process = st_obj_process_n_thread(thread_obj=thr_stats, name="STATS",
                                                        syntraf_instance_type="STATS", exit_boolean=False,
                                                        starttime=datetime.now(), opposite_side="", group="", port="")
            threads_n_processes.append(thread_or_process)

        # LISTENERS
        manage_listeners_process(config, threads_n_processes, dict_data_to_send_to_server, conn_db)

        # CONNECTORS
        manage_connectors_process(config, threads_n_processes, dict_data_to_send_to_server, conn_db)

        # SERVER
        if "SERVER" in config:
            manage_mesh(config, threads_n_processes, "SERVER", obj_stats, config_file_path, cli_parameters,
                        dict_of_client_pending_acceptance=dict_of_client_pending_acceptance,
                        dict_of_clients=dict_of_clients, conn_db=conn_db,
                        _dict_by_node_generated_config=_dict_by_node_generated_config,
                        dict_of_commands_for_network_clients=dict_of_commands_for_network_clients)

            # WEBUI
            list = [thr for thr in threads_n_processes if getattr(thr, 'syntraf_instance_type') == "WEBUI"]
            if not list:
                thr_webui = threading.Thread(target=launch_webui,
                                             args=(
                                             threads_n_processes, subprocess_iperf_dict, _dict_by_node_generated_config,
                                             _dict_by_group_of_generated_tuple_for_map, dict_data_to_send_to_server,
                                             config, cli_parameters, config_file_path, conn_db,
                                             dict_of_commands_for_network_clients, dict_of_clients),
                                             daemon=True)
                thr_webui.name = "WEBUI"
                thr_webui.start()
                thread_or_process = st_obj_process_n_thread(thread_obj=thr_webui, name="WEBUI",
                                                            syntraf_instance_type="WEBUI", exit_boolean=False,
                                                            starttime=datetime.now(), opposite_side="", group="",
                                                            port="")
                threads_n_processes.append(thread_or_process)

            # COVARIANCE, ONLY IF SERVER
            list = [thr for thr in threads_n_processes if getattr(thr, 'syntraf_instance_type') == "COVARIANCE"]
            # if not list:
            # thr_covariance = threading.Thread(target=init_covar,
            #                                  args=[config, conn_db],
            #                                  daemon=True)
            # thr_covariance.name = "COVARIANCE"
            # thr_covariance.start()
            # thread_or_process = st_obj_process_n_thread(thread_obj=thr_covariance, name="COVARIANCE", syntraf_instance_type="COVARIANCE", exit_boolean=False, starttime=datetime.now())
            # threads_n_processes.append(thread_or_process)

        # CLIENT
        manage_mesh(config, threads_n_processes, "CLIENT", obj_stats, config_file_path, cli_parameters,
                    dict_data_to_send_to_server=dict_data_to_send_to_server)


    except Exception as exc:
        log.error(f"launch_and_respawn_workers:{type(exc).__name__}:{exc}", exc_info=True)
    return threads_n_processes, subprocess_iperf_dict


def launch_webui(threads_n_processes, subprocess_iperf_dict, _dict_by_node_generated_config,
                 _dict_by_group_of_generated_tuple_for_map, dict_data_to_send_to_server, config, cli_parameters,
                 config_file_path, conn_db, dict_of_commands_for_network_clients, dict_of_clients):
    if platform == "linux":
        pyprctl.set_name("WEBUI")
    try:
        app = create_app(threads_n_processes, subprocess_iperf_dict, _dict_by_node_generated_config,
                         _dict_by_group_of_generated_tuple_for_map, dict_data_to_send_to_server, config,
                         config_file_path, conn_db, dict_of_commands_for_network_clients, dict_of_clients)
        # app = ProfilerMiddleware(app)
        cert_path = os.path.join(DefaultValues.SYNTRAF_ROOT_DIR, "crypto", "WEBUI_X509_SELFSIGNED_DIRECTORY")
        pool = Pool(100)

        try:
            http_server = WSGIServer(('0.0.0.0', DefaultValues.DEFAULT_WEBUI_PORT), app, error_log=log, log=log)

            # try:
            #    http_server = WSGIServer(('0.0.0.0', DefaultValues.DEFAULT_WEBUI_PORT), app,
            #                             certfile=os.path.join(cert_path, 'certificate_webui.pem'),
            #                             keyfile=os.path.join(cert_path, 'private_key_webui.pem'), server_side=True,
            #                             cert_reqs=ssl.CERT_NONE, do_handshake_on_connect=True, spawn=pool, environ={'wsgi.multithread': True, 'wsgi.multiprocess': True,})
            http_server.serve_forever()
        except Exception as exc:
            log.error(exc)
    except Exception as msg:
        log.error(msg)


def launch_stats(config, obj_stats):
    if platform == "linux":
        pyprctl.set_name("STATS")
    while True:
        # Client only code
        if 'CLIENT' in config:
            obj_stats.update_stats()

        time.sleep(DefaultValues.DEFAULT_CLIENT_METRICS_UPDATE_FREQUENCY)


def init_client_obj_dict(config, dict_of_clients):
    if "SERVER" in config and "SERVER_CLIENT" in config:
        # Initializing status dict
        for client in config['SERVER_CLIENT']:
            dict_of_clients[client['UID']] = cc_client(status="UNKNOWN", status_since=datetime.now(),
                                                       status_explanation="NEVER CONNECTED", client_uid=client['UID'],
                                                       bool_dynamic_client=False)

            list_stats_if_pct_usage_tx = []
            list_stats_if_pct_usage_rx = []
            list_stats_mem_pct_free = []
            list_stats_cpu_pct_usage = []

            dict_of_clients[client['UID']].system_stats = {'if_pct_usage_rx': list_stats_if_pct_usage_tx,
                                                           'if_pct_usage_tx': list_stats_if_pct_usage_rx,
                                                           'mem_pct_free': list_stats_mem_pct_free,
                                                           'cpu_pct_usage': list_stats_cpu_pct_usage}


def manage_mesh(config, threads_n_processes, mesh_type, obj_stats, config_file_path, cli_parameters,
                dict_of_client_pending_acceptance={}, dict_of_clients={}, dict_data_to_send_to_server=[], conn_db=None,
                _dict_by_node_generated_config=dict(), dict_of_commands_for_network_clients=dict()):
    # Variable to be able to stop thread. It is in a list to be mutable and will be assigned inside a st_obj_thread_n_process object
    stop_thread = [False]

    try:
        # check if a thread exist with the mesh_type. Only one such thread is supposed to exist.
        if mesh_type in config:
            thr_temp = None
            for thr in threads_n_processes:
                if thr.syntraf_instance_type == mesh_type:
                    thr_temp = thr
                    break
                else:
                    thr_temp = None

            # Thread already started, not a initial start. No need to do the validation, only restart if dead
            if thr_temp and not thr_temp.thread_obj.is_alive():
                # log.error("WEBUI THREAD COULD NOT RUN OR DIED, PLEASE INVESTIGATE")
                # sys.exit()
                threads_n_processes.remove(thr_temp)

                thread_run = None
                # RESTART MESH INSTANCE
                if mesh_type == "CLIENT":
                    thread_run = threading.Thread(target=eval(mesh_type.lower()), args=(
                    config, stop_thread, dict_data_to_send_to_server, threads_n_processes, obj_stats, config_file_path,
                    cli_parameters),
                                                  daemon=True)
                elif mesh_type == "SERVER":
                    init_client_obj_dict(config, dict_of_clients)
                    thread_run = threading.Thread(target=eval(mesh_type.lower()),
                                                  args=(config, threads_n_processes, stop_thread,
                                                        _dict_by_node_generated_config, obj_stats, conn_db,
                                                        dict_of_commands_for_network_clients, dict_of_clients,
                                                        dict_of_client_pending_acceptance), daemon=True)
                thread_run.daemon = True
                thread_run.name = mesh_type
                thread_run.start()
                thread_or_process = st_obj_process_n_thread(thread_obj=thread_run, name=mesh_type, object_type="THREAD",
                                                            syntraf_instance_type=mesh_type, exit_boolean=stop_thread,
                                                            starttime=datetime.now(), opposite_side="", group="",
                                                            port="")
                threads_n_processes.append(thread_or_process)
                if mesh_type == "CLIENT":
                    log.info(
                        f"{mesh_type} RE-INITIATED : {config[mesh_type]['SERVER']}:{config[mesh_type]['SERVER_PORT']}")
                elif mesh_type == "SERVER":
                    log.info(
                        f"{mesh_type} RE-INITIATED : {config[mesh_type]['BIND_ADDRESS']}:{config[mesh_type]['SERVER_PORT']}")
            # Validate MESH config and start the thread
            elif thr_temp is None:
                log.info(f"VALIDATION OF {mesh_type} CONFIG SUCCESSFUL!")

                thread_run = None
                # START MESH INSTANCE
                if mesh_type == "CLIENT":
                    thread_run = threading.Thread(target=eval(mesh_type.lower()), args=(
                    config, stop_thread, dict_data_to_send_to_server, threads_n_processes, obj_stats, config_file_path,
                    cli_parameters),
                                                  daemon=True)
                elif mesh_type == "SERVER":
                    init_client_obj_dict(config, dict_of_clients)
                    thread_run = threading.Thread(target=eval(mesh_type.lower()),
                                                  args=(config, threads_n_processes, stop_thread,
                                                        _dict_by_node_generated_config, obj_stats, conn_db,
                                                        dict_of_commands_for_network_clients, dict_of_clients,
                                                        dict_of_client_pending_acceptance), daemon=True)
                thread_run.daemon = True
                thread_run.name = mesh_type
                thread_run.start()
                thread_or_process = st_obj_process_n_thread(thread_obj=thread_run, name=mesh_type, object_type="THREAD",
                                                            syntraf_instance_type=mesh_type, exit_boolean=stop_thread,
                                                            starttime=datetime.now(), opposite_side="", group="",
                                                            port="")

                threads_n_processes.append(thread_or_process)
                if config[mesh_type] == "CLIENT":
                    log.info(
                        f"{mesh_type} INITIATED : {config[mesh_type]['SERVER']}:{config[mesh_type]['SERVER_PORT']}")
                elif config[mesh_type] == "SERVER":
                    log.info(
                        f"{mesh_type} INITIATED : {config[mesh_type]['BIND_ADDRESS']}:{config[mesh_type]['SERVER_PORT']}")

    except Exception as exc:
        log.error(f"manage_mesh:{type(exc).__name__}:{exc}", exc_info=True)


def manage_listeners_process(config, threads_n_processes, dict_data_to_send_to_server, conn_db):
    try:
        # For each connector, validate config and run the iperf_client
        if 'LISTENERS' in config:
            for listener_key, listener_value in config['LISTENERS'].items():

                # Do we already have a LISTENER in the threads_n_processes dict
                thr_temp = st_obj_process_n_thread_exist(threads_n_processes, "LISTENER", listener_key)

                # # Dead, remove from dict
                # if not thr_temp.subproc:
                #     threads_n_processes.remove(thr_temp)
                #     thr_temp = None

                # Was never launch or was removed
                if thr_temp is None:
                    # starting the new iperf server
                    start_iperf3_server(config, listener_key, listener_value, threads_n_processes, dict_data_to_send_to_server)


                # Iperf3 server was launch, but is it still running?
                else:
                    # The subproc is not running
                    if not thr_temp.getstatus():
                        # Print the last breath and remove from threads_n_processes dict
                        terminate_listener_and_childs(threads_n_processes, listener_key, thr_temp, config)

                        # starting the new iperf3 server
                        start_iperf3_server(config, listener_key, listener_value, threads_n_processes,
                                            dict_data_to_send_to_server)
    except Exception as exc:
        log.error(f"manage_listeners_process:{type(exc).__name__}:{exc}", exc_info=True)


# Launch the iperf3_client and add the subproc to threads_n_processes dict of st_obj_process_n_thread
def start_iperf3_server(config, listener_key, listener_value, threads_n_processes, dict_data_to_send_to_server):
    from lib.st_iperf import iperf3_server
    try:
        thread_or_process = st_obj_process_n_thread(subproc=None, name=listener_key,
                                                    syntraf_instance_type="LISTENER",
                                                    starttime=datetime.now(),
                                                    opposite_side=listener_value['UID_CLIENT'],
                                                    group=listener_value['MESH_GROUP'], port=listener_value['PORT'])
        threads_n_processes.append(thread_or_process)
        iperf3_server(config, listener_key, listener_value, threads_n_processes, dict_data_to_send_to_server)

    except Exception as exc:
        log.error(f"{type(exc).__name__}:{exc}", exc_info=True)


# Launch the iperf3_client and add the subproc to threads_n_processes dict of st_obj_process_n_thread
def start_iperf3_client(config, connector_key, connector_value, threads_n_processes, dict_data_to_send_to_server):
    from lib.st_iperf import iperf3_client
    try:
        # If this is a dynamic IP client, do not start a connector until we have the IP address of the listener
        if config['CONNECTORS'][connector_key]['DESTINATION_ADDRESS'] != "0.0.0.0":
            iperf3_conn_thread = st_obj_process_n_thread(subproc=None, name=connector_key,
                                                         syntraf_instance_type="CONNECTOR",
                                                         starttime=datetime.now(),
                                                         opposite_side=connector_value['UID_SERVER'],
                                                         group=connector_value['MESH_GROUP'],
                                                         port=connector_value['PORT'],
                                                         bidir_src_port=0, bidir_local_addr="")
            threads_n_processes.append(iperf3_conn_thread)
            iperf3_client(config, connector_key, connector_value, threads_n_processes, dict_data_to_send_to_server)

    except Exception as exc:
        log.error(f"{type(exc).__name__}:{exc}", exc_info=True)


def thread_read_log(config, edge_key, edge_value, edge_type, threads_n_processes, iperf3_thread,
                    dict_data_to_send_to_server):
    from lib.st_iperf3_readlog import read_log

    stop_thread_read_log = [False]
    thread_run = threading.Thread(target=read_log,
                                  args=(
                                      edge_key, edge_type, config,
                                      dict_data_to_send_to_server,
                                      threads_n_processes, iperf3_thread, stop_thread_read_log),
                                  daemon=True)

    thread_run.daemon = True
    thread_run.name = f"READ_LOG_{edge_type}:{edge_key}"
    thread_run.start()
    iperf_read_log_thread = st_obj_process_n_thread(thread_obj=thread_run, name=edge_key,
                                                    syntraf_instance_type="READ_LOG",
                                                    exit_boolean=stop_thread_read_log,
                                                    starttime=datetime.now(),
                                                    opposite_side=edge_value['UID_CLIENT'],
                                                    group=edge_value['MESH_GROUP'], port="")
    threads_n_processes.append(iperf_read_log_thread)


def thread_udp_hole(config, connector_key, connector_value, threads_n_processes, iperf3_conn_thread):
    from lib.st_iperf import udp_hole_punch
    stop_thread_udp_hole = [False]
    thread_run = threading.Thread(target=udp_hole_punch,
                                  args=(
                                      config['CONNECTORS'][connector_key]['DESTINATION_ADDRESS'],
                                      config['CONNECTORS'][connector_key]['PORT'], iperf3_conn_thread, connector_key,
                                      threads_n_processes, stop_thread_udp_hole),
                                  daemon=True)
    thread_run.daemon = True
    thread_run.name = f"UDP_HOLE:{connector_key}"
    thread_or_process = st_obj_process_n_thread(thread_obj=thread_run, name=connector_key,
                                                syntraf_instance_type="UDP_HOLE",
                                                exit_boolean=stop_thread_udp_hole,
                                                starttime=datetime.now(),
                                                opposite_side=connector_value['UID_CLIENT'],
                                                group=connector_value['MESH_GROUP'],
                                                port="")
    threads_n_processes.append(thread_or_process)
    thread_run.start()


# Validate if a st_obj_process_n_thread exist in the thread dict that correspond to the instance_type and the key provided
def st_obj_process_n_thread_exist(threads_n_processes, instance_type, connector_key):
    for thr in threads_n_processes:
        if thr.syntraf_instance_type == instance_type and connector_key in thr.name:
            return thr
    return None


def iperf3_print_last_breath(edge_key, edge_type, threads_n_processes, thr_temp):
    stderr_last_breath = ""
    if thr_temp.subproc.stderr:
        for l in thr_temp.subproc.stderr:
            stderr_last_breath = f"{stderr_last_breath} - {l}"

    last_breath = thr_temp.subproc.communicate()[1]
    thr_temp.subproc.stderr.close()
    last_breath = last_breath.replace("\r", "")
    last_breath = last_breath.replace("\n", "")
    log.warning(
        f"IPERF3 {edge_type} '{edge_key}' DIED OR NEVER START. LAST BREATH : '{last_breath.upper()} - {stderr_last_breath}'")

    try:
        thr_temp.subproc.communicate(timeout=1)
    except subprocess.TimeoutExpired:
        thr_temp.subproc.kill()
        thr_temp.subproc.communicate()
    except Exception as exc:
        pass
    threads_n_processes.remove(thr_temp)


def manage_connectors_process(config, threads_n_processes, dict_data_to_send_to_server, conn_db):
    try:
        # For each connector, validate config and run the iperf_client
        if 'CONNECTORS' in config:
            for connector_key, connector_value in config['CONNECTORS'].items():

                # Do we already have a CONNECTOR in the threads_n_processes dict
                thr_temp = st_obj_process_n_thread_exist(threads_n_processes, "CONNECTOR", connector_key)

                # Was never launch or was removed (maybe a client reverted to dynamic IP)
                if thr_temp is None:
                    # starting the new iperf3 connector. Also start udp_hole and read_log if this is a bidirectionnal connection
                    start_iperf3_client(config, connector_key, connector_value, threads_n_processes,
                                        dict_data_to_send_to_server)
                # Iperf3 client was launch, but is it still running?
                else:
                    # The subproc is not running
                    if not thr_temp.getstatus():
                        # Print the last breath and remove from threads_n_processes dict
                        terminate_connector_and_childs(threads_n_processes, connector_key, thr_temp, config)

                        # starting the new iperf3 connector. Also start udp_hole and read_log if this is a bidirectionnal connection
                        start_iperf3_client(config, connector_key, connector_value, threads_n_processes,
                                            dict_data_to_send_to_server)
    except Exception as exc:
        log.error(f"manage_connectors_process:{type(exc).__name__}:{exc}", exc_info=True)


#################################################################################
### RECEIVE DICTIONARY OF SUBPROCESSES THEN KILL THEM
#################################################################################
def kill_processes(subprocess_iperf_dict):
    import signal
    for e, f in enumerate(subprocess_iperf_dict):
        os.kill(subprocess_iperf_dict[f].pid, signal.SIGTERM)


#################################################################################
### RETURN THE st_obj_process_n_thread FROM THE threads_n_processes dict
#################################################################################
def get_current_obj_proc_n_thread(threads_n_processes, key, type):
    # Find current thread to update packet sent in the st_obj_process_n_thread object
    for thr in threads_n_processes:
        if key in thr.name and thr.syntraf_instance_type == type:
            return thr


def terminate_connector_and_childs(threads_n_processes, connector_key, thr_temp, config):
    """
    This function is called when we need to remove a connector. Either because we received non defined IP (see st_mesh.py), which mean the
    CLIENT on the other end was disconnected from SERVER, or when there is failure establishing a connection between the CONNECTOR and the LISTENER
    :param threads_n_processes: Dictionnary of st_obj_process_n_thread where we have all our thread and subproc
    :param connector_key: The unique key of the connector
    :param thr_temp : The actual thread we want to remove
    :param config : The configuration of syntraf
    """
    # If the connector is dead, send signal to terminate udp_hole and readlog instances and remove them from threads_n_processes dict

    copy_threads_n_processes = copy(threads_n_processes)
    for thread_to_kill in copy_threads_n_processes:
        if thread_to_kill.syntraf_instance_type == "UDP_HOLE" and connector_key in thread_to_kill.name:
            thread_to_kill.exit_boolean[0] = [True]
            threads_n_processes.remove(thread_to_kill)

        if thread_to_kill.syntraf_instance_type == "READ_LOG" and connector_key in thread_to_kill.name:
            thread_to_kill.exit_boolean[0] = [True]
            threads_n_processes.remove(thread_to_kill)

    # Print the last breath and remove from threads_n_processes dict
    iperf3_print_last_breath(connector_key, "CONNECTOR", threads_n_processes, thr_temp)


def terminate_listener_and_childs(threads_n_processes, listener_key, thr_temp, config):
    """
    This function is called when we need to remove a listener. i.e. When receiving new config
    :param threads_n_processes: Dictionnary of st_obj_process_n_thread where we have all our thread and subproc
    :param listener_key: The unique key of the connector
    :param thr_temp : The actual thread we want to remove
    :param config : The configuration of syntraf
    """

    # Kill the READ_LOG
    copy_threads_n_processes = copy(threads_n_processes)
    for thread_to_kill in copy_threads_n_processes:
        if thread_to_kill.syntraf_instance_type == "READ_LOG" and listener_key in thread_to_kill.name:
            thread_to_kill.exit_boolean[0] = [True]
            threads_n_processes.remove(thread_to_kill)

    # Print the last breath and remove from threads_n_processes dict
    iperf3_print_last_breath(listener_key, "LISTENER", threads_n_processes, thr_temp)


def close_listeners_and_connectors(threads_n_processes, _config):
    for thr in threads_n_processes:
        if thr.syntraf_instance_type == "CONNECTOR":
            terminate_connector_and_childs(threads_n_processes, thr.name, thr, _config)
        elif thr.syntraf_instance_type == "LISTENER":
            terminate_listener_and_childs(threads_n_processes, thr.name, thr, _config)
