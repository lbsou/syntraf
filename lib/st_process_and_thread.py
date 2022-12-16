# SYNTRAF GLOBAL IMPORT
from lib.st_global import DefaultValues
from lib.st_mesh import *
from lib.st_iperf import *
from lib.st_obj_process_n_thread import *
from lib.st_conf_validation import *
from lib.st_iperf3_readlog import *
from lib.st_system_stats import *


# SYNTRAF SERVER IMPORT
if not CompilationOptions.client_only:
    from lib.web_ui_kindafixed2 import create_app

    #from gevent import monkey
    #monkey.patch_all()
    from gevent.pywsgi import WSGIServer

    from werkzeug.serving import run_simple
    from werkzeug.middleware.profiler import ProfilerMiddleware
    from gevent.pool import Pool
# BUILTIN IMPORT
import logging
from datetime import datetime
import threading
import time
import os

# from lib.st_covariance import *

log = logging.getLogger("syntraf." + __name__)




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
def launch_and_respawn_workers(config, cli_parameters, threads_n_processes,  obj_stats, dict_of_clients, dict_data_to_send_to_server, dict_of_commands_for_network_clients, _dict_by_node_generated_config, _dict_by_group_of_generated_tuple_for_map, dict_of_client_pending_acceptance, config_file_path, conn_db, subprocess_iperf_dict=dict()):
    try:
        # STATS
        list = [thr for thr in threads_n_processes if getattr(thr, 'syntraf_instance_type') == "STATS"]
        if not list:
            thr_stats = threading.Thread(target=launch_stats,
                                          args=(config, obj_stats),
                                          daemon=True)
            thr_stats.name = "STATS"
            thr_stats.start()
            thread_or_process = st_obj_process_n_thread(thread_obj=thr_stats, name="STATS", syntraf_instance_type="STATS", exit_boolean=False, starttime=datetime.now().strftime("%d/%m/%Y %H:%M:%S"), opposite_side="", group="", port="")
            threads_n_processes.append(thread_or_process)

        # LISTENERS
        manage_listeners_process(config, threads_n_processes, dict_data_to_send_to_server, conn_db)

        # CONNECTORS
        manage_connectors_process(config, threads_n_processes, dict_data_to_send_to_server, conn_db)

        # SERVER
        if "SERVER" in config:
            manage_mesh(config, threads_n_processes, "SERVER", obj_stats, config_file_path, cli_parameters, dict_of_client_pending_acceptance=dict_of_client_pending_acceptance, dict_of_clients=dict_of_clients, conn_db=conn_db, _dict_by_node_generated_config=_dict_by_node_generated_config, dict_of_commands_for_network_clients=dict_of_commands_for_network_clients)

            # WEBUI
            list = [thr for thr in threads_n_processes if getattr(thr, 'syntraf_instance_type') == "WEBUI"]
            if not list:
                thr_webui = threading.Thread(target=launch_webui,
                                              args=(threads_n_processes, subprocess_iperf_dict, _dict_by_node_generated_config, _dict_by_group_of_generated_tuple_for_map, dict_data_to_send_to_server, config, cli_parameters, config_file_path, conn_db, dict_of_commands_for_network_clients, dict_of_clients),
                                              daemon=True)
                thr_webui.name = "WEBUI"
                thr_webui.start()
                thread_or_process = st_obj_process_n_thread(thread_obj=thr_webui, name="WEBUI", syntraf_instance_type="WEBUI", exit_boolean=False, starttime=datetime.now().strftime("%d/%m/%Y %H:%M:%S"), opposite_side="", group="", port="")
                threads_n_processes.append(thread_or_process)

            # COVARIANCE, ONLY IF SERVER
            list = [thr for thr in threads_n_processes if getattr(thr, 'syntraf_instance_type') == "COVARIANCE"]
            #if not list:
                #thr_covariance = threading.Thread(target=init_covar,
                #                                  args=[config, conn_db],
                #                                  daemon=True)
                #thr_covariance.name = "COVARIANCE"
                # thr_covariance.start()
                # thread_or_process = st_obj_process_n_thread(thread_obj=thr_covariance, name="COVARIANCE", syntraf_instance_type="COVARIANCE", exit_boolean=False, starttime=datetime.now())
                # threads_n_processes.append(thread_or_process)

        # CLIENT
        manage_mesh(config, threads_n_processes, "CLIENT", obj_stats, config_file_path, cli_parameters, dict_data_to_send_to_server=dict_data_to_send_to_server)


    except Exception as exc:
        log.error(f"launch_and_respawn_workers:{type(exc).__name__}:{exc}", exc_info=True)
    return threads_n_processes, subprocess_iperf_dict


def launch_webui(threads_n_processes, subprocess_iperf_dict, _dict_by_node_generated_config, _dict_by_group_of_generated_tuple_for_map, dict_data_to_send_to_server, config, cli_parameters, config_file_path, conn_db, dict_of_commands_for_network_clients, dict_of_clients):
    try:
        app = create_app(threads_n_processes, subprocess_iperf_dict, _dict_by_node_generated_config, _dict_by_group_of_generated_tuple_for_map, dict_data_to_send_to_server, config, config_file_path, conn_db, dict_of_commands_for_network_clients, dict_of_clients)
        #app = ProfilerMiddleware(app)
        cert_path = os.path.join(DefaultValues.SYNTRAF_ROOT_DIR, "crypto", "WEBUI_X509_SELFSIGNED_DIRECTORY")
        pool = Pool(100)

        try:
            http_server = WSGIServer(('0.0.0.0', DefaultValues.DEFAULT_WEBUI_PORT), app, error_log=log, log=log)

        #try:
        #    http_server = WSGIServer(('0.0.0.0', DefaultValues.DEFAULT_WEBUI_PORT), app,
        #                             certfile=os.path.join(cert_path, 'certificate_webui.pem'),
        #                             keyfile=os.path.join(cert_path, 'private_key_webui.pem'), server_side=True,
        #                             cert_reqs=ssl.CERT_NONE, do_handshake_on_connect=True, spawn=pool, environ={'wsgi.multithread': True, 'wsgi.multiprocess': True,})
            http_server.serve_forever()
        except Exception as exc:
            print(exc)
    except Exception as msg:
        print(msg)


def launch_stats(config, obj_stats):
    while True:
        # Client only code
        if 'CLIENT' in config:
            obj_stats.update_stats()

        time.sleep(DefaultValues.DEFAULT_CLIENT_METRICS_UPDATE_FREQUENCY)


def init_client_obj_dict(config, dict_of_clients):
    if "SERVER" in config and "SERVER_CLIENT" in config:
        # Initializing status dict
        for client in config['SERVER_CLIENT']:

            dict_of_clients[client['UID']] = cc_client(status="UNKNOWN", status_since=datetime.now().strftime("%d/%m/%Y %H:%M:%S"),  status_explanation="NEVER CONNECTED", client_uid=client['UID'], bool_dynamic_client=False)

            list_stats_if_pct_usage_tx = []
            list_stats_if_pct_usage_rx = []
            list_stats_mem_pct_free = []
            list_stats_cpu_pct_usage = []

            dict_of_clients[client['UID']].system_stats = {'if_pct_usage_rx': list_stats_if_pct_usage_tx,
                                                   'if_pct_usage_tx': list_stats_if_pct_usage_rx,
                                                   'mem_pct_free': list_stats_mem_pct_free,
                                                   'cpu_pct_usage': list_stats_cpu_pct_usage}


def manage_mesh(config, threads_n_processes, mesh_type, obj_stats, config_file_path, cli_parameters, dict_of_client_pending_acceptance={}, dict_of_clients={}, dict_data_to_send_to_server=[], conn_db=None, _dict_by_node_generated_config=dict(), dict_of_commands_for_network_clients=dict()):
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
                #log.error("WEBUI THREAD COULD NOT RUN OR DIED, PLEASE INVESTIGATE")
                #sys.exit()
                threads_n_processes.remove(thr_temp)

                thread_run = None
                # RESTART MESH INSTANCE
                if mesh_type == "CLIENT":
                    thread_run = threading.Thread(target=eval(mesh_type.lower()), args=(config, stop_thread, dict_data_to_send_to_server, threads_n_processes, obj_stats, config_file_path, cli_parameters),
                                                  daemon=True)
                elif mesh_type == "SERVER":
                    init_client_obj_dict(config, dict_of_clients)
                    thread_run = threading.Thread(target=eval(mesh_type.lower()),
                                                  args=(config, threads_n_processes, stop_thread, _dict_by_node_generated_config, obj_stats, conn_db, dict_of_commands_for_network_clients, dict_of_clients, dict_of_client_pending_acceptance), daemon=True)
                thread_run.daemon = True
                thread_run.name = mesh_type
                thread_run.start()
                thread_or_process = st_obj_process_n_thread(thread_obj=thread_run, name=mesh_type, object_type="THREAD",
                                                            syntraf_instance_type=mesh_type, exit_boolean=stop_thread, starttime=datetime.now().strftime("%d/%m/%Y %H:%M:%S"), opposite_side="", group="", port="")
                threads_n_processes.append(thread_or_process)
                if mesh_type == "CLIENT":
                    log.info(f"{mesh_type} RE-INITIATED : {config[mesh_type]['SERVER']}:{config[mesh_type]['SERVER_PORT']}")
                elif mesh_type == "SERVER":
                    log.info(f"{mesh_type} RE-INITIATED : {config[mesh_type]['BIND_ADDRESS']}:{config[mesh_type]['SERVER_PORT']}")
            # Validate MESH config and start the thread
            elif thr_temp is None:
                log.info(f"VALIDATION OF {mesh_type} CONFIG SUCCESSFUL!")

                thread_run = None
                # START MESH INSTANCE
                if mesh_type == "CLIENT":
                    thread_run = threading.Thread(target=eval(mesh_type.lower()), args=(config, stop_thread, dict_data_to_send_to_server, threads_n_processes, obj_stats, config_file_path, cli_parameters),
                                                  daemon=True)
                elif mesh_type == "SERVER":
                    init_client_obj_dict(config, dict_of_clients)
                    thread_run = threading.Thread(target=eval(mesh_type.lower()),
                                                  args=(config, threads_n_processes, stop_thread, _dict_by_node_generated_config, obj_stats, conn_db, dict_of_commands_for_network_clients, dict_of_clients, dict_of_client_pending_acceptance), daemon=True)
                thread_run.daemon = True
                thread_run.name = mesh_type
                thread_run.start()
                thread_or_process = st_obj_process_n_thread(thread_obj=thread_run, name=mesh_type, object_type="THREAD",
                                                            syntraf_instance_type=mesh_type, exit_boolean=stop_thread, starttime=datetime.now().strftime("%d/%m/%Y %H:%M:%S"), opposite_side="", group="", port="")

                threads_n_processes.append(thread_or_process)
                if config[mesh_type] == "CLIENT":
                    log.info(
                        f"{mesh_type} INITIATED : {config[mesh_type]['SERVER']}:{config[mesh_type]['SERVER_PORT']}")
                elif config[mesh_type] == "SERVER":
                    log.info(f"{mesh_type} INITIATED : {config[mesh_type]['BIND_ADDRESS']}:{config[mesh_type]['SERVER_PORT']}")

    except Exception as exc:
        log.error(f"manage_mesh:{type(exc).__name__}:{exc}", exc_info=True)


def thread_udp_hole(config, connector, connector_v, iperf3_pid, threads_n_processes, iperf_conn_thread):
    exit_boolean = [False]
    log.error("===================================================================================")
    log.error(iperf_conn_thread, connector_v,connector)
    log.error("===================================================================================")
    thread_run = threading.Thread(target=udp_hole_punch,
                                  args=(
                                      config['CONNECTORS'][connector]['DESTINATION_ADDRESS'],
                                      config['CONNECTORS'][connector]['PORT'], iperf3_pid, exit_boolean, iperf_conn_thread),
                                  daemon=True)
    thread_run.daemon = True
    thread_run.name = str("UDP HOLE PUNCH")
    thread_run.start()
    thread_or_process = st_obj_process_n_thread(thread_obj=thread_run, name=connector,
                                                syntraf_instance_type="UDP_HOLE",
                                                exit_boolean=exit_boolean,
                                                starttime=datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
                                                opposite_side=connector_v['UID_CLIENT'], group=connector_v['MESH_GROUP'],
                                                port="")

    threads_n_processes.append(thread_or_process)


def manage_listeners_process(config, threads_n_processes, dict_data_to_send_to_server, conn_db):
    stop_thread = [False]
    try:
        # For each listener, validate config and run the iperf_server
        if 'LISTENERS' in config:

            for listener, listener_v in config['LISTENERS'].items():
                # check if a st_obj_process_n_thread exist with LISTENER instance_type and the name corresponding the current listener config of the loop
                # the goal is to see if it's already running
                for thr in threads_n_processes:
                    if thr.syntraf_instance_type == "LISTENER" and thr.name == listener:
                        if not thr.subproc:
                            threads_n_processes.remove(thr)
                            thr_temp = None
                        else:
                            thr_temp = thr
                        break
                    else:
                        thr_temp = None

                # Was never launch
                if not thr_temp:
                    # starting the new iperf server
                    thread_or_process = st_obj_process_n_thread(subproc=iperf3_server(listener, config), name=listener,
                                                                syntraf_instance_type="LISTENER",
                                                                starttime=datetime.now().strftime("%d/%m/%Y %H:%M:%S"), opposite_side=listener_v['UID_CLIENT'], group=listener_v['MESH_GROUP'], port=listener_v['PORT'])
                    threads_n_processes.append(thread_or_process)
                # Was launch, but is it running?
                else:
                    # The subproc is not running
                    if not thr_temp.subproc.poll() is None:
                        # Print the last breath
                        log.warning(f"IPERF3 SERVER OF LISTENER '{listener}' DIED OR NEVER START. LAST BREATH : '{thr_temp.subproc.communicate()[1]}'")
                        threads_n_processes.remove(thr_temp)

                        # starting the new iperf server
                        thread_or_process = st_obj_process_n_thread(subproc=iperf3_server(listener, config), name=listener,
                                                            syntraf_instance_type="LISTENER", starttime=datetime.now().strftime("%d/%m/%Y %H:%M:%S"), opposite_side=listener_v['UID_CLIENT'], group=listener_v['MESH_GROUP'], port=listener_v['PORT'])

                        threads_n_processes.append(thread_or_process)

                # MAKE SURE WE HAVE A READLOG FOR EACH LISTENER
                for thr in threads_n_processes:
                    if thr.syntraf_instance_type == "LISTENER":
                        got_a_readlog_instance = False
                        for thr2 in threads_n_processes:
                            # There is already a thread, but is it running?
                            if thr2.syntraf_instance_type == "READ_LOG" and thr2.name == listener:
                                # Is the subproc running? If no, restart it
                                if not thr2.thread_obj.is_alive():
                                    threads_n_processes.remove(thr2)

                                    stop_thread = [False]
                                    thread_run = threading.Thread(target=read_log_listener,
                                                                  args=(
                                                                  listener, config, stop_thread, dict_data_to_send_to_server, conn_db, threads_n_processes),
                                                                  daemon=True)
                                    thread_run.daemon = True
                                    thread_run.name = str(listener)
                                    thread_run.start()
                                    thread_or_process = st_obj_process_n_thread(thread_obj=thread_run, name=listener,
                                                                                syntraf_instance_type="READ_LOG",
                                                                                exit_boolean=stop_thread,
                                                                                starttime=datetime.now().strftime("%d/%m/%Y %H:%M:%S"), opposite_side=listener_v['UID_CLIENT'], group=listener_v['MESH_GROUP'], port="")
                                    threads_n_processes.append(thread_or_process)
                                    got_a_readlog_instance = True
                                else:
                                    got_a_readlog_instance = True

                        if not got_a_readlog_instance:
                            # Was never launch, starting the new READLOG thread
                            thread_run = threading.Thread(target=read_log_listener,
                                                          args=(listener, config, stop_thread, dict_data_to_send_to_server, conn_db, threads_n_processes),
                                                          daemon=True)
                            thread_run.daemon = True
                            thread_run.name = str(listener)
                            thread_run.start()
                            thread_or_process = st_obj_process_n_thread(thread_obj=thread_run, name=listener,
                                                                        syntraf_instance_type="READ_LOG",
                                                                        exit_boolean=stop_thread, starttime=datetime.now().strftime("%d/%m/%Y %H:%M:%S"), opposite_side=listener_v['UID_CLIENT'], group=listener_v['MESH_GROUP'], port="")

                            threads_n_processes.append(thread_or_process)

    except Exception as exc:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)
        log.error(f"manage_listeners_process:{type(exc).__name__}:{exc}", exc_info=True)


def manage_connectors_process(config, threads_n_processes, dict_data_to_send_to_server, conn_db):
    stop_thread = [False]
    thr_temp = None
    try:
        # For each connector, validate config and run the iperf_client
        if 'CONNECTORS' in config:
            for connector, connector_v in config['CONNECTORS'].items():

                # If this is a dynamic IP client, do not start a connector until we have his IP address
                if config['CONNECTORS'][connector]['DESTINATION_ADDRESS'] == "0.0.0.0":
                    continue

                # check if a st_obj_process_n_thread exist with CONNECTOR instance_type and the name corresponding the current connector config of the loop
                # the goal is to see if it's already running
                for thr in threads_n_processes:
                    if thr.syntraf_instance_type == "CONNECTOR" and thr.name == connector:
                        thr_temp = thr
                        break
                    else:
                        thr_temp = None

                # Was never launch
                if not thr_temp:
                    # starting the new iperf connector
                    iperf_conn_thread = st_obj_process_n_thread(subproc=iperf3_client(connector, config), name=connector,
                                                                syntraf_instance_type="CONNECTOR",
                                                                starttime=datetime.now().strftime("%d/%m/%Y %H:%M:%S"), opposite_side=connector_v['UID_SERVER'], group=connector_v['MESH_GROUP'], port=connector_v['PORT'], bidir_src_port=0)

                    # It is possible that the process failed on start, in that case, do not add the object to the dict
                    if iperf_conn_thread.subproc:
                        threads_n_processes.append(iperf_conn_thread)

                        # Make sure we have a udp_hole punching thread for each bidir connector
                        if config['CONNECTORS'][connector]['BIDIR']:
                            thread_udp_hole(config, connector, connector_v, iperf_conn_thread.subproc.pid, threads_n_processes, iperf_conn_thread)

                # Was launch, but is it running?
                else:
                    # The subproc is not running
                    if not thr_temp.getstatus():
                        # Print the last breath
                        last_breath = thr_temp.subproc.communicate()[1].decode('utf-8')
                        thr_temp.subproc.stderr.close()
                        last_breath = last_breath.replace("\r", "")
                        last_breath = last_breath.replace("\n", "")
                        log.warning(f"IPERF3 CLIENT OF CONNECTOR '{connector}' DIED OR NEVER START. LAST BREATH : '{last_breath.upper()}'")

                        threads_n_processes.remove(thr_temp)

                        # If the connector is dead, kill the udp_hole instance
                        if config['CONNECTORS'][connector]['BIDIR']:
                            for thr_udp_hole in threads_n_processes:
                                if thr_udp_hole.syntraf_instance_type == "UDP_HOLE" and thr_udp_hole.name == connector:
                                    thr_udp_hole.exit_boolean = True
                                    threads_n_processes.remove(thr_udp_hole)
                                    #thr_udp_hole = None
                                    break

                        # Removing previous subprocess


                        # starting the new iperf connector
                        iperf_conn_thread = st_obj_process_n_thread(subproc=iperf3_client(connector, config), name=connector,
                                                            syntraf_instance_type="CONNECTOR", starttime=datetime.now().strftime("%d/%m/%Y %H:%M:%S"), opposite_side=connector_v['UID_SERVER'], group=connector_v['MESH_GROUP'], port=connector_v['PORT'], bidir_src_port=0)

                        # It is possible that the process failed on start, in that case, do not add the object to the dict
                        if iperf_conn_thread.subproc:
                            threads_n_processes.append(iperf_conn_thread)

                            # Make sure we have a udp_hole punching thread for each bidir connector
                            if config['CONNECTORS'][connector]['BIDIR']:
                                thread_udp_hole(config, connector, connector_v, iperf_conn_thread.subproc.pid, threads_n_processes, iperf_conn_thread)

                # MAKE SURE WE HAVE A READLOG FOR EACH BIDIR CONNECTOR
                for thr in threads_n_processes:
                    # FIND A BIDIR CONNECTOR
                    if thr.syntraf_instance_type == "CONNECTOR" and config['CONNECTORS'][connector]['BIDIR']:
                        got_a_readlog_instance = False
                        # FIND IF THERE IS AN ASSOCIATED READ_LOG
                        for thr2 in threads_n_processes:
                            if thr2.syntraf_instance_type == "READ_LOG" and thr2.name == connector:
                                # THERE IS AN OBJECT BUT IS IT RUNNING?
                                if not thr2.thread_obj.is_alive():
                                    # DELETE THE DEAD THREAD
                                    threads_n_processes.remove(thr2)

                                    stop_thread = [False]
                                    thread_run = threading.Thread(target=read_log_connector,
                                                                  args=(
                                                                      connector, config, stop_thread,
                                                                      dict_data_to_send_to_server, conn_db,
                                                                      threads_n_processes, thr),
                                                                  daemon=True)
                                    thread_run.daemon = True
                                    thread_run.name = str(connector)
                                    thread_run.start()
                                    iperf_read_log_thread = st_obj_process_n_thread(thread_obj=thread_run, name=connector,
                                                                                syntraf_instance_type="READ_LOG",
                                                                                exit_boolean=stop_thread,
                                                                                starttime=datetime.now().strftime(
                                                                                    "%d/%m/%Y %H:%M:%S"),
                                                                                opposite_side=connector_v['UID_CLIENT'],
                                                                                group=connector_v['MESH_GROUP'], port="")
                                    threads_n_processes.append(iperf_read_log_thread)
                                    got_a_readlog_instance = True
                                else:
                                    got_a_readlog_instance = True
                        if not got_a_readlog_instance:
                            # Was never launch, starting the new READLOG thread
                            thread_run = threading.Thread(target=read_log_connector,
                                                          args=(
                                                          connector, config, stop_thread, dict_data_to_send_to_server, conn_db,
                                                          threads_n_processes, thr),
                                                          daemon=True)
                            thread_run.daemon = True
                            thread_run.name = str(connector)
                            thread_run.start()
                            iperf_read_log_thread = st_obj_process_n_thread(thread_obj=thread_run, name=connector,
                                                                        syntraf_instance_type="READ_LOG",
                                                                        exit_boolean=stop_thread,
                                                                        starttime=datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
                                                                        opposite_side=connector_v['UID_CLIENT'],
                                                                        group=connector_v['MESH_GROUP'], port="")

                            threads_n_processes.append(iperf_read_log_thread)

    except Exception as exc:
        log.error(f"manage_connectors_process:{type(exc).__name__}:{exc}", exc_info=True)


#################################################################################
### RECEIVE DICTIONARY OF SUBPROCESSES DANS KILL THEM
#################################################################################
def kill_processes(subprocess_iperf_dict):
    import signal
    for e, f in enumerate(subprocess_iperf_dict):
        os.kill(subprocess_iperf_dict[f].pid, signal.SIGTERM)


