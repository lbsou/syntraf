# SYNTRAF GLOBAL IMPORT
from lib.st_global import CompilationOptions, DefaultValues

# SYNTRAF SERVER IMPORT
if not CompilationOptions.client_only:
    from lib.st_crypto import *
    from lib.st_read_toml import *

    from flask import Flask, Response, render_template, request, send_from_directory, current_app, safe_join, jsonify
    from gevent.pywsgi import WSGIServer
    from gevent.pool import Pool
    from PIL import Image

    # BUILTIN IMPORT
    import os
    import time
    import ssl
    import logging

    # PACKAGE IMPORT
    import toml
    import json
    from pprint import pp

    app = Flask(__name__, template_folder=os.path.join(DefaultValues.SYNTRAF_ROOT_DIR, "lib", "web_ui", "templates"))
    app.config['EXPLAIN_TEMPLATE_LOADING'] = False
    app.debug = False

log = logging.getLogger(__name__)


class flask_wrapper (object):
    def __init__(self, threads_n_processes_param, subprocess_iperf_dict, _dict_by_node_generated_config, _dict_by_group_of_generated_tuple_for_map, dict_data_to_send_to_server, config, stats_dict_for_webui, config_file_path, conn_db, dict_of_commands_for_network_clients, dict_of_clients):
        self.conn_db = conn_db
        self.threads_n_processes = threads_n_processes_param
        self.subprocess_iperf_dict = subprocess_iperf_dict
        self._dict_by_node_generated_config = _dict_by_node_generated_config
        self.dict_data_to_send_to_server = dict_data_to_send_to_server
        self.config = config
        self.stats_dict_for_webui = stats_dict_for_webui
        self.config_file_path = config_file_path
        self.dict_of_commands_for_network_clients = dict_of_commands_for_network_clients
        self.dict_of_clients = dict_of_clients

        # Converting a dict of tuple to a dict of arrays for javascript
        dict_of_arrays_generated_tuples_for_map = {}

        for key, value in _dict_by_group_of_generated_tuple_for_map.items():
            if not key in dict_of_arrays_generated_tuples_for_map: dict_of_arrays_generated_tuples_for_map[key] = []
            for tuple in value:
                dict_of_arrays_generated_tuples_for_map[key].append([tuple[0], tuple[1]])

        self.dict_of_arrays_generated_tuples_for_map = dict_of_arrays_generated_tuples_for_map

    def run(self):
        pool = Pool(1000)
        http_server = WSGIServer(('0.0.0.0', DefaultValues.DEFAULT_WEBUI_PORT), app)

        try:
            #http_server = WSGIServer(('0.0.0.0', 5000), app, certfile=os.path.join(DefaultValues.DEFAULT_WEBUI_X509_SELFSIGNED_DIRECTORY,'certificate_webui.pem'), keyfile=os.path.join(DefaultValues.DEFAULT_WEBUI_X509_SELFSIGNED_DIRECTORY, 'private_key_webui.pem'), server_side=True, cert_reqs=ssl.CERT_NONE, do_handshake_on_connect=True, spawn=pool)
            http_server.serve_forever()
        except Exception as exc:
            print(exc)
            pass

    def inject(self):
        @app.route('/')
        @app.route('/home.html')
        def index():
            gen_config = toml.dumps(self._dict_by_node_generated_config).replace("\n", "<br/>")
            online_client = 0
            offline_client = 0

            return render_template('home.html', title='SYNTRAF WEBUI', config=self.config, gen_config=gen_config, conn_db=self.conn_db, online_client=online_client, offline_client=offline_client, syntraf_version=DefaultValues.SYNTRAF_VERSION)

        @app.route('/generated_client_config.html')
        def generated_config():
            #gen_config = toml.dumps(self._dict_by_node_generated_config)#.replace("\n", "</p><p>")
            return render_template('generated_client_config.html', title='SYNTRAF WEBUI', _dict_by_node_generated_config=self._dict_by_node_generated_config, syntraf_version=DefaultValues.SYNTRAF_VERSION)

        @app.route('/proc.html')
        def proc():
            return render_template('proc.html', title='SYNTRAF WEBUI', thr=self.threads_n_processes, process=self.subprocess_iperf_dict, syntraf_version=DefaultValues.SYNTRAF_VERSION)

        @app.route('/token.html')
        def token():
            return render_template('token.html', title='SYNTRAF - TOKEN CONFIGURATION', syntraf_version=DefaultValues.SYNTRAF_VERSION)

        @app.route('/config.html')
        def config():
            #config = toml.dumps(self.config).replace("\n", "<br/>")
            return render_template('config.html', title='SYNTRAF WEBUI', config=self.config, syntraf_version=DefaultValues.SYNTRAF_VERSION)

        @app.route('/queue.html')
        def queue():
            return render_template('queue.html', title='SYNTRAF WEBUI', dict_data_to_send_to_server=self.dict_data_to_send_to_server, syntraf_version=DefaultValues.SYNTRAF_VERSION)

        @app.route('/map.html')
        def map():
            return render_template('map.html', title='SYNTRAF WEBUI', config=self.config, syntraf_version=DefaultValues.SYNTRAF_VERSION)

        @app.route('/database_config.html')
        def database_config():
            return render_template('database_config.html', title='SYNTRAF WEBUI', config=self.config, syntraf_version=DefaultValues.SYNTRAF_VERSION)

        @app.route('/global_config.html')
        def global_config():
            return render_template('global_config.html', title='SYNTRAF WEBUI', config=self.config, syntraf_version=DefaultValues.SYNTRAF_VERSION)

        @app.route('/mesh_group_config.html')
        def mesh_group_config():
            return render_template('mesh_group_config.html', title='SYNTRAF WEBUI', config=self.config, syntraf_version=DefaultValues.SYNTRAF_VERSION)

        @app.route('/client_config.html')
        def client_config():
            return render_template('client_config.html', title='SYNTRAF WEBUI', config=self.config, syntraf_version=DefaultValues.SYNTRAF_VERSION)

        @app.route('/server.html')
        def server():
            return render_template('server.html', title='SYNTRAF WEBUI', config=self.config, syntraf_version=DefaultValues.SYNTRAF_VERSION)

        @app.route('/stats.html')
        def stats():
            return render_template('stats.html', title='SYNTRAF WEBUI', stats_dict_for_webui=self.stats_dict_for_webui, config=self.config, _dict_by_node_generated_config=self._dict_by_node_generated_config, syntraf_version=DefaultValues.SYNTRAF_VERSION, dict_of_clients=self.dict_of_clients)

        @app.route('/clients_configuration.html')
        def clients_configurations():
            return render_template('clients_configuration.html', title='SYNTRAF WEBUI', config=self.config, _dict_by_node_generated_config=self._dict_by_node_generated_config, syntraf_version=DefaultValues.SYNTRAF_VERSION)

        @app.route('/api', methods=['GET', 'POST'])
        def api():
            if request.method == 'GET':
                if 'getlogfilename' in request.args:
                    list_of_logfilename = os.listdir(self.config['GLOBAL']['LOGDIR'])
                    return jsonify(list_of_logfilename)

            elif request.method == 'POST':
                requested_action = request.values.get('ACTION', '')
                if requested_action == "SAVE_MAPS_JSON":
                    # read json and write JSON with new value
                    read_success, config = read_conf(self.config_file_path)
                    if read_success:
                        for mg in config['MESH_GROUP']:
                            if request.values.get('MESH_GROUP', '') == mg['UID']:
                                config['MESH_GROUP'][config['MESH_GROUP'].index(mg)]['WEBUI_JSON'] = request.values.get('CYTO_JSON', '')
                                with open(self.config_file_path, "w") as toml_file:
                                    #print("writing to disk")
                                    #print(config, self.config_file_path)
                                    toml.dump(config, toml_file)
                                    log.debug(f"RECEIVED A REQUEST TO SAVE MAPS CONFIG OF GROUP '{mg['UID']}' TO DISK")
                elif requested_action == "RECONNECT_CLIENT":

                    client_uid = request.values.get('CLIENT', '')
                    log.debug(f"RECONNECT ASKED FOR CLIENT: '{client_uid}'")

                    if self.dict_of_clients[client_uid].status == "CONNECTED":
                        # if the client_uid is not in the dict, add it with an empty array as value
                        if not client_uid in self.dict_of_commands_for_network_clients: self.dict_of_commands_for_network_clients[client_uid] = []

                        # add the action
                        self.dict_of_commands_for_network_clients[client_uid].append({"ACTION": requested_action})

                        return "OK"
                    else:
                        # Client not connected
                        return "E1003"

                elif requested_action == "RESTART_CLIENT":

                    client_uid = request.values.get('CLIENT', '')
                    log.debug(f"RESTART ASKED FOR CLIENT: '{client_uid}'")

                    if self.dict_of_clients[client_uid].status == "CONNECTED":
                        # if the client_uid is not in the dict, add it with an empty array as value
                        if not client_uid in self.dict_of_commands_for_network_clients: self.dict_of_commands_for_network_clients[client_uid] = []

                        # add the action
                        self.dict_of_commands_for_network_clients[client_uid].append({"ACTION": requested_action})

                        return "OK"
                    else:
                        # Client not connected
                        return "E1003"

                elif requested_action == "SAVE_BACKGROUND":
                    group = request.values.get('GROUP', '')
                    image = request.values.get('BACKGROUND_IMAGE', '')
                    log.debug(f"RECEIVED A REQUEST TO UPDATE BACKGROUND IMAGE OF GROUP '{group}'")
                    print(image)

                    # if image.filename == '':
                    #     return "FAIL_NO_FILE_SELECTED"
                    # if image:
                    #     file.save(os.path.join(app.config['UPLOAD_FOLDER'], image.filename))
                    # return "OK"

                elif requested_action == "GET_THREAD_STATUS":
                    client_uid = request.values.get('CLIENT_UID', '')

                    if client_uid in self.dict_of_clients:
                        if len(self.dict_of_clients[client_uid].system_infos) >= 1:
                            return jsonify(self.dict_of_clients[client_uid].thread_status)
                        else:
                            # No thread_status for this client
                            return "E1001"
                    else:
                        # Non existent client
                        return "E1002"

                elif requested_action == "GET_SYSTEM_INFOS":
                    client_uid = request.values.get('CLIENT_UID', '')

                    if client_uid in self.dict_of_clients:
                        if len(self.dict_of_clients[client_uid].system_infos) >= 1:
                            return jsonify(self.dict_of_clients[client_uid].system_infos)
                        else:
                            # No system infos for this client
                            return "E1001"
                    else:
                        # Non existent client
                        return "E1002"

                elif requested_action == "GET_SYSTEM_STATS":
                    dict_of_clients_as_json = {}
                    for k, v in self.dict_of_clients.items():
                        dict_of_clients_as_json[k] = v.asjson()
                    return dict_of_clients_as_json

                elif requested_action == "GET_TOKENS":
                    tokens = self.config['SERVER']['TOKEN']
                    print(type(tokens))
                    for a, b in tokens.items():
                        print(a, "@", b)

                    return self.config['SERVER']['TOKEN']

                elif requested_action == "GET_NUMBER_OF_ONLINE_CLIENT":
                    online_client = 0
                    for client in self.dict_of_clients.values():
                        if client.status == "CONNECTED":
                            online_client += 1
                    return str(online_client)

                elif requested_action == "GET_NUMBER_OF_OFFLINE_CLIENT":
                    offline_client = 0
                    for client in self.dict_of_clients.values():
                        if client.status == "DISCONNECTED" or client.status == "UNSEEN":
                            offline_client += 1
                    return str(offline_client)

                return "OK"
            else:
                return "OK"

        def flask_logger(logfile):
            for i in range(10000):
                yield str(i)
                time.sleep(1)
            #yield self.config['GLOBAL']['LOGDIR']

        @app.route("/log_viewer.html", methods=["GET"])
        def log_viewer():
            #return Response(flask_logger(request.args.get("logfile")), mimetype="text/plain", content_type="text/event-stream")
            return render_template("log_viewer.html")

        @app.route("/maps.html", methods=['GET', 'POST'])
        def maps():
            elements = ""
            background = ""
            elements = ""
            background_size = ("", "")
            if request.method == "GET" and request.args.get("mesh_group_map"):
                read_success, config = read_conf(self.config_file_path)
                if read_success:
                    mesh_group = [mg for mg in config['MESH_GROUP'] if mg['UID'] == request.args.get("mesh_group_map")]

                    if "WEBUI_JSON" in mesh_group[0]:
                        elements = mesh_group[0]["WEBUI_JSON"]

                    if "WEBUI_BACKGROUND" in mesh_group[0]:
                        background = mesh_group[0]["WEBUI_BACKGROUND"]

                        # We must get the width and height of the background
                        bg_path = os.path.join(DefaultValues.SYNTRAF_ROOT_DIR, "lib", "static", "maps", mesh_group[0]["WEBUI_BACKGROUND"])
                        im = Image.open(bg_path)
                        background_size = im.size

            return render_template("maps.html", elem=elements, config=self.config, selected_map=request.args.get("mesh_group_map"), background=background, background_size=background_size, dict_of_arrays_generated_tuples_for_map=self.dict_of_arrays_generated_tuples_for_map, syntraf_version=DefaultValues.SYNTRAF_VERSION)

        @app.after_request
        def add_header(r):
            r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, public, max-age=0"
            r.headers["Pragma"] = "no-cache"
            r.headers["Expires"] = "0"
            return r

