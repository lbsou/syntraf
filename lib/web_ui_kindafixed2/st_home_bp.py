# SYNTRAF GLOBAL IMPORT
from lib import st_mesh_group_ops
from lib.web_ui_kindafixed2.st_auth import actor as _actor
from lib.st_global import CompilationOptions, DefaultValues

# SYNTRAF SERVER IMPORT
if not CompilationOptions.client_only:
    from flask import current_app as app
    from lib.st_crypto import *
    from lib.st_read_toml import *

    from flask import Flask, Response, render_template, request, send_from_directory, current_app, jsonify, \
        make_response, flash, redirect, session, abort, url_for, g, Blueprint



    # BUILTIN IMPORT
    import os
    import time
    import logging
    import copy
    import collections
    from datetime import datetime as dt

    # PACKAGE IMPORT
    import toml
    import json
    #from pprint import pp

log = logging.getLogger("syntraf." + __name__)

# Blueprint Configuration
st_home_bp = Blueprint(
    'st_home_bp', __name__,
    template_folder='templates',
    static_folder='static'
)


@st_home_bp.route('/home.html')
def home():
    return render_template(
        'home.html',
        title="SYNTRAF",
        conn_db=app.config['conn_db'],
        syntraf_version=DefaultValues.SYNTRAF_VERSION
    )

@st_home_bp.route('/favicon.ico')
def favicon():
    return redirect(url_for('static', filename='favicon.svg'))


@st_home_bp.route('/')
def index():
    # login.html date d'avant le passage à Bootstrap 5 et l'authentification n'est pas branchée : accueil direct.
    return redirect(url_for('st_home_bp.home'))


@st_home_bp.route('/token_config.html')
def token_config():
    return render_template('token_config.html', syntraf_version=DefaultValues.SYNTRAF_VERSION)


@st_home_bp.route('/database_config.html')
def database_config():
    return render_template('database_config.html', title='SYNTRAF WEBUI', config=app.config['config'],
                           syntraf_version=DefaultValues.SYNTRAF_VERSION)


@st_home_bp.route('/mesh_group_config.html')
def mesh_group_config():
    return render_template('mesh_group_config.html', title='SYNTRAF WEBUI', config=app.config['config'],
                           syntraf_version=DefaultValues.SYNTRAF_VERSION)


@st_home_bp.route('/client_config.html')
def client_config():
    return render_template('client_config.html', title='SYNTRAF WEBUI', config=app.config['config'])


# Documentation HTML du dépôt (docs/html), servie aux utilisateurs connectés
DOCS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "docs", "html")


@st_home_bp.route('/docs/')
@st_home_bp.route('/docs/<path:name>')
def documentation(name="index.html"):
    if not os.path.isfile(os.path.join(DOCS_DIR, "index.html")):
        return "Documentation not installed (docs/html is missing from this installation).", 404
    return send_from_directory(DOCS_DIR, name)  # refuse tout chemin hors du dossier (404)


@st_home_bp.route('/maintenance.html')
def maintenance_page():
    return render_template('maintenance.html')


@st_home_bp.route('/grafana.html')
def grafana_page():
    return render_template('grafana.html')


@st_home_bp.route('/alerts.html')
def alerts_page():
    return render_template('alerts.html')


@st_home_bp.route('/live_map.html')
def live_map():
    return render_template('live_map.html', title='SYNTRAF WEBUI')


@st_home_bp.route('/server.html')
def server():
    return render_template('server.html', title='SYNTRAF WEBUI', config=app.config['config'],
                           syntraf_version=DefaultValues.SYNTRAF_VERSION)



@st_home_bp.route('/paths.html')
def paths():
    return render_template('paths.html')


@st_home_bp.route('/tcp_tests.html')
def tcp_tests():
    return render_template('tcp_tests.html')


@st_home_bp.route('/profile_config.html')
def profile_config():
    return render_template('profile_config.html')


@st_home_bp.route('/data.html')
def data():
    return render_template('data.html')


@st_home_bp.route('/updates.html')
def updates():
    return render_template('updates.html')


@st_home_bp.route('/audit.html')
def audit():
    return render_template('audit.html', syntraf_version=DefaultValues.SYNTRAF_VERSION)


@st_home_bp.route('/stats.html')
def stats():
    return render_template('stats.html', title='SYNTRAF WEBUI', config=app.config['config'],
                           _dict_by_node_generated_config=app.config['_dict_by_node_generated_config'],
                           dict_of_clients=app.config['dict_of_clients'])


@st_home_bp.route('/api', methods=['GET', 'POST'])
def api():
    if request.method == 'POST':
        requested_action = request.values.get('ACTION', '')
        if requested_action == "RECONNECT_CLIENT":
            ''' =============================================================================================== '''

            client_uid = request.values.get('CLIENT', '')
            log.debug(f"RECONNECT ASKED FOR CLIENT: '{client_uid}'")

            if app.config['dict_of_clients'][client_uid].status == "CONNECTED":
                # if the client_uid is not in the dict, add it with an empty array as value
                if not client_uid in app.config['dict_of_commands_for_network_clients']:
                    app.config['dict_of_commands_for_network_clients'][client_uid] = []

                # add the action
                app.config['dict_of_commands_for_network_clients'][client_uid].append({"ACTION": requested_action})

                return "OK"
            else:
                # Client not connected
                return "E1003"

        elif requested_action == "RESTART_CLIENT":
            ''' =============================================================================================== '''
            client_uid = request.values.get('CLIENT', '')
            log.debug(f"RESTART ASKED FOR CLIENT: '{client_uid}'")

            if app.config['dict_of_clients'][client_uid].status == "CONNECTED":
                # if the client_uid is not in the dict, add it with an empty array as value
                if not client_uid in app.config['dict_of_commands_for_network_clients']:
                    app.config['dict_of_commands_for_network_clients'][client_uid] = []

                # add the action
                app.config['dict_of_commands_for_network_clients'][client_uid].append({"ACTION": requested_action})

                return "OK"
            else:
                # Client not connected
                return "E1003"

        elif requested_action == "GET_THREAD_STATUS":
            ''' =============================================================================================== '''
            client_uid = request.values.get('CLIENT_UID', '')

            if client_uid in app.config['dict_of_clients']:
                if len(app.config['dict_of_clients'][client_uid].system_infos) >= 1:
                    return jsonify(app.config['dict_of_clients'][client_uid].thread_status)
                else:
                    # No thread_status for this client
                    return "E1001"
            else:
                # Non existent client
                return "E1002"

        elif requested_action == "GET_SYSTEM_INFOS":
            ''' =============================================================================================== '''
            client_uid = request.values.get('CLIENT_UID', '')

            if client_uid in app.config['dict_of_clients']:
                if len(app.config['dict_of_clients'][client_uid].system_infos) >= 1:
                    return jsonify(app.config['dict_of_clients'][client_uid].system_infos)
                else:
                    # No system infos for this client
                    return "E1001"
            else:
                # Non existent client
                return "E1002"

        elif requested_action == "GET_SYSTEM_STATS":
            ''' =============================================================================================== '''
            # Clients déclarés seulement : une connexion refusée ou en attente reste rangée sous son adresse IP,
            # sans statistiques (la page Supervision cassait sur elle)
            declared = {c.get('UID'): c for c in app.config['config'].get('SERVER_CLIENT', [])}
            dict_of_clients_as_json = {}
            for k, v in app.config['dict_of_clients'].items():
                if k in declared:
                    row = json.loads(v.asjson())
                    row['paused'] = declared[k].get('PAUSED') is True  # sonde en pause : « CONNECTED - PAUSED »
                    dict_of_clients_as_json[k] = json.dumps(row, default=str)
            return dict_of_clients_as_json

        elif requested_action == "GET_NUMBER_OF_ONLINE_CLIENT":
            ''' =============================================================================================== '''
            online_client = 0
            for client in app.config['dict_of_clients'].values():
                if client.status == "CONNECTED":
                    online_client += 1
            return str(online_client)

        elif requested_action == "GET_NUMBER_OF_OFFLINE_CLIENT":
            ''' =============================================================================================== '''
            online_client = 0
            offline_client = len(app.config['config']['SERVER_CLIENT'])

            for client in app.config['dict_of_clients'].values():
                if client.status == "CONNECTED":
                    online_client += 1

            return str(offline_client - online_client)

        elif requested_action == "GET_LIST_OF_DATABASES_INFOS":
            ''' =============================================================================================== '''
            list_of_databases_infos = {}
            for database in app.config['conn_db']:
                database.force_status_check()
                list_of_databases_infos[database.DB_UID] = {"STATUS": database.status, "STATUS_TIME": database.status_time,
                                                      "BACKLOG": len(database.write_queue.queue)}
            return jsonify(list_of_databases_infos)

        return "OK"
    else:
        return "OK"


@st_home_bp.route("/log_viewer.html", methods=["GET"])
def log_viewer():
    return render_template("log_viewer.html")

