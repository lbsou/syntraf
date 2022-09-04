# SYNTRAF GLOBAL IMPORT
from flask_login import *
from . import db
from .st_models import User

from lib.st_global import CompilationOptions, DefaultValues

# SYNTRAF SERVER IMPORT
if not CompilationOptions.client_only:
    from flask import current_app as app
    from lib.st_crypto import *
    from lib.st_read_toml import *

    from flask import Flask, Response, render_template, request, send_from_directory, current_app, safe_join, jsonify, \
        make_response, flash, redirect, session, abort, url_for, g, Blueprint

    from PIL import Image
    # from flask_sqlalchemy import SQLAlchemy

    import uuid  # for public id
    from werkzeug.security import generate_password_hash, check_password_hash
    from functools import wraps

    # BUILTIN IMPORT
    import os
    import time
    import ssl
    import logging
    import sys
    from datetime import datetime as dt

    # PACKAGE IMPORT
    import toml
    import json
    from pprint import pp

log = logging.getLogger("syntraf." + __name__)

# Blueprint Configuration
st_home_bp = Blueprint(
    'st_home_bp', __name__,
    template_folder='templates',
    static_folder='static'
)

@st_home_bp.route('/users.html')
def webui_users():
    return render_template(
        'users.html',
        users=User.query.all(),
        title="SYNTRAF Users",
        syntraf_version=DefaultValues.SYNTRAF_VERSION
    )

@st_home_bp.route('/webui-delete-user', methods=['GET'])
def del_user():
    request.args.get('user')

@st_home_bp.route('/create', methods=['GET'])
def user_records():
    """Create a user via query string parameters."""
    username = request.args.get('user')
    email = request.args.get('email')
    if username and email:
        existing_user = User.query.filter(
            User.username == username or User.email == email
        ).first()
        if existing_user:
            return make_response(
                f'{username} ({email}) already exist!'
            )
        new_user = User(
            username=username,
            email=email,
            created=dt.now(),
            description="It's me, Mario!",
            admin=False,
            last_login=None,
            password="None"
        )  # Create an instance of the User class
        db.session.add(new_user)  # Adds new User record to database
        db.session.commit()  # Commits all changes
        redirect(url_for('st_home_bp.user_records'))
    return render_template(
       'users.html',
       users=User.query.all(),
       title="SYNRTAF Users"
    )


@st_home_bp.errorhandler(404)
def not_found():
    """Page not found."""
    return "404"
    # return make_response(render_template("home.html"), 404)
    # return make_response(404)


@app.errorhandler(400)
def bad_request():
    """Bad request."""
    return make_response(render_template("400.html"), 400)


@app.errorhandler(500)
def server_error():
    """Internal server error."""
    return make_response(render_template("500.html"), 500)


@st_home_bp.route('/')
def index():
    return render_template('login.html')


# def authorize():
#         @wraps(f)
#         def decorated_function(*args, **kwargs):
#             if session['logged_in'] is True:
#                 return redirect(url_for('login', next=request.url))
#             return f(*args, **kwargs)
#         return decorated_function

@st_home_bp.route('/login', methods=['POST'])
def user_login():
    try:
        if request.form['password'] == 'password' and request.form['username'] == 'admin':
            login_user("lbs", remember=True)
        else:
            flash("Invalid username or password")
        return index()
    except Exception as msg:
        log.error(msg)


@st_home_bp.route("/logout")
def logout():
    logout_user()
    return redirect(index)


# @st_home_bp.route('/generated_client_config.html')
# def generated_config():
#     # gen_config = toml.dumps(self._dict_by_node_generated_config)#.replace("\n", "</p><p>")
#     return render_template('generated_client_config.html', title='SYNTRAF WEBUI',
#                            _dict_by_node_generated_config=self._dict_by_node_generated_config,
#                            syntraf_version=DefaultValues.SYNTRAF_VERSION)

# @st_home_bp.route('/proc.html')
# def proc():
#     return render_template('proc.html', title='SYNTRAF WEBUI', thr=self.threads_n_processes,
#                            process=self.subprocess_iperf_dict, syntraf_version=DefaultValues.SYNTRAF_VERSION)

@st_home_bp.route('/token.html')
def token():
    return render_template('token.html', title='SYNTRAF - TOKEN CONFIGURATION',
                           syntraf_version=DefaultValues.SYNTRAF_VERSION)


@st_home_bp.route('/config.html')
def config():
    # config = toml.dumps(self.config).replace("\n", "<br/>")
    return render_template('config.html', title='SYNTRAF WEBUI', config=app.config['config'],
                           syntraf_version=DefaultValues.SYNTRAF_VERSION)


@st_home_bp.route('/queue.html')
def queue():
    return render_template('queue.html', title='SYNTRAF WEBUI',
                           dict_data_to_send_to_server=app.config['dict_data_to_send_to_server'],
                           syntraf_version=DefaultValues.SYNTRAF_VERSION)


@st_home_bp.route('/map.html')
def map():
    return render_template('map.html', title='SYNTRAF WEBUI', config=app.config['config'],
                           syntraf_version=DefaultValues.SYNTRAF_VERSION)


@st_home_bp.route('/database_config.html')
def database_config():
    return render_template('database_config.html', title='SYNTRAF WEBUI', config=app.config['config'],
                           syntraf_version=DefaultValues.SYNTRAF_VERSION)


@st_home_bp.route('/global_config.html')
def global_config():
    return render_template('global_config.html', title='SYNTRAF WEBUI', config=app.config['config'],
                           syntraf_version=DefaultValues.SYNTRAF_VERSION)


@st_home_bp.route('/mesh_group_config.html')
def mesh_group_config():
    return render_template('mesh_group_config.html', title='SYNTRAF WEBUI', config=app.config['config'],
                           syntraf_version=DefaultValues.SYNTRAF_VERSION)


@st_home_bp.route('/client_config.html')
def client_config():
    return render_template('client_config.html', title='SYNTRAF WEBUI', config=app.config['config'])


@st_home_bp.route('/server.html')
def server():
    return render_template('server.html', title='SYNTRAF WEBUI', config=app.config['config'],
                           syntraf_version=DefaultValues.SYNTRAF_VERSION)


@st_home_bp.route('/stats.html')
def stats():
    return render_template('stats.html', title='SYNTRAF WEBUI', config=app.config['config'],
                           _dict_by_node_generated_config=app.config['_dict_by_node_generated_config'],
                           dict_of_clients=app.config['dict_of_clients'])


@st_home_bp.route('/clients_configuration.html')
def clients_configurations():
    return render_template('clients_configuration.html', title='SYNTRAF WEBUI', config=app.config['config'],
                           _dict_by_node_generated_config=app.config['_dict_by_node_generated_config'])


@st_home_bp.route('/api', methods=['GET', 'POST'])
def api():
    if request.method == 'POST':
        requested_action = request.values.get('ACTION', '')
        if requested_action == "SAVE_MAPS_JSON":
            # read json and write JSON with new value
            read_success, config = read_conf(app.config['config_file_path'])
            if read_success:
                for mg in config['MESH_GROUP']:
                    if request.values.get('MESH_GROUP', '') == mg['UID']:
                        config['MESH_GROUP'][config['MESH_GROUP'].index(mg)]['WEBUI_JSON'] = request.values.get(
                            'CYTO_JSON', '')
                        with open(app.config['config_file_path'], "w") as toml_file:
                            # print("writing to disk")
                            # print(config, self.config_file_path)
                            toml.dump(config, toml_file)
                            log.debug(f"RECEIVED A REQUEST TO SAVE MAPS CONFIG OF GROUP '{mg['UID']}' TO DISK")
        elif requested_action == "RECONNECT_CLIENT":

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
            dict_of_clients_as_json = {}
            for k, v in app.config['dict_of_clients'].items():
                dict_of_clients_as_json[k] = v.asjson()
            return dict_of_clients_as_json

        elif requested_action == "GET_TOKENS":
            tokens = app.config['config']['SERVER']['TOKEN']
            print(type(tokens))
            for a, b in tokens.items():
                print(a, "@", b)

            return app.config['config']['SERVER']['TOKEN']

        elif requested_action == "GET_NUMBER_OF_ONLINE_CLIENT":
            online_client = 0
            for client in app.config['dict_of_clients'].values():
                if client.status == "CONNECTED":
                    online_client += 1
            return str(online_client)

        elif requested_action == "GET_NUMBER_OF_OFFLINE_CLIENT":
            online_client = 0
            offline_client = len(app.config['config']['SERVER_CLIENT'])

            for client in app.config['dict_of_clients'].values():
                if client.status == "CONNECTED":
                    online_client += 1

            return str(offline_client - online_client)

        elif requested_action == "GET_LIST_OF_DATABASES_INFOS":
            list_of_databases_infos = {}
            for db in app.config['conn_db']:
                db.force_status_check()
                list_of_databases_infos[db.DB_UID] = {"STATUS": db.status, "STATUS_TIME": db.status_time,
                                                      "BACKLOG": len(db.write_queue.queue)}
            return jsonify(list_of_databases_infos)

        return "OK"
    else:
        return "OK"


def flask_logger(logfile):
    for i in range(10000):
        yield str(i)
        time.sleep(1)
    # yield self.config['GLOBAL']['LOGDIR']


@st_home_bp.route("/log_viewer.html", methods=["GET"])
def log_viewer():
    # return Response(flask_logger(request.args.get("logfile")), mimetype="text/plain", content_type="text/event-stream")
    return render_template("log_viewer.html")


@st_home_bp.route("/maps.html", methods=['GET', 'POST'])
def maps():
    elements = ""
    background = ""
    elements = ""
    background_size = ("", "")
    if request.method == "GET" and request.args.get("mesh_group_map"):
        read_success, config = read_conf(app.config['config_file_path'])
        if read_success:
            mesh_group = [mg for mg in config['MESH_GROUP'] if mg['UID'] == request.args.get("mesh_group_map")]

            if "WEBUI_JSON" in mesh_group[0]:
                elements = mesh_group[0]["WEBUI_JSON"]

            if "WEBUI_BACKGROUND" in mesh_group[0]:
                background = mesh_group[0]["WEBUI_BACKGROUND"]

                # We must get the width and height of the background
                bg_path = os.path.join(DefaultValues.SYNTRAF_ROOT_DIR, "lib", "web_ui/static", "maps",
                                       mesh_group[0]["WEBUI_BACKGROUND"])
                im = Image.open(bg_path)
                background_size = im.size

    return render_template("maps.html", elem=elements, config=app.config['config'],
                           selected_map=request.args.get("mesh_group_map"), background=background,
                           background_size=background_size,
                           dict_of_arrays_generated_tuples_for_map=app.config['dict_of_arrays_generated_tuples_for_map'],
                           syntraf_version=DefaultValues.SYNTRAF_VERSION)


@st_home_bp.after_request
def add_header(r):
    r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, public, max-age=0"
    r.headers["Pragma"] = "no-cache"
    r.headers["Expires"] = "0"
    return r


# # Login with user/pass
# @current_app.login_manager.user_loader
# def load_user(user_id):
#     return User.get(user_id)


# login with API
@current_app.login_manager.request_loader
def request_loader(request):
    email = request.form.get('email')
    if "email" not in "users":
        return

    user = User()
    user.id = email
    return user

@current_app.login_manager.user_loader
def load_user(user_id):
    return User.objects(id=user_id).first()

