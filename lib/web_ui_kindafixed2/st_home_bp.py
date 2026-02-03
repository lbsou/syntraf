# SYNTRAF GLOBAL IMPORT
from lib.st_conf_validation import validate_bandwidth, validate_config_for_webui, generate_client_config_mesh
from lib.st_global import CompilationOptions, DefaultValues
from lib.st_obj_cc_client import cc_client

# SYNTRAF SERVER IMPORT
if not CompilationOptions.client_only:
    from flask import current_app as app
    from lib.st_crypto import *
    from lib.st_read_toml import *

    from flask import Flask, Response, render_template, request, send_from_directory, current_app, safe_join, jsonify, \
        make_response, flash, redirect, session, abort, url_for, g, Blueprint

    from flask_wtf.csrf import CSRFProtect, CSRFError
    from PIL import Image

    # User management module
    from lib.web_ui_kindafixed2 import st_user_management as user_mgmt
    # Import csrf instance for exempting routes
    from lib.web_ui_kindafixed2 import csrf

    # BUILTIN IMPORT
    import os
    import time
    import logging
    import copy
    from datetime import datetime as dt

    # PACKAGE IMPORT
    import toml
    import json

log = logging.getLogger("syntraf." + __name__)


def update_config_in_place(new_config):
    """
    Update the app config dictionary IN-PLACE so that all references
    (including the mesh server's _config) see the changes immediately.
    This enables hot-reload of configuration without restarting SYNTRAF.

    Also regenerates the mesh configuration if SERVER_CLIENT or MESH_GROUP changed.
    """
    original_config = app.config['config']

    # Check if we need to regenerate mesh config
    need_mesh_regeneration = (
        original_config.get('SERVER_CLIENT') != new_config.get('SERVER_CLIENT') or
        original_config.get('MESH_GROUP') != new_config.get('MESH_GROUP')
    )

    # Update the original config dict IN-PLACE
    # This ensures the mesh server's reference sees the changes
    original_config.clear()
    original_config.update(new_config)

    # Regenerate mesh configuration if clients or mesh groups changed
    if need_mesh_regeneration and 'SERVER' in original_config:
        try:
            # Get references to the shared dicts
            _dict_by_node_generated_config = app.config.get('_dict_by_node_generated_config', {})
            _dict_by_group_of_generated_tuple_for_map = app.config.get('_dict_by_group_of_generated_tuple_for_map', {})

            # Clear and regenerate
            _dict_by_node_generated_config.clear()
            _dict_by_group_of_generated_tuple_for_map.clear()

            new_node_config, new_group_tuples = generate_client_config_mesh(original_config, {})
            _dict_by_node_generated_config.update(new_node_config)
            _dict_by_group_of_generated_tuple_for_map.update(new_group_tuples)

            log.info("Mesh configuration regenerated - new clients can now connect without restart")
        except Exception as e:
            log.error(f"Failed to regenerate mesh config: {e}")

    return original_config


def save_tokens_to_config(config_path, tokens_dict):
    """
    Save tokens to the config file safely by reading the original file,
    updating only the TOKEN section, and writing it back.
    This avoids issues with runtime objects in app.config['config'].

    Token format can be either:
    - Old format: {"2018-01-01": "token_string"}
    - New format: {"2018-01-01": {"value": "token_string", "description": "optional desc"}}
    """
    from datetime import date
    import toml

    try:
        # Read the original config file
        with open(config_path, 'r') as f:
            config = toml.load(f)

        # Ensure SERVER.TOKEN section exists
        if 'SERVER' not in config:
            config['SERVER'] = {}

        # Convert date keys to ISO strings for TOML compatibility
        # Handle both old (string) and new (object) token formats
        new_tokens = {}
        for key, value in tokens_dict.items():
            if isinstance(key, date):
                key_str = key.isoformat()
            else:
                key_str = str(key)

            # Value can be either a string (old format) or dict (new format)
            # TOML can serialize both correctly
            new_tokens[key_str] = value

        config['SERVER']['TOKEN'] = new_tokens

        # Write back to file
        with open(config_path, 'w') as f:
            toml.dump(config, f)

        return True, None
    except Exception as e:
        log.error(f"Error in save_tokens_to_config: {e}")
        import traceback
        log.error(traceback.format_exc())
        return False, str(e)


# Blueprint Configuration
st_home_bp = Blueprint(
    'st_home_bp', __name__,
    template_folder='templates',
    static_folder='static'
)


# CSRF error handler
@st_home_bp.errorhandler(CSRFError)
def handle_csrf_error(e):
    """Handle CSRF token errors"""
    log.warning(f"CSRF error: {e.description}")
    flash('Session expired or invalid request. Please try again.')
    return redirect(url_for('st_home_bp.index'))


@st_home_bp.route('/test.html')
def test():
    print(dt.now())
    return render_template('test.html')

@st_home_bp.route('/home.html')
def home():
    if not session.get('logged_in'):
        return redirect(url_for('st_home_bp.index'))
    return render_template(
        'home.html',
        title="SYNTRAF",
        syntraf_version=DefaultValues.SYNTRAF_VERSION,
        conn_db=app.config.get('conn_db', [])
    )

@st_home_bp.route('/users_config.html')
def webui_users():
    if not session.get('logged_in'):
        return redirect(url_for('st_home_bp.index'))
    # Only admins can manage users
    if session.get('user_role') != user_mgmt.ROLE_ADMIN:
        flash('Admin access required to manage users')
        return redirect('/home.html')

    users = user_mgmt.get_all_users()
    password_policy = user_mgmt.get_password_policy()
    return render_template(
        'users_config.html',
        users=users,
        password_policy=password_policy,
        roles=user_mgmt.VALID_ROLES,
        title="SYNTRAF Users",
        syntraf_version=DefaultValues.SYNTRAF_VERSION
    )
#         new_user = User(
#             username=username,
#             email=email,
#             created=dt.now(),
#             description="It's me, Mario!",
#             admin=False,
#             last_login=None,
#             password="None"
#         )  # Create an instance of the User class
#         db.session.add(new_user)  # Adds new User record to database
#         db.session.commit()  # Commits all changes
#         redirect(url_for('st_home_bp.user_records'))
#     return render_template(
#        'users.html',
#        users=User.query.all(),
#        title="SYNRTAF Users"
#     )


# @st_home_bp.errorhandler(404)
# def not_found():
#     """Page not found."""
#     return "404"
#     # return make_response(render_template("home.html"), 404)
#     # return make_response(404)
#
#
# @app.errorhandler(400)
# def bad_request():
#     """Bad request."""
#     return make_response(render_template("400.html"), 400)
#
#
# @app.errorhandler(500)
# def server_error():
#     """Internal server error."""
#     return make_response(render_template("500.html"), 500)


@st_home_bp.route('/')
def index():
    if session.get('logged_in'):
        # Check if user must change password
        if session.get('must_change_password'):
            return redirect(url_for('st_home_bp.change_password_page'))
        return redirect('/home.html')
    return render_template('login.html', syntraf_version=DefaultValues.SYNTRAF_VERSION)


@st_home_bp.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    ip_address = request.remote_addr

    success, result = user_mgmt.authenticate_user(username, password, ip_address)

    if success:
        session['logged_in'] = True
        session['username'] = result['username']
        session['user_id'] = result['id']
        session['user_role'] = result['role']
        session['must_change_password'] = result.get('must_change_password', False)

        if result.get('must_change_password') or result.get('password_expired'):
            if result.get('password_expired'):
                flash('Your password has expired. Please change it now.')
            else:
                flash('You must change your password before continuing.')
            return redirect(url_for('st_home_bp.change_password_page'))

        return redirect('/home.html')
    else:
        flash(result)  # result contains error message
        return redirect(url_for('st_home_bp.index'))


@st_home_bp.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('st_home_bp.index'))


@st_home_bp.route('/change_password.html')
def change_password_page():
    if not session.get('logged_in'):
        return redirect(url_for('st_home_bp.index'))
    return render_template('change_password.html', syntraf_version=DefaultValues.SYNTRAF_VERSION,
                          must_change=session.get('must_change_password', False))


@st_home_bp.route('/change_password', methods=['POST'])
def change_password():
    if not session.get('logged_in'):
        return redirect(url_for('st_home_bp.index'))

    old_password = request.form.get('old_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if new_password != confirm_password:
        flash('New passwords do not match')
        return redirect(url_for('st_home_bp.change_password_page'))

    success, message = user_mgmt.change_password(session['user_id'], old_password, new_password)

    if success:
        session['must_change_password'] = False
        flash('Password changed successfully')
        return redirect('/home.html')
    else:
        flash(message)
        return redirect(url_for('st_home_bp.change_password_page'))


# def authorize():
#         @wraps(f)
#         def decorated_function(*args, **kwargs):
#             if session['logged_in'] is True:
#                 return redirect(url_for('login', next=request.url))
#             return f(*args, **kwargs)
#         return decorated_function

# @st_home_bp.route('/login', methods=['POST'])
# def user_login():
#     try:
#         if request.form['password'] == 'password' and request.form['username'] == 'admin':
#             login_user("lbs", remember=True)
#         else:
#             flash("Invalid username or password")
#         return index()
#     except Exception as msg:
#         log.error(msg)
#
#
# @st_home_bp.route("/logout")
# def logout():
#     logout_user()
#     return redirect(index)


# @st_home_bp.route('/generated_client_config.html')
# def generated_config():
#     # gen_config = toml.dumps(self._dict_by_node_generated_config)#.replace("\n", "</p><p>")
#     return render_template('generated_client_config.html', title='SYNTRAF WEBUI',
#                            _dict_by_node_generated_config=self._dict_by_node_generated_config,
#                            syntraf_version=DefaultValues.SYNTRAF_VERSION)

@st_home_bp.route('/proc.html')
def proc():
    if not session.get('logged_in'):
        return redirect(url_for('st_home_bp.index'))
    return render_template('proc.html', title='SYNTRAF WEBUI',
                           thr=app.config['threads_n_processes'],
                           process=app.config['subprocess_iperf_dict'],
                           syntraf_version=DefaultValues.SYNTRAF_VERSION)


@st_home_bp.route('/token_config.html')
def token_config():
    if not session.get('logged_in'):
        return redirect(url_for('st_home_bp.index'))
    # Only admins can manage tokens
    if session.get('user_role') != user_mgmt.ROLE_ADMIN:
        flash('Admin access required to manage tokens')
        return redirect('/home.html')
    return render_template('token_config.html', syntraf_version=DefaultValues.SYNTRAF_VERSION)


@st_home_bp.route('/config.html')
def config():
    if not session.get('logged_in'):
        return redirect(url_for('st_home_bp.index'))
    # config = toml.dumps(self.config).replace("\n", "<br/>")
    return render_template('config.html', title='SYNTRAF WEBUI', config=app.config['config'],
                           syntraf_version=DefaultValues.SYNTRAF_VERSION)


@st_home_bp.route('/queue.html')
def queue():
    if not session.get('logged_in'):
        return redirect(url_for('st_home_bp.index'))
    return render_template('queue.html', title='SYNTRAF WEBUI',
                           dict_data_to_send_to_server=app.config['dict_data_to_send_to_server'],
                           conn_db=app.config.get('conn_db', []),
                           syntraf_version=DefaultValues.SYNTRAF_VERSION)


@st_home_bp.route('/map.html')
def map():
    if not session.get('logged_in'):
        return redirect(url_for('st_home_bp.index'))
    return render_template('map.html', title='SYNTRAF WEBUI', config=app.config['config'],
                           syntraf_version=DefaultValues.SYNTRAF_VERSION)


@st_home_bp.route('/database_config.html')
def database_config():
    if not session.get('logged_in'):
        return redirect(url_for('st_home_bp.index'))
    # Only admins can modify database config
    if session.get('user_role') != user_mgmt.ROLE_ADMIN:
        flash('Admin access required to manage database configuration')
        return redirect('/home.html')
    return render_template('database_config.html', title='SYNTRAF WEBUI', config=app.config['config'],
                           syntraf_version=DefaultValues.SYNTRAF_VERSION)


@st_home_bp.route('/global_config.html')
def global_config():
    if not session.get('logged_in'):
        return redirect(url_for('st_home_bp.index'))
    # Only admins can modify global config
    if session.get('user_role') != user_mgmt.ROLE_ADMIN:
        flash('Admin access required to manage global configuration')
        return redirect('/home.html')
    return render_template('global_config.html', title='SYNTRAF WEBUI', config=app.config['config'],
                           syntraf_version=DefaultValues.SYNTRAF_VERSION)


@st_home_bp.route('/mesh_group_config.html')
def mesh_group_config():
    if not session.get('logged_in'):
        return redirect(url_for('st_home_bp.index'))
    # Only admins can modify mesh group config
    if session.get('user_role') != user_mgmt.ROLE_ADMIN:
        flash('Admin access required to manage mesh groups')
        return redirect('/home.html')
    return render_template('mesh_group_config.html', title='SYNTRAF WEBUI', config=app.config['config'],
                           syntraf_version=DefaultValues.SYNTRAF_VERSION)


@st_home_bp.route('/client_config.html')
def client_config():
    if not session.get('logged_in'):
        return redirect(url_for('st_home_bp.index'))
    # Only admins can modify client config
    if session.get('user_role') != user_mgmt.ROLE_ADMIN:
        flash('Admin access required to manage client configuration')
        return redirect('/home.html')
    return render_template('client_config.html', title='SYNTRAF WEBUI', config=app.config['config'])


@st_home_bp.route('/server.html')
def server():
    if not session.get('logged_in'):
        return redirect(url_for('st_home_bp.index'))
    # Only admins can modify server config
    if session.get('user_role') != user_mgmt.ROLE_ADMIN:
        flash('Admin access required to manage server configuration')
        return redirect('/home.html')
    return render_template('server.html', title='SYNTRAF WEBUI', config=app.config['config'],
                           syntraf_version=DefaultValues.SYNTRAF_VERSION)



@st_home_bp.route('/stats.html')
def stats():
    if not session.get('logged_in'):
        return redirect(url_for('st_home_bp.index'))
    # Merge configured clients with connected clients
    # This ensures newly added clients appear even before they connect
    merged_clients = dict(app.config['dict_of_clients'])  # Start with connected clients

    # Add configured clients that aren't in dict_of_clients yet
    config = app.config.get('config', {})
    for client_config in config.get('SERVER_CLIENT', []):
        client_uid = client_config.get('UID')
        if client_uid and client_uid not in merged_clients:
            # Create a placeholder cc_client for clients that haven't connected yet
            merged_clients[client_uid] = cc_client(
                status="OFFLINE",
                status_since="N/A",
                status_explanation="Client has not connected yet",
                bool_dynamic_client=(client_config.get('IP_ADDRESS', '0.0.0.0') == '0.0.0.0'),
                client_uid=client_uid,
                ip_address=client_config.get('IP_ADDRESS', '')
            )

    return render_template('stats.html', title='SYNTRAF WEBUI', config=app.config['config'],
                           _dict_by_node_generated_config=app.config['_dict_by_node_generated_config'],
                           dict_of_clients=merged_clients)


@st_home_bp.route('/clients_configuration.html')
def clients_configurations():
    if not session.get('logged_in'):
        return redirect(url_for('st_home_bp.index'))
    return render_template('clients_configuration.html', title='SYNTRAF WEBUI', config=app.config['config'],
                           _dict_by_node_generated_config=app.config['_dict_by_node_generated_config'])


@st_home_bp.route('/api', methods=['GET', 'POST'])
@csrf.exempt  # API uses session auth; AJAX calls include session cookie
def api():
    if request.method == 'POST':
        requested_action = request.values.get('ACTION', '')

        # Define which actions require authentication and which require admin role
        # Read-only actions that readonly users can access
        readonly_actions = [
            'GET_NUMBER_OF_ONLINE_CLIENT', 'GET_NUMBER_OF_OFFLINE_CLIENT',
            'GET_LIST_OF_DATABASES_INFOS', 'GET_CLIENTS', 'GET_CLIENT',
            'GET_MESH_GROUPS', 'GET_THREAD_STATUS', 'GET_MAP', 'GET_TOKENS',
            'GET_LOG_FILES', 'GET_LOG_CONTENT', 'TAIL_LOG', 'DOWNLOAD_LOG',
            'GET_DATABASES', 'GET_SERVER_CONFIG', 'GET_GLOBAL_CONFIG'
        ]

        # Actions that require admin privileges
        admin_actions = [
            'SAVE_MAPS_JSON', 'DELETE_MESH_GROUPS', 'DUPLICATE_MESH_GROUP',
            'EDIT_MESH_GROUP', 'CREATE_MESH_GROUP', 'TOGGLE_DISABLE_MESH_GROUPS',
            'RECONNECT_CLIENT', 'RESTART_CLIENT', 'SAVE_BACKGROUND',
            'ADD_CLIENT', 'EDIT_CLIENT', 'DELETE_CLIENTS', 'TOGGLE_DISABLE_CLIENTS',
            'MOVE_CLIENTS_TO_GROUP', 'CREATE_TOKEN', 'DELETE_TOKEN', 'UPDATE_TOKEN',
            'CREATE_DATABASE', 'EDIT_DATABASE', 'DELETE_DATABASE', 'TOGGLE_DISABLE_DATABASE',
            'SAVE_SERVER_CONFIG', 'SAVE_GLOBAL_CONFIG', 'EXPORT_SERVER_FILE',
            'CREATE_USER', 'UPDATE_USER', 'DELETE_USER', 'RESET_USER_PASSWORD',
            'TOGGLE_USER_ACTIVE'
        ]

        # Check if user is logged in for all API actions
        if not session.get('logged_in'):
            return jsonify({"status": "ERROR", "message": "Authentication required"})

        # Check if admin role is required for this action
        if requested_action in admin_actions:
            if session.get('user_role') != user_mgmt.ROLE_ADMIN:
                return jsonify({"status": "ERROR", "message": "Admin access required for this action"})
        if requested_action == "SAVE_MAPS_JSON":
            ''' =============================================================================================== '''
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

        elif requested_action == "DELETE_MESH_GROUPS":
            ''' =============================================================================================== '''
            mesh_group_uids_list = request.values.get('MESH_GROUP_UIDS', '').split(",")
            read_success, config = read_conf(app.config['config_file_path'])
            results_delete_list = []

            try:
                if read_success:
                    for mg_uid in mesh_group_uids_list:
                        # Does this group have members?
                        cpt_members = 0
                        for client in config['SERVER_CLIENT']:
                            if mg_uid in client['MESH_GROUP_UID_LIST']:
                                cpt_members += 1

                        if cpt_members >= 1:
                            # Cannot delete, this mesh group is in use.
                            results_delete_list.append({"ID": mg_uid, "MSG": "not deleted (in use)"})
                        else:
                            # Delete the group from config (live and disk)
                            for mesh_group in config['MESH_GROUP']:
                                if mesh_group['UID'] == mg_uid:
                                    app.config['config']['MESH_GROUP'].remove(mesh_group)
                                    config['MESH_GROUP'].remove(mesh_group)
                                    results_delete_list.append({"ID": mg_uid, "MSG": "deleted"})
                else:
                    # Unable to open config file
                    log.debug(f"UNABLE TO READ CONFIG FILE WHILE TRYING TO DELETE MESH_GROUP '{mesh_group_uids_list}'")
                    results_delete_list.append({"ID": "FATAL_ERROR", "MSG": f"UNABLE TO READ CONFIG FILE WHILE TRYING TO DELETE MESH_GROUP '{mesh_group_uids_list}'"})
                    return jsonify(results_delete_list)
            except Exception as exc:
                log.debug(exc)
                results_delete_list.append({"ID": "FATAL_ERROR", "MSG": exc})
                return jsonify(results_delete_list)

            try:
                with open(app.config['config_file_path'], "w") as toml_file:
                    toml.dump(config, toml_file)
                    log.debug(f"CONFIG FILE SUCCESSFULLY OVERWRITTEN")
            except Exception as exc:
                results_delete_list.append({"ID": "FATAL_ERROR", "MSG": f"AN ERROR OCCURRED WHILE TRYING TO SAVE CONFIG FILE"})
                log.debug(f"AN ERROR OCCURRED WHILE TRYING TO SAVE CONFIG FILE", exc)
                return jsonify(results_delete_list)

            try:
                for msg in results_delete_list:
                    if "FATAL_ERROR" == msg['ID']:
                        log.debug(f"MESH_GROUP {msg['ID']} : {msg['MSG']}")
            except Exception as exc:
                results_delete_list.append({"ID": "FATAL_ERROR", "MSG": f"AN ERROR OCCURRED WHILE"})
                log.debug(f"AN ERROR OCCURRED WHILE ", exc)
                return jsonify(results_delete_list)

            return jsonify(results_delete_list)

        elif requested_action == "GET_MESH_GROUPS":
            ''' =============================================================================================== '''
            read_success, config = read_conf(app.config['config_file_path'])
            if read_success:
                # deepcopy for eventually add packet per seconds
                mesh_groups = copy.deepcopy(config['MESH_GROUP'])

                for mg in mesh_groups:
                    mg['MEMBERS'] = 0
                    for client in config['SERVER_CLIENT']:
                        if mg['UID'] in client['MESH_GROUP_UID_LIST']:
                            if mg['MEMBERS'] >= 1:
                                mg['MEMBERS'] += 1
                            else:
                                mg['MEMBERS'] = 1

                for mg in mesh_groups:
                    if mg['MEMBERS'] >= 1:
                        bw_mg = validate_bandwidth(mg['BANDWIDTH'])
                        bw_total = mg['MEMBERS'] * (mg['MEMBERS']-1) * bw_mg
                        bw_per_node = bw_total / mg['MEMBERS']
                        bw_per_node_kbps = bw_per_node / 1000
                        mg['BW_PER_NODE_KBPS'] = bw_per_node_kbps
                    else:
                        mg['BW_PER_NODE_KBPS'] = 0


                return jsonify(mesh_groups)
            else:
                log.debug(f"UNABLE TO READ CONFIG FILE WHILE TRYING TO GET MESH GROUPS")
                # Unable to open config file
                return "E1004"

        elif requested_action == "DUPLICATE_MESH_GROUP":
            ''' =============================================================================================== '''
            mesh_group_uid = request.values.get('MESH_GROUP_UID', '')
            read_success, config = read_conf(app.config['config_file_path'])
            result = []

            try:
                if read_success:
                    for mg in config['MESH_GROUP']:

                        if mg['UID'] == mesh_group_uid:
                            # Copy mesh group
                            mg_clone = copy.deepcopy(mg)

                            # We have to make sure that the new name is unique
                            no_valid_name = True
                            suffix = "_COPY"
                            suffix2 = 0
                            try:
                                while no_valid_name:
                                    found = False
                                    for mg2 in config['MESH_GROUP']:
                                        if suffix2 != 0:
                                            if mg2['UID'] == mg['UID'] + suffix + str(suffix2):
                                                found = True
                                                suffix2 += 1
                                                break
                                        else:
                                            if mg2['UID'] == mg['UID'] + suffix or mg2['UID'] == mg['UID'] + suffix + str(suffix2):
                                                found = True
                                                suffix2 += 1
                                                break
                                    if not found:
                                        no_valid_name = False
                            except Exception as exc:
                                log.error(exc)

                            if suffix2 >= 1:
                                mg_clone['UID'] = mg['UID'] + suffix + str(suffix2)
                            else:
                                mg_clone['UID'] = mg['UID'] + suffix

                            # Put it in config file (live and disk)
                            app.config['config']['MESH_GROUP'].append(mg_clone)
                            config['MESH_GROUP'].append(mg_clone)
                            result.append({"ID": mesh_group_uid, "MSG": "cloned"})

                else:
                    # Unable to open config file
                    log.debug(f"UNABLE TO READ CONFIG FILE WHILE TRYING TO CLONE MESH_GROUP '{mesh_group_uid}'")
                    result.append({"ID": "FATAL_ERROR", "MSG": f"UNABLE TO READ CONFIG FILE WHILE TRYING TO CLONE MESH_GROUP '{mesh_group_uid}'"})
                    return jsonify(result)
            except Exception as exc:
                log.debug(exc)
                result.append({"ID": "FATAL_ERROR", "MSG": exc})
                return jsonify(result)

            try:
                with open(app.config['config_file_path'], "w") as toml_file:
                    toml.dump(config, toml_file)
                    log.debug(f"CONFIG FILE SUCCESSFULLY OVERWRITTEN")
            except Exception as exc:
                result.append({"ID": "FATAL_ERROR", "MSG": f"AN ERROR OCCURRED WHILE TRYING TO SAVE CONFIG FILE"})
                log.debug(f"AN ERROR OCCURRED WHILE TRYING TO SAVE CONFIG FILE", exc)
                return jsonify(result)

            return jsonify(result)

        elif requested_action == "EDIT_MESH_GROUP":
            ''' =============================================================================================== '''
            mesh_group_uid = request.values.get('MESH_GROUP_UID', '')
            new_bandwidth = request.values.get('BANDWIDTH', '')
            new_dscp = request.values.get('DSCP', '')
            new_packet_size = request.values.get('PACKET_SIZE', '')
            new_interval = request.values.get('INTERVAL', '')
            new_description = request.values.get('DESCRIPTION', '')
            new_disabled = request.values.get('DISABLED', None)

            read_success, config = read_conf(app.config['config_file_path'])
            result = {"status": "ERROR", "message": "Mesh group not found"}

            try:
                if read_success:
                    for mg in config['MESH_GROUP']:
                        if mg['UID'] == mesh_group_uid:
                            # Update fields
                            if new_bandwidth:
                                mg['BANDWIDTH'] = new_bandwidth
                            if new_dscp:
                                mg['DSCP'] = new_dscp
                            if new_packet_size:
                                mg['PACKET_SIZE'] = new_packet_size
                            if new_interval:
                                mg['INTERVAL'] = new_interval
                            if new_description is not None:
                                mg['DESCRIPTION'] = new_description
                            if new_disabled is not None:
                                mg['DISABLED'] = (new_disabled.lower() == 'true')

                            # Validate configuration before saving
                            validation_result = validate_config_for_webui(config)
                            if not validation_result['valid']:
                                return jsonify({
                                    "status": "VALIDATION_ERROR",
                                    "message": "Configuration validation failed",
                                    "errors": validation_result['errors'],
                                    "warnings": validation_result['warnings']
                                })

                            # Save to file
                            with open(app.config['config_file_path'], "w") as toml_file:
                                toml.dump(config, toml_file)

                            # Update in-memory config
                            update_config_in_place(config)

                            log.info(f"Mesh group '{mesh_group_uid}' updated")
                            result = {"status": "OK", "message": f"Mesh group '{mesh_group_uid}' updated successfully"}
                            if validation_result['warnings']:
                                result['warnings'] = validation_result['warnings']
                            break
                else:
                    result = {"status": "ERROR", "message": "Unable to read config file"}
            except Exception as e:
                log.error(f"Error editing mesh group: {e}")
                result = {"status": "ERROR", "message": str(e)}

            return jsonify(result)

        elif requested_action == "CREATE_MESH_GROUP":
            ''' =============================================================================================== '''
            new_uid = request.values.get('UID', '').strip()
            new_bandwidth = request.values.get('BANDWIDTH', '')
            new_dscp = request.values.get('DSCP', '')
            new_packet_size = request.values.get('PACKET_SIZE', '')
            new_interval = request.values.get('INTERVAL', '')
            new_description = request.values.get('DESCRIPTION', '')

            if not new_uid:
                return jsonify({"status": "ERROR", "message": "UID is required"})

            read_success, config = read_conf(app.config['config_file_path'])
            result = {"status": "ERROR", "message": "Unable to create mesh group"}

            try:
                if read_success:
                    # Check if UID already exists
                    for mg in config['MESH_GROUP']:
                        if mg['UID'] == new_uid:
                            return jsonify({"status": "ERROR", "message": f"Mesh group '{new_uid}' already exists"})

                    # Create new mesh group
                    new_mesh_group = {
                        'UID': new_uid,
                        'BANDWIDTH': new_bandwidth or '100K',
                        'DSCP': new_dscp or '0',
                        'PACKET_SIZE': new_packet_size or '218',
                        'INTERVAL': new_interval or '1'
                    }
                    if new_description:
                        new_mesh_group['DESCRIPTION'] = new_description

                    config['MESH_GROUP'].append(new_mesh_group)

                    # Validate configuration before saving
                    validation_result = validate_config_for_webui(config)
                    if not validation_result['valid']:
                        return jsonify({
                            "status": "VALIDATION_ERROR",
                            "message": "Configuration validation failed",
                            "errors": validation_result['errors'],
                            "warnings": validation_result['warnings']
                        })

                    # Save to file
                    with open(app.config['config_file_path'], "w") as toml_file:
                        toml.dump(config, toml_file)

                    # Update in-memory config
                    update_config_in_place(config)

                    log.info(f"Mesh group '{new_uid}' created")
                    result = {"status": "OK", "message": f"Mesh group '{new_uid}' created successfully"}
                    if validation_result['warnings']:
                        result['warnings'] = validation_result['warnings']
                else:
                    result = {"status": "ERROR", "message": "Unable to read config file"}
            except Exception as e:
                log.error(f"Error creating mesh group: {e}")
                result = {"status": "ERROR", "message": str(e)}

            return jsonify(result)

        elif requested_action == "TOGGLE_DISABLE_MESH_GROUPS":
            ''' =============================================================================================== '''
            mesh_group_uids_list = request.values.get('MESH_GROUP_UIDS', '').split(",")
            read_success, config = read_conf(app.config['config_file_path'])
            results = []

            try:
                if read_success:
                    for mg in config['MESH_GROUP']:
                        if mg['UID'] in mesh_group_uids_list:
                            # Toggle DISABLED status
                            current_status = mg.get('DISABLED', False)
                            mg['DISABLED'] = not current_status
                            new_status = "disabled" if mg['DISABLED'] else "enabled"
                            results.append(f"{mg['UID']}: {new_status}")

                    # Save to file
                    with open(app.config['config_file_path'], "w") as toml_file:
                        toml.dump(config, toml_file)

                    # Update in-memory config
                    update_config_in_place(config)

                    log.info(f"Mesh groups toggled: {', '.join(results)}")
                    return jsonify({"status": "OK", "message": "Status updated: " + ", ".join(results)})
                else:
                    return jsonify({"status": "ERROR", "message": "Unable to read config file"})
            except Exception as e:
                log.error(f"Error toggling mesh groups: {e}")
                return jsonify({"status": "ERROR", "message": str(e)})

        elif requested_action == "RECONNECT_CLIENT":
            ''' =============================================================================================== '''

            client_uid = request.values.get('CLIENT', '')
            log.debug(f"RECONNECT ASKED FOR CLIENT: '{client_uid}'")

            # Check if client exists and is connected (handles both "CONNECTED" and "CONNECTED (PASSIVE)")
            client_status = getattr(app.config['dict_of_clients'].get(client_uid), 'status', None)
            if client_status and client_status.startswith("CONNECTED"):
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

            # Check if client exists and is connected (handles both "CONNECTED" and "CONNECTED (PASSIVE)")
            client_status = getattr(app.config['dict_of_clients'].get(client_uid), 'status', None)
            if client_status and client_status.startswith("CONNECTED"):
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
            ''' =============================================================================================== '''
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
            ''' =============================================================================================== '''
            client_uid = request.values.get('CLIENT_UID', '')

            if client_uid in app.config['dict_of_clients']:
                thread_status = app.config['dict_of_clients'][client_uid].thread_status
                if thread_status and len(thread_status) >= 1:
                    return jsonify(thread_status)
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
            # Merge configured clients with connected clients
            dict_of_clients_as_json = {}

            # First add all connected clients
            for k, v in app.config['dict_of_clients'].items():
                dict_of_clients_as_json[k] = v.asjson()

            # Add configured clients that aren't connected yet
            config = app.config.get('config', {})
            for client_config in config.get('SERVER_CLIENT', []):
                client_uid = client_config.get('UID')
                if client_uid and client_uid not in dict_of_clients_as_json:
                    # Create a placeholder for clients that haven't connected
                    placeholder = cc_client(
                        status="OFFLINE",
                        status_since="N/A",
                        status_explanation="Client has not connected yet",
                        bool_dynamic_client=(client_config.get('IP_ADDRESS', '0.0.0.0') == '0.0.0.0'),
                        client_uid=client_uid,
                        ip_address=client_config.get('IP_ADDRESS', '')
                    )
                    dict_of_clients_as_json[client_uid] = placeholder.asjson()

            return dict_of_clients_as_json

        elif requested_action == "GET_TOKENS":
            ''' =============================================================================================== '''
            try:
                # Check if SERVER section exists
                if 'SERVER' not in app.config['config']:
                    log.warning("GET_TOKENS: SERVER section not in config")
                    return jsonify({})
                # Check if TOKEN subsection exists
                if 'TOKEN' not in app.config['config']['SERVER']:
                    log.warning("GET_TOKENS: TOKEN not in SERVER config")
                    log.warning(f"GET_TOKENS: SERVER keys: {list(app.config['config']['SERVER'].keys())}")
                    return jsonify({})
                tokens = app.config['config']['SERVER']['TOKEN']
                log.warning(f"GET_TOKENS: Found {len(tokens)} tokens")
                # Convert datetime keys to strings for JSON serialization
                tokens_str = {}
                for key, value in tokens.items():
                    if hasattr(key, 'isoformat'):
                        tokens_str[key.isoformat()] = value
                    else:
                        tokens_str[str(key)] = value
                log.warning(f"GET_TOKENS: Returning: {tokens_str}")
                return jsonify(tokens_str)
            except Exception as e:
                log.error(f"GET_TOKENS error: {e}")
                import traceback
                log.error(traceback.format_exc())
                return jsonify({})

        elif requested_action == "ADD_TOKEN":
            ''' =============================================================================================== '''
            token_date = request.form.get('TOKEN_DATE')
            token_value = request.form.get('TOKEN_VALUE')
            token_description = request.form.get('TOKEN_DESCRIPTION', '')
            log.info(f"ADD_TOKEN request: date={token_date}, value={token_value}, description={token_description}")
            if token_date and token_value:
                # Use date + time as unique key to allow multiple tokens per day
                from datetime import datetime
                # Create unique key: date + current time (to seconds)
                now = datetime.now()
                unique_key = f"{token_date}T{now.strftime('%H:%M:%S')}"
                # Store as object with value and description
                token_data = {"value": token_value, "description": token_description}
                # Update in-memory config
                app.config['config']['SERVER']['TOKEN'][unique_key] = token_data
                log.info(f"Token added to memory: {unique_key} = {token_data}")
                # Save to config file using the safe method
                config_path = app.config.get('config_file_path')
                log.info(f"Config file path: {config_path}")
                if not config_path:
                    return jsonify({"status": "ERROR", "message": "Config file path not set"})
                success, error = save_tokens_to_config(config_path, app.config['config']['SERVER']['TOKEN'])
                if success:
                    log.info(f"Config saved to {config_path}")
                    return jsonify({"status": "OK", "message": "Token added"})
                else:
                    return jsonify({"status": "ERROR", "message": error})
            return jsonify({"status": "ERROR", "message": "Missing token date or value"})

        elif requested_action == "DELETE_TOKEN":
            ''' =============================================================================================== '''
            token_date_str = request.form.get('TOKEN_DATE')
            # Find the matching key (could be datetime.date or string)
            from datetime import date
            token_key = None
            for key in app.config['config']['SERVER']['TOKEN'].keys():
                key_str = key.isoformat() if hasattr(key, 'isoformat') else str(key)
                if key_str == token_date_str:
                    token_key = key
                    break
            if token_key is not None:
                del app.config['config']['SERVER']['TOKEN'][token_key]
                # Save to config file using the safe method
                config_path = app.config.get('config_file_path')
                if not config_path:
                    return jsonify({"status": "ERROR", "message": "Config file path not set"})
                success, error = save_tokens_to_config(config_path, app.config['config']['SERVER']['TOKEN'])
                if success:
                    return jsonify({"status": "OK", "message": "Token deleted"})
                else:
                    return jsonify({"status": "ERROR", "message": error})
            return jsonify({"status": "ERROR", "message": "Token not found"})

        elif requested_action == "GET_NUMBER_OF_ONLINE_CLIENT":
            ''' =============================================================================================== '''
            online_client = 0
            for client in app.config['dict_of_clients'].values():
                # Include both "CONNECTED" and "CONNECTED (PASSIVE)" clients
                if client.status and client.status.startswith("CONNECTED"):
                    online_client += 1
            return str(online_client)

        elif requested_action == "GET_NUMBER_OF_OFFLINE_CLIENT":
            ''' =============================================================================================== '''
            online_client = 0
            offline_client = len(app.config['config']['SERVER_CLIENT'])

            for client in app.config['dict_of_clients'].values():
                # Include both "CONNECTED" and "CONNECTED (PASSIVE)" clients
                if client.status and client.status.startswith("CONNECTED"):
                    online_client += 1

            return str(offline_client - online_client)

        elif requested_action == "GET_LIST_OF_DATABASES_INFOS":
            ''' =============================================================================================== '''
            list_of_databases_infos = {}
            for database in app.config['conn_db']:
                if not getattr(database, 'disabled', False):
                    database.force_status_check()
                list_of_databases_infos[database.DB_UID] = {
                    "STATUS": database.status,
                    "STATUS_TIME": database.status_time,
                    "BACKLOG": len(database.write_queue.queue),
                    "DISABLED": getattr(database, 'disabled', False)
                }
            return jsonify(list_of_databases_infos)

        # ======================= DATABASE MANAGEMENT API =======================

        elif requested_action == "GET_DATABASES":
            ''' Get all database configurations with cached status (fast) '''
            read_success, config = read_conf(app.config['config_file_path'])
            if not read_success:
                return jsonify({"status": "ERROR", "message": "Unable to read config file"})

            databases = []
            config_databases = config.get('DATABASE', [])

            # Get cached status from conn_db objects (no blocking connection test)
            live_status = {}
            for db_obj in app.config.get('conn_db', []):
                try:
                    # Use cached status instead of force_status_check() for speed
                    # Accept both 'OK' and 'ONLINE' as successful statuses
                    db_status = getattr(db_obj, 'status', None)
                    live_status[db_obj.DB_UID] = {
                        'CONNECTION_STATUS': 'OK' if db_status in ('OK', 'ONLINE') else ('ERROR' if db_status else 'UNKNOWN'),
                        'CONNECTION_ERROR': getattr(db_obj, 'status_message', ''),
                        'BACKLOG': len(db_obj.write_queue.queue) if hasattr(db_obj, 'write_queue') else 0
                    }
                except Exception as e:
                    live_status[db_obj.DB_UID] = {
                        'CONNECTION_STATUS': 'ERROR',
                        'CONNECTION_ERROR': str(e),
                        'BACKLOG': 0
                    }

            for db in config_databases:
                db_info = dict(db)
                db_uid = db.get('DB_UID', '')
                if db_uid in live_status:
                    db_info.update(live_status[db_uid])
                else:
                    db_info['CONNECTION_STATUS'] = 'UNKNOWN'
                    db_info['BACKLOG'] = 0
                databases.append(db_info)

            return jsonify(databases)

        elif requested_action == "CREATE_DATABASE":
            ''' Create a new database configuration '''
            db_uid = request.values.get('DB_UID', '').strip()
            if not db_uid:
                return jsonify({"status": "ERROR", "message": "Database UID is required"})

            read_success, config = read_conf(app.config['config_file_path'])
            if not read_success:
                return jsonify({"status": "ERROR", "message": "Unable to read config file"})

            # Check if UID already exists
            for db in config.get('DATABASE', []):
                if db.get('DB_UID') == db_uid:
                    return jsonify({"status": "ERROR", "message": f"Database '{db_uid}' already exists"})

            # Create new database entry
            new_database = {
                'DB_UID': db_uid,
                'DB_ENGINE': request.values.get('DB_ENGINE', 'InfluxDB2'),
                'DB_SERVER': request.values.get('DB_SERVER', ''),
                'DB_PORT': request.values.get('DB_PORT', '8086'),
                'DB_ORG': request.values.get('DB_ORG', ''),
                'DB_BUCKET': request.values.get('DB_BUCKET', ''),
                'DB_TOKEN': request.values.get('DB_TOKEN', ''),
                'DB_SERVER_USE_SSL': request.values.get('DB_SERVER_USE_SSL', 'false').lower() == 'true'
            }

            if 'DATABASE' not in config:
                config['DATABASE'] = []
            config['DATABASE'].append(new_database)

            try:
                with open(app.config['config_file_path'], "w") as toml_file:
                    toml.dump(config, toml_file)
                update_config_in_place(config)
                log.info(f"Database '{db_uid}' created")
                return jsonify({"status": "OK", "message": f"Database '{db_uid}' created successfully. Restart SYNTRAF to apply changes."})
            except Exception as e:
                log.error(f"Error creating database: {e}")
                return jsonify({"status": "ERROR", "message": str(e)})

        elif requested_action == "EDIT_DATABASE":
            ''' Edit an existing database configuration '''
            db_uid = request.values.get('DB_UID', '').strip()
            if not db_uid:
                return jsonify({"status": "ERROR", "message": "Database UID is required"})

            read_success, config = read_conf(app.config['config_file_path'])
            if not read_success:
                return jsonify({"status": "ERROR", "message": "Unable to read config file"})

            # Find and update the database
            found = False
            for db in config.get('DATABASE', []):
                if db.get('DB_UID') == db_uid:
                    found = True
                    db['DB_ENGINE'] = request.values.get('DB_ENGINE', db.get('DB_ENGINE', 'InfluxDB2'))
                    db['DB_SERVER'] = request.values.get('DB_SERVER', db.get('DB_SERVER', ''))
                    db['DB_PORT'] = request.values.get('DB_PORT', db.get('DB_PORT', '8086'))
                    db['DB_ORG'] = request.values.get('DB_ORG', db.get('DB_ORG', ''))
                    db['DB_BUCKET'] = request.values.get('DB_BUCKET', db.get('DB_BUCKET', ''))

                    # Only update token if provided (non-empty)
                    new_token = request.values.get('DB_TOKEN', '')
                    if new_token:
                        db['DB_TOKEN'] = new_token

                    db['DB_SERVER_USE_SSL'] = request.values.get('DB_SERVER_USE_SSL', 'false').lower() == 'true'

                    # Handle disabled flag
                    disabled = request.values.get('DISABLED', None)
                    if disabled is not None:
                        db['DISABLED'] = disabled.lower() == 'true'
                    break

            if not found:
                return jsonify({"status": "ERROR", "message": f"Database '{db_uid}' not found"})

            try:
                with open(app.config['config_file_path'], "w") as toml_file:
                    toml.dump(config, toml_file)
                update_config_in_place(config)
                log.info(f"Database '{db_uid}' updated")
                return jsonify({"status": "OK", "message": f"Database '{db_uid}' updated successfully. Restart SYNTRAF to apply changes."})
            except Exception as e:
                log.error(f"Error updating database: {e}")
                return jsonify({"status": "ERROR", "message": str(e)})

        elif requested_action == "DELETE_DATABASES":
            ''' Delete one or more database configurations '''
            db_uids_str = request.values.get('DB_UIDS', '')
            if not db_uids_str:
                return jsonify({"status": "ERROR", "message": "No databases specified"})

            db_uids = [uid.strip() for uid in db_uids_str.split(',')]

            read_success, config = read_conf(app.config['config_file_path'])
            if not read_success:
                return jsonify({"status": "ERROR", "message": "Unable to read config file"})

            # Remove matching databases
            original_count = len(config.get('DATABASE', []))
            config['DATABASE'] = [db for db in config.get('DATABASE', []) if db.get('DB_UID') not in db_uids]
            deleted_count = original_count - len(config.get('DATABASE', []))

            if deleted_count == 0:
                return jsonify({"status": "ERROR", "message": "No matching databases found"})

            try:
                with open(app.config['config_file_path'], "w") as toml_file:
                    toml.dump(config, toml_file)
                update_config_in_place(config)
                log.info(f"Deleted {deleted_count} database(s): {db_uids}")
                return jsonify({"status": "OK", "message": f"Deleted {deleted_count} database(s). Restart SYNTRAF to apply changes."})
            except Exception as e:
                log.error(f"Error deleting databases: {e}")
                return jsonify({"status": "ERROR", "message": str(e)})

        elif requested_action == "TEST_DATABASE_CONNECTION":
            ''' Test database connection with provided parameters '''
            db_engine = request.values.get('DB_ENGINE', 'InfluxDB2').upper()
            db_server = request.values.get('DB_SERVER', '').strip()
            db_port = request.values.get('DB_PORT', '8086')
            db_org = request.values.get('DB_ORG', '').strip()
            db_bucket = request.values.get('DB_BUCKET', '').strip()
            db_token = request.values.get('DB_TOKEN', '')
            use_ssl = request.values.get('DB_SERVER_USE_SSL', 'false').lower() == 'true'

            protocol = 'https' if use_ssl else 'http'
            url = f"{protocol}://{db_server}:{db_port}"

            if db_engine == "VICTORIAMETRICS":
                # VictoriaMetrics: only server and port required
                if not all([db_server, db_port]):
                    return jsonify({"status": "ERROR", "message": "Missing required parameters (server, port)"})

                try:
                    import requests
                    headers = {'Content-Type': 'text/plain'}
                    if db_token:
                        headers['Authorization'] = f'Bearer {db_token}'
                    response = requests.get(f"{url}/health", headers=headers, timeout=10)
                    if response.status_code == 200:
                        return jsonify({"status": "OK", "message": "Connection successful"})
                    else:
                        return jsonify({"status": "ERROR", "message": f"Health check failed: HTTP {response.status_code}"})
                except Exception as e:
                    log.error(f"VictoriaMetrics connection test failed: {e}")
                    return jsonify({"status": "ERROR", "message": str(e)})
            else:
                # InfluxDB 2.x or 3.x
                from influxdb_client import InfluxDBClient

                if not all([db_server, db_port, db_org, db_token]):
                    return jsonify({"status": "ERROR", "message": "Missing required parameters"})

                try:
                    client = InfluxDBClient(url=url, token=db_token, org=db_org, timeout=10000)
                    # Test connection by checking health
                    health = client.health()
                    client.close()

                    if health.status == "pass":
                        return jsonify({"status": "OK", "message": "Connection successful"})
                    else:
                        return jsonify({"status": "ERROR", "message": f"Health check failed: {health.message}"})
                except Exception as e:
                    log.error(f"Database connection test failed: {e}")
                    return jsonify({"status": "ERROR", "message": str(e)})

        elif requested_action == "TEST_DATABASE_CONNECTION_BY_UID":
            ''' Test connection to a configured database by UID '''
            db_uid = request.values.get('DB_UID', '').strip()
            if not db_uid:
                return jsonify({"status": "ERROR", "message": "Database UID is required"})

            # Find the database in conn_db
            for db_obj in app.config.get('conn_db', []):
                if db_obj.DB_UID == db_uid:
                    try:
                        db_obj.force_status_check()
                        # Accept both 'OK' and 'ONLINE' as successful statuses
                        if db_obj.status in ('OK', 'ONLINE'):
                            return jsonify({"status": "OK", "message": "Connection successful"})
                        else:
                            return jsonify({"status": "ERROR", "message": getattr(db_obj, 'status_message', 'Connection failed')})
                    except Exception as e:
                        return jsonify({"status": "ERROR", "message": str(e)})

            return jsonify({"status": "ERROR", "message": f"Database '{db_uid}' not found in active connections"})

        # ======================= CLIENT MANAGEMENT API =======================

        elif requested_action == "GET_CLIENTS":
            ''' Get all client configurations with live connection status '''
            read_success, config = read_conf(app.config['config_file_path'])
            if not read_success:
                return jsonify({"status": "ERROR", "message": "Unable to read config file"})

            clients = []
            config_clients = config.get('SERVER_CLIENT', [])

            # Get live connection status from dict_of_clients
            connected_clients = {}
            for client_uid, client_obj in app.config.get('dict_of_clients', {}).items():
                try:
                    status = getattr(client_obj, 'status', None) or ''
                    live_ip = getattr(client_obj, 'ip_address', None) or ''
                    # Include both "CONNECTED" and "CONNECTED (PASSIVE)" clients
                    if status.startswith('CONNECTED'):
                        connected_clients[client_uid] = {
                            'CONNECTION_STATUS': 'CONNECTED',
                            'LIVE_IP_ADDRESS': live_ip
                        }
                    else:
                        connected_clients[client_uid] = {'CONNECTION_STATUS': 'OFFLINE'}
                except Exception:
                    connected_clients[client_uid] = {'CONNECTION_STATUS': 'OFFLINE'}

            for client in config_clients:
                client_info = dict(client)
                client_uid = client.get('UID', '')
                if client_uid in connected_clients:
                    client_info.update(connected_clients[client_uid])
                else:
                    client_info['CONNECTION_STATUS'] = 'OFFLINE'
                clients.append(client_info)

            return jsonify(clients)

        elif requested_action == "CREATE_CLIENT":
            ''' Create a new client configuration '''
            client_uid = request.values.get('CLIENT_UID', '').strip()
            if not client_uid:
                return jsonify({"status": "ERROR", "message": "Client UID is required"})

            read_success, config = read_conf(app.config['config_file_path'])
            if not read_success:
                return jsonify({"status": "ERROR", "message": "Unable to read config file"})

            # Check if UID already exists
            for client in config.get('SERVER_CLIENT', []):
                if client.get('UID') == client_uid:
                    return jsonify({"status": "ERROR", "message": f"Client '{client_uid}' already exists"})

            # Parse mesh group list
            mesh_groups = []
            mesh_groups_str = request.values.get('MESH_GROUP_UID_LIST', '[]')
            try:
                mesh_groups = json.loads(mesh_groups_str)
            except:
                mesh_groups = []

            # Create new client entry
            new_client = {
                'UID': client_uid,
                'IP_ADDRESS': request.values.get('IP_ADDRESS', '0.0.0.0'),
                'MESH_GROUP_UID_LIST': mesh_groups
            }

            # Optional fields
            max_bw = request.values.get('MAX_BANDWIDTH', '').strip()
            if max_bw:
                new_client['MAX_BANDWIDTH'] = max_bw

            # Parse override IPs
            override_ips_str = request.values.get('OVERRIDE_DST_NODE_IP', '{}')
            try:
                override_ips = json.loads(override_ips_str)
                if override_ips:
                    new_client['OVERRIDE_DST_NODE_IP'] = override_ips
            except:
                pass

            # Parse exclusions
            exclusions_str = request.values.get('EXCLUDED_CLIENT_DICT', '{}')
            try:
                exclusions = json.loads(exclusions_str)
                if exclusions:
                    new_client['EXCLUDED_CLIENT_DICT'] = exclusions
            except:
                pass

            if 'SERVER_CLIENT' not in config:
                config['SERVER_CLIENT'] = []
            config['SERVER_CLIENT'].append(new_client)

            try:
                # Validate configuration before saving
                validation_result = validate_config_for_webui(config)
                if not validation_result['valid']:
                    return jsonify({
                        "status": "VALIDATION_ERROR",
                        "message": "Configuration validation failed",
                        "errors": validation_result['errors'],
                        "warnings": validation_result['warnings']
                    })

                with open(app.config['config_file_path'], "w") as toml_file:
                    toml.dump(config, toml_file)
                update_config_in_place(config)
                log.info(f"Client '{client_uid}' created")
                result = {"status": "OK", "message": f"Client '{client_uid}' created successfully. New clients can connect immediately."}
                if validation_result['warnings']:
                    result['warnings'] = validation_result['warnings']
                return jsonify(result)
            except Exception as e:
                log.error(f"Error creating client: {e}")
                return jsonify({"status": "ERROR", "message": str(e)})

        elif requested_action == "EDIT_CLIENT":
            ''' Edit an existing client configuration '''
            client_uid = request.values.get('CLIENT_UID', '').strip()
            if not client_uid:
                return jsonify({"status": "ERROR", "message": "Client UID is required"})

            read_success, config = read_conf(app.config['config_file_path'])
            if not read_success:
                return jsonify({"status": "ERROR", "message": "Unable to read config file"})

            # Find and update the client
            found = False
            for client in config.get('SERVER_CLIENT', []):
                if client.get('UID') == client_uid:
                    found = True
                    client['IP_ADDRESS'] = request.values.get('IP_ADDRESS', client.get('IP_ADDRESS', '0.0.0.0'))

                    # Parse mesh group list
                    mesh_groups_str = request.values.get('MESH_GROUP_UID_LIST', None)
                    if mesh_groups_str:
                        try:
                            client['MESH_GROUP_UID_LIST'] = json.loads(mesh_groups_str)
                        except:
                            pass

                    # Optional fields
                    max_bw = request.values.get('MAX_BANDWIDTH', '').strip()
                    if max_bw:
                        client['MAX_BANDWIDTH'] = max_bw
                    elif 'MAX_BANDWIDTH' in client and not max_bw:
                        del client['MAX_BANDWIDTH']

                    # Parse override IPs
                    override_ips_str = request.values.get('OVERRIDE_DST_NODE_IP', None)
                    if override_ips_str:
                        try:
                            override_ips = json.loads(override_ips_str)
                            if override_ips:
                                client['OVERRIDE_DST_NODE_IP'] = override_ips
                            elif 'OVERRIDE_DST_NODE_IP' in client:
                                del client['OVERRIDE_DST_NODE_IP']
                        except:
                            pass

                    # Parse exclusions
                    exclusions_str = request.values.get('EXCLUDED_CLIENT_DICT', None)
                    if exclusions_str:
                        try:
                            exclusions = json.loads(exclusions_str)
                            if exclusions:
                                client['EXCLUDED_CLIENT_DICT'] = exclusions
                            elif 'EXCLUDED_CLIENT_DICT' in client:
                                del client['EXCLUDED_CLIENT_DICT']
                        except:
                            pass

                    # Handle disabled flag
                    disabled = request.values.get('DISABLED', None)
                    if disabled is not None:
                        client['DISABLED'] = disabled.lower() == 'true'
                    break

            if not found:
                return jsonify({"status": "ERROR", "message": f"Client '{client_uid}' not found"})

            try:
                # Validate configuration before saving
                validation_result = validate_config_for_webui(config)
                if not validation_result['valid']:
                    return jsonify({
                        "status": "VALIDATION_ERROR",
                        "message": "Configuration validation failed",
                        "errors": validation_result['errors'],
                        "warnings": validation_result['warnings']
                    })

                with open(app.config['config_file_path'], "w") as toml_file:
                    toml.dump(config, toml_file)
                update_config_in_place(config)
                log.info(f"Client '{client_uid}' updated")
                result = {"status": "OK", "message": f"Client '{client_uid}' updated successfully. Changes applied immediately."}
                if validation_result['warnings']:
                    result['warnings'] = validation_result['warnings']
                return jsonify(result)
            except Exception as e:
                log.error(f"Error updating client: {e}")
                return jsonify({"status": "ERROR", "message": str(e)})

        elif requested_action == "DELETE_CLIENTS":
            ''' Delete one or more client configurations '''
            client_uids_str = request.values.get('CLIENT_UIDS', '')
            if not client_uids_str:
                return jsonify({"status": "ERROR", "message": "No clients specified"})

            client_uids = [uid.strip() for uid in client_uids_str.split(',')]

            read_success, config = read_conf(app.config['config_file_path'])
            if not read_success:
                return jsonify({"status": "ERROR", "message": "Unable to read config file"})

            # Remove matching clients
            original_count = len(config.get('SERVER_CLIENT', []))
            config['SERVER_CLIENT'] = [c for c in config.get('SERVER_CLIENT', []) if c.get('UID') not in client_uids]
            deleted_count = original_count - len(config.get('SERVER_CLIENT', []))

            if deleted_count == 0:
                return jsonify({"status": "ERROR", "message": "No matching clients found"})

            try:
                with open(app.config['config_file_path'], "w") as toml_file:
                    toml.dump(config, toml_file)
                update_config_in_place(config)

                # Also remove deleted clients from the in-memory dict_of_clients
                # so they disappear from the status page immediately
                dict_of_clients = app.config.get('dict_of_clients', {})
                for uid in client_uids:
                    if uid in dict_of_clients:
                        del dict_of_clients[uid]

                log.info(f"Deleted {deleted_count} client(s): {client_uids}")
                return jsonify({"status": "OK", "message": f"Deleted {deleted_count} client(s). Changes applied immediately."})
            except Exception as e:
                log.error(f"Error deleting clients: {e}")
                return jsonify({"status": "ERROR", "message": str(e)})

        elif requested_action == "DUPLICATE_CLIENT":
            ''' Duplicate an existing client configuration '''
            client_uid = request.values.get('CLIENT_UID', '').strip()
            if not client_uid:
                return jsonify({"status": "ERROR", "message": "Client UID is required"})

            read_success, config = read_conf(app.config['config_file_path'])
            if not read_success:
                return jsonify({"status": "ERROR", "message": "Unable to read config file"})

            # Find the client to duplicate
            source_client = None
            for client in config.get('SERVER_CLIENT', []):
                if client.get('UID') == client_uid:
                    source_client = copy.deepcopy(client)
                    break

            if not source_client:
                return jsonify({"status": "ERROR", "message": f"Client '{client_uid}' not found"})

            # Generate unique name
            new_uid = client_uid + "_COPY"
            suffix = 1
            existing_uids = [c.get('UID') for c in config.get('SERVER_CLIENT', [])]
            while new_uid in existing_uids:
                new_uid = f"{client_uid}_COPY{suffix}"
                suffix += 1

            source_client['UID'] = new_uid
            config['SERVER_CLIENT'].append(source_client)

            try:
                with open(app.config['config_file_path'], "w") as toml_file:
                    toml.dump(config, toml_file)
                update_config_in_place(config)
                log.info(f"Client '{client_uid}' duplicated as '{new_uid}'")
                return jsonify({"status": "OK", "message": f"Client duplicated as '{new_uid}'. New client can connect immediately."})
            except Exception as e:
                log.error(f"Error duplicating client: {e}")
                return jsonify({"status": "ERROR", "message": str(e)})

        # ======================= USER MANAGEMENT API =======================

        elif requested_action == "GET_USERS":
            ''' Get all users (admin only) '''
            if session.get('user_role') != user_mgmt.ROLE_ADMIN:
                return jsonify({"status": "ERROR", "message": "Admin access required"})
            users = user_mgmt.get_all_users()
            return jsonify({"status": "OK", "users": users})

        elif requested_action == "CREATE_USER":
            ''' Create new user (admin only) '''
            if session.get('user_role') != user_mgmt.ROLE_ADMIN:
                return jsonify({"status": "ERROR", "message": "Admin access required"})

            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            email = request.form.get('email', '').strip() or None
            role = request.form.get('role', user_mgmt.ROLE_READONLY)
            description = request.form.get('description', '').strip() or None

            success, result = user_mgmt.create_user(username, password, role, email, description)
            if success:
                return jsonify({"status": "OK", "message": "User created successfully", "user_id": result})
            else:
                return jsonify({"status": "ERROR", "message": result})

        elif requested_action == "UPDATE_USER":
            ''' Update user details (admin only) '''
            if session.get('user_role') != user_mgmt.ROLE_ADMIN:
                return jsonify({"status": "ERROR", "message": "Admin access required"})

            user_id = request.form.get('user_id')
            if not user_id:
                return jsonify({"status": "ERROR", "message": "User ID required"})

            email = request.form.get('email')
            role = request.form.get('role')
            description = request.form.get('description')
            is_active = request.form.get('is_active')

            # Convert is_active to boolean if provided
            if is_active is not None:
                is_active = is_active.lower() in ('true', '1', 'yes')

            success, message = user_mgmt.update_user(
                int(user_id),
                email=email if email else None,
                role=role if role else None,
                description=description,
                is_active=is_active,
                admin_user_id=session.get('user_id')
            )
            if success:
                return jsonify({"status": "OK", "message": message})
            else:
                return jsonify({"status": "ERROR", "message": message})

        elif requested_action == "DELETE_USER":
            ''' Delete user (admin only) '''
            if session.get('user_role') != user_mgmt.ROLE_ADMIN:
                return jsonify({"status": "ERROR", "message": "Admin access required"})

            user_id = request.form.get('user_id')
            if not user_id:
                return jsonify({"status": "ERROR", "message": "User ID required"})

            success, message = user_mgmt.delete_user(int(user_id), session.get('user_id'))
            if success:
                return jsonify({"status": "OK", "message": message})
            else:
                return jsonify({"status": "ERROR", "message": message})

        elif requested_action == "RESET_USER_PASSWORD":
            ''' Reset user password (admin only) '''
            if session.get('user_role') != user_mgmt.ROLE_ADMIN:
                return jsonify({"status": "ERROR", "message": "Admin access required"})

            user_id = request.form.get('user_id')
            new_password = request.form.get('new_password')

            if not user_id or not new_password:
                return jsonify({"status": "ERROR", "message": "User ID and new password required"})

            success, message = user_mgmt.reset_password(int(user_id), new_password, session.get('user_id'))
            if success:
                return jsonify({"status": "OK", "message": message})
            else:
                return jsonify({"status": "ERROR", "message": message})

        elif requested_action == "UNLOCK_USER":
            ''' Unlock locked user account (admin only) '''
            if session.get('user_role') != user_mgmt.ROLE_ADMIN:
                return jsonify({"status": "ERROR", "message": "Admin access required"})

            user_id = request.form.get('user_id')
            if not user_id:
                return jsonify({"status": "ERROR", "message": "User ID required"})

            success, message = user_mgmt.unlock_user(int(user_id), session.get('user_id'))
            if success:
                return jsonify({"status": "OK", "message": message})
            else:
                return jsonify({"status": "ERROR", "message": message})

        elif requested_action == "GET_PASSWORD_POLICY":
            ''' Get password policy '''
            return jsonify({"status": "OK", "policy": user_mgmt.get_password_policy()})

        elif requested_action == "GET_AUDIT_LOG":
            ''' Get audit log (admin only) '''
            if session.get('user_role') != user_mgmt.ROLE_ADMIN:
                return jsonify({"status": "ERROR", "message": "Admin access required"})

            limit = int(request.form.get('limit', 100))
            user_id = request.form.get('user_id')
            logs = user_mgmt.get_audit_log(limit, int(user_id) if user_id else None)
            return jsonify({"status": "OK", "logs": logs})

        elif requested_action == "VALIDATE_CONFIG":
            ''' Validate configuration before saving '''
            if not session.get('logged_in'):
                return jsonify({"status": "ERROR", "message": "Authentication required"})

            try:
                config_path = app.config.get('config_file_path')
                if not config_path:
                    return jsonify({"status": "ERROR", "message": "Config file path not set"})

                # Read the current config file
                with open(config_path, 'r') as f:
                    config = toml.load(f)

                # Run validation
                result = validate_config_for_webui(config)

                return jsonify({
                    "status": "OK" if result['valid'] else "VALIDATION_ERRORS",
                    "valid": result['valid'],
                    "errors": result['errors'],
                    "warnings": result['warnings']
                })

            except Exception as e:
                log.error(f"Error validating config: {e}")
                import traceback
                log.error(traceback.format_exc())
                return jsonify({"status": "ERROR", "message": str(e)})

        elif requested_action == "SAVE_SERVER_CONFIG":
            ''' Save server configuration (admin only) '''
            if session.get('user_role') != user_mgmt.ROLE_ADMIN:
                return jsonify({"status": "ERROR", "message": "Admin access required"})

            try:
                config_path = app.config.get('config_file_path')
                if not config_path:
                    return jsonify({"status": "ERROR", "message": "Config file path not set"})

                # Read the original config file
                with open(config_path, 'r') as f:
                    config = toml.load(f)

                # Update SERVER section (excluding TOKEN which is managed separately)
                if 'SERVER' not in config:
                    config['SERVER'] = {}

                bind_address = request.form.get('BIND_ADDRESS')
                server_port = request.form.get('SERVER_PORT')
                mesh_port_range = request.form.get('MESH_LISTENERS_PORT_RANGE')
                x509_private_key = request.form.get('SERVER_X509_PRIVATE_KEY')
                x509_certificate = request.form.get('SERVER_X509_CERTIFICATE')

                if bind_address:
                    config['SERVER']['BIND_ADDRESS'] = bind_address
                    app.config['config']['SERVER']['BIND_ADDRESS'] = bind_address

                if server_port:
                    config['SERVER']['SERVER_PORT'] = server_port
                    app.config['config']['SERVER']['SERVER_PORT'] = server_port

                if mesh_port_range:
                    config['SERVER']['MESH_LISTENERS_PORT_RANGE'] = mesh_port_range
                    app.config['config']['SERVER']['MESH_LISTENERS_PORT_RANGE'] = mesh_port_range

                if x509_private_key:
                    config['SERVER']['SERVER_X509_PRIVATE_KEY'] = x509_private_key
                    app.config['config']['SERVER']['SERVER_X509_PRIVATE_KEY'] = x509_private_key

                if x509_certificate:
                    config['SERVER']['SERVER_X509_CERTIFICATE'] = x509_certificate
                    app.config['config']['SERVER']['SERVER_X509_CERTIFICATE'] = x509_certificate

                # iperf3 Authentication Settings
                rsa_key_listeners = request.form.get('RSA_KEY_LISTENERS')
                rsa_key_connectors = request.form.get('RSA_KEY_CONNECTORS')
                iperf3_username = request.form.get('IPERF3_USERNAME')
                iperf3_password = request.form.get('IPERF3_PASSWORD')

                if rsa_key_listeners is not None:
                    config['SERVER']['RSA_KEY_LISTENERS'] = rsa_key_listeners
                    app.config['config']['SERVER']['RSA_KEY_LISTENERS'] = rsa_key_listeners

                if rsa_key_connectors is not None:
                    config['SERVER']['RSA_KEY_CONNECTORS'] = rsa_key_connectors
                    app.config['config']['SERVER']['RSA_KEY_CONNECTORS'] = rsa_key_connectors

                if iperf3_username is not None:
                    config['SERVER']['IPERF3_USERNAME'] = iperf3_username
                    app.config['config']['SERVER']['IPERF3_USERNAME'] = iperf3_username

                if iperf3_password:
                    # Only update password if a new one is provided
                    config['SERVER']['IPERF3_PASSWORD'] = iperf3_password
                    app.config['config']['SERVER']['IPERF3_PASSWORD'] = iperf3_password
                    # Generate SHA256 hash for the password
                    import hashlib
                    password_hash = hashlib.sha256(iperf3_password.encode()).hexdigest()
                    config['SERVER']['IPERF3_PASSWORD_HASH'] = password_hash
                    app.config['config']['SERVER']['IPERF3_PASSWORD_HASH'] = password_hash

                # Validate configuration before saving
                validation_result = validate_config_for_webui(config)
                if not validation_result['valid']:
                    return jsonify({
                        "status": "VALIDATION_ERROR",
                        "message": "Configuration validation failed",
                        "errors": validation_result['errors'],
                        "warnings": validation_result['warnings']
                    })

                # Write back to file
                with open(config_path, 'w') as f:
                    toml.dump(config, f)

                log.info(f"Server configuration saved to {config_path}")
                response = {"status": "OK", "message": "Configuration saved successfully"}
                if validation_result['warnings']:
                    response['warnings'] = validation_result['warnings']
                return jsonify(response)

            except Exception as e:
                log.error(f"Error saving server config: {e}")
                import traceback
                log.error(traceback.format_exc())
                return jsonify({"status": "ERROR", "message": str(e)})

        elif requested_action == "SAVE_GLOBAL_CONFIG":
            ''' Save global configuration (admin only) '''
            if session.get('user_role') != user_mgmt.ROLE_ADMIN:
                return jsonify({"status": "ERROR", "message": "Admin access required"})

            try:
                config_path = app.config.get('config_file_path')
                if not config_path:
                    return jsonify({"status": "ERROR", "message": "Config file path not set"})

                # Read the original config file
                with open(config_path, 'r') as f:
                    config = toml.load(f)

                # Update GLOBAL section
                if 'GLOBAL' not in config:
                    config['GLOBAL'] = {}

                iperf3_binary_path = request.form.get('IPERF3_BINARY_PATH')
                iperf3_time_skew_threshold = request.form.get('IPERF3_TIME_SKEW_THRESHOLD')
                log_to = request.form.get('LOG_TO')
                log_level = request.form.get('LOG_LEVEL')
                log_max_size = request.form.get('LOG_MAX_SIZE_PER_FILE_MB')
                log_file_to_keep = request.form.get('LOG_FILE_TO_KEEP')
                watchdog_check_rate = request.form.get('WATCHDOG_CHECK_RATE')

                if iperf3_binary_path is not None:
                    config['GLOBAL']['IPERF3_BINARY_PATH'] = iperf3_binary_path
                    app.config['config']['GLOBAL']['IPERF3_BINARY_PATH'] = iperf3_binary_path

                if iperf3_time_skew_threshold is not None:
                    config['GLOBAL']['IPERF3_TIME_SKEW_THRESHOLD'] = iperf3_time_skew_threshold
                    app.config['config']['GLOBAL']['IPERF3_TIME_SKEW_THRESHOLD'] = iperf3_time_skew_threshold

                if log_to is not None:
                    config['GLOBAL']['LOG_TO'] = log_to
                    app.config['config']['GLOBAL']['LOG_TO'] = log_to

                if log_level is not None:
                    config['GLOBAL']['LOG_LEVEL'] = log_level
                    app.config['config']['GLOBAL']['LOG_LEVEL'] = log_level

                if log_max_size is not None:
                    config['GLOBAL']['LOG_MAX_SIZE_PER_FILE_MB'] = log_max_size
                    app.config['config']['GLOBAL']['LOG_MAX_SIZE_PER_FILE_MB'] = log_max_size

                if log_file_to_keep is not None:
                    config['GLOBAL']['LOG_FILE_TO_KEEP'] = log_file_to_keep
                    app.config['config']['GLOBAL']['LOG_FILE_TO_KEEP'] = log_file_to_keep

                if watchdog_check_rate is not None:
                    config['GLOBAL']['WATCHDOG_CHECK_RATE'] = watchdog_check_rate
                    app.config['config']['GLOBAL']['WATCHDOG_CHECK_RATE'] = watchdog_check_rate

                # Validate configuration before saving
                validation_result = validate_config_for_webui(config)
                if not validation_result['valid']:
                    return jsonify({
                        "status": "VALIDATION_ERROR",
                        "message": "Configuration validation failed",
                        "errors": validation_result['errors'],
                        "warnings": validation_result['warnings']
                    })

                # Write back to file
                with open(config_path, 'w') as f:
                    toml.dump(config, f)

                log.info(f"Global configuration saved to {config_path}")
                response = {"status": "OK", "message": "Configuration saved successfully"}
                if validation_result['warnings']:
                    response['warnings'] = validation_result['warnings']
                return jsonify(response)

            except Exception as e:
                log.error(f"Error saving global config: {e}")
                import traceback
                log.error(traceback.format_exc())
                return jsonify({"status": "ERROR", "message": str(e)})

        elif requested_action == "EXPORT_SERVER_FILE":
            ''' Export certificate or private key file (admin only) '''
            if session.get('user_role') != user_mgmt.ROLE_ADMIN:
                return jsonify({"status": "ERROR", "message": "Admin access required"})

            file_type = request.form.get('FILE_TYPE')
            if file_type not in ('private_key', 'certificate'):
                return jsonify({"status": "ERROR", "message": "Invalid file type"})

            try:
                if file_type == 'private_key':
                    file_path = app.config['config']['SERVER'].get('SERVER_X509_PRIVATE_KEY', '')
                    filename = 'private_key_server.pem'
                else:
                    file_path = app.config['config']['SERVER'].get('SERVER_X509_CERTIFICATE', '')
                    filename = 'certificate_server.pem'

                if not file_path:
                    return jsonify({"status": "ERROR", "message": f"No {file_type} path configured"})

                if not os.path.exists(file_path):
                    return jsonify({"status": "ERROR", "message": f"File not found: {file_path}"})

                with open(file_path, 'r') as f:
                    content = f.read()

                log.info(f"Exported {file_type} file: {file_path}")
                return jsonify({"status": "OK", "content": content, "filename": filename})

            except Exception as e:
                log.error(f"Error exporting file: {e}")
                return jsonify({"status": "ERROR", "message": str(e)})

        # ======================= LOG MANAGEMENT API =======================

        elif requested_action == "GET_LOG_FILES":
            ''' Get list of available log files '''
            if not session.get('logged_in'):
                return jsonify({"status": "ERROR", "message": "Authentication required"})

            try:
                # Get log directory from config
                log_dir = app.config.get('log_dir', '')
                if not log_dir:
                    # Try to get from GLOBAL config
                    log_dir = app.config['config'].get('GLOBAL', {}).get('LOGDIR', '')

                if not log_dir or not os.path.exists(log_dir):
                    return jsonify({"status": "ERROR", "message": "Log directory not configured or not found"})

                files = []
                for filename in os.listdir(log_dir):
                    filepath = os.path.join(log_dir, filename)
                    if os.path.isfile(filepath) and (filename.endswith('.log') or filename.endswith('.txt')):
                        stat = os.stat(filepath)
                        files.append({
                            'name': filename,
                            'size': stat.st_size,
                            'modified': dt.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                        })

                # Sort by modification time, newest first
                files.sort(key=lambda x: x['modified'], reverse=True)

                return jsonify({"status": "OK", "files": files, "log_dir": log_dir})
            except Exception as e:
                log.error(f"Error listing log files: {e}")
                return jsonify({"status": "ERROR", "message": str(e)})

        elif requested_action == "GET_LOG_CONTENT":
            ''' Get content of a log file '''
            if not session.get('logged_in'):
                return jsonify({"status": "ERROR", "message": "Authentication required"})

            filename = request.values.get('FILENAME', '')
            lines_limit = int(request.values.get('LINES', 500))

            if not filename:
                return jsonify({"status": "ERROR", "message": "Filename required"})

            # Prevent directory traversal
            if '..' in filename or '/' in filename or '\\' in filename:
                return jsonify({"status": "ERROR", "message": "Invalid filename"})

            try:
                log_dir = app.config.get('log_dir', '')
                if not log_dir:
                    log_dir = app.config['config'].get('GLOBAL', {}).get('LOGDIR', '')

                filepath = os.path.join(log_dir, filename)

                if not os.path.exists(filepath):
                    return jsonify({"status": "ERROR", "message": "File not found"})

                stat = os.stat(filepath)
                file_size = stat.st_size
                modified = dt.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')

                # Read file content
                with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                    if lines_limit == 0:
                        # Read all
                        content = f.read()
                        total_lines = content.count('\n') + 1
                    else:
                        # Read last N lines efficiently
                        all_lines = f.readlines()
                        total_lines = len(all_lines)
                        content = ''.join(all_lines[-lines_limit:])

                return jsonify({
                    "status": "OK",
                    "content": content,
                    "file_size": file_size,
                    "modified": modified,
                    "total_lines": total_lines
                })
            except Exception as e:
                log.error(f"Error reading log file: {e}")
                return jsonify({"status": "ERROR", "message": str(e)})

        elif requested_action == "TAIL_LOG":
            ''' Get new content since last read position '''
            if not session.get('logged_in'):
                return jsonify({"status": "ERROR", "message": "Authentication required"})

            filename = request.values.get('FILENAME', '')
            last_size = int(request.values.get('LAST_SIZE', 0))

            if not filename:
                return jsonify({"status": "ERROR", "message": "Filename required"})

            # Prevent directory traversal
            if '..' in filename or '/' in filename or '\\' in filename:
                return jsonify({"status": "ERROR", "message": "Invalid filename"})

            try:
                log_dir = app.config.get('log_dir', '')
                if not log_dir:
                    log_dir = app.config['config'].get('GLOBAL', {}).get('LOGDIR', '')

                filepath = os.path.join(log_dir, filename)

                if not os.path.exists(filepath):
                    return jsonify({"status": "ERROR", "message": "File not found"})

                current_size = os.path.getsize(filepath)

                if current_size > last_size:
                    # File has grown, read new content
                    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                        f.seek(last_size)
                        new_content = f.read()

                    return jsonify({
                        "status": "OK",
                        "new_content": new_content,
                        "file_size": current_size
                    })
                elif current_size < last_size:
                    # File was truncated/rotated, read from beginning
                    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                        content = f.read()

                    return jsonify({
                        "status": "OK",
                        "new_content": content,
                        "file_size": current_size,
                        "rotated": True
                    })
                else:
                    # No change
                    return jsonify({
                        "status": "OK",
                        "new_content": "",
                        "file_size": current_size
                    })
            except Exception as e:
                log.error(f"Error tailing log file: {e}")
                return jsonify({"status": "ERROR", "message": str(e)})

        elif requested_action == "DOWNLOAD_LOG":
            ''' Download full log file content '''
            if not session.get('logged_in'):
                return jsonify({"status": "ERROR", "message": "Authentication required"})

            filename = request.values.get('FILENAME', '')

            if not filename:
                return jsonify({"status": "ERROR", "message": "Filename required"})

            # Prevent directory traversal
            if '..' in filename or '/' in filename or '\\' in filename:
                return jsonify({"status": "ERROR", "message": "Invalid filename"})

            try:
                log_dir = app.config.get('log_dir', '')
                if not log_dir:
                    log_dir = app.config['config'].get('GLOBAL', {}).get('LOGDIR', '')

                filepath = os.path.join(log_dir, filename)

                if not os.path.exists(filepath):
                    return jsonify({"status": "ERROR", "message": "File not found"})

                with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()

                return jsonify({
                    "status": "OK",
                    "content": content,
                    "filename": filename
                })
            except Exception as e:
                log.error(f"Error downloading log file: {e}")
                return jsonify({"status": "ERROR", "message": str(e)})

        elif requested_action == "RESTART_SYNTRAF":
            ''' Restart SYNTRAF server (admin only) '''
            if session.get('user_role') != user_mgmt.ROLE_ADMIN:
                return jsonify({"status": "ERROR", "message": "Admin access required"})

            import signal
            import threading
            import subprocess
            import sys

            def delayed_restart():
                time.sleep(1)  # Give time for response to be sent
                log.info("SYNTRAF restart requested via WebUI - spawning new instance")

                # Get the original command line arguments
                python_exe = sys.executable
                script_args = sys.argv.copy()

                try:
                    # On Windows, spawn a new detached process before exiting
                    if sys.platform == 'win32':
                        # Use CREATE_NEW_PROCESS_GROUP and DETACHED_PROCESS flags
                        CREATE_NEW_PROCESS_GROUP = 0x00000200
                        DETACHED_PROCESS = 0x00000008
                        subprocess.Popen(
                            [python_exe] + script_args,
                            creationflags=CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS,
                            close_fds=True
                        )
                    else:
                        # On Linux/macOS, fork a new process
                        subprocess.Popen(
                            [python_exe] + script_args,
                            start_new_session=True,
                            close_fds=True
                        )

                    log.info("New SYNTRAF instance spawned - shutting down current instance")
                except Exception as e:
                    log.error(f"Failed to spawn new SYNTRAF instance: {e}")

                time.sleep(0.5)
                os.kill(os.getpid(), signal.SIGINT)

            restart_thread = threading.Thread(target=delayed_restart, daemon=True)
            restart_thread.start()

            log.info(f"SYNTRAF restart requested by user '{session.get('username', 'unknown')}'")
            return jsonify({"status": "OK", "message": "Restart initiated"})

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


@st_home_bp.route("/logs.html", methods=["GET"])
def logs():
    if not session.get('logged_in'):
        return redirect(url_for('st_home_bp.index'))
    return render_template("logs.html", syntraf_version=DefaultValues.SYNTRAF_VERSION)


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


# @st_home_bp.after_request
# def add_header(r):
#     r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, public, max-age=0"
#     r.headers["Pragma"] = "no-cache"
#     r.headers["Expires"] = "0"
#     return r


# # Login with user/pass
# @current_app.login_manager.user_loader
# def load_user(user_id):
#     return User.get(user_id)


# login with API
# @current_app.login_manager.request_loader
# def request_loader(request):
#     email = request.form.get('email')
#     if "email" not in "users":
#         return
#
#     user = User()
#     user.id = email
#     return user
#
# @current_app.login_manager.user_loader
# def load_user(user_id):
#     return User.objects(id=user_id).first()

