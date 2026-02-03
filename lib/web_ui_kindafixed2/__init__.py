from flask import Flask
#from flask_sqlalchemy import SQLAlchemy
#from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from lib.web_ui_kindafixed2 import st_config
from lib.web_ui_kindafixed2 import st_user_management as user_mgmt
from lib.web_ui_kindafixed2 import st_i18n
import os
import logging
from lib.st_global import DefaultValues

log = logging.getLogger("syntraf." + __name__)

# CSRF protection instance
csrf = CSRFProtect()

# Globally accessible libraries
#db = SQLAlchemy()
#login_manager = LoginManager()


def create_app(threads_n_processes, subprocess_iperf_dict, _dict_by_node_generated_config,
               _dict_by_group_of_generated_tuple_for_map, dict_data_to_send_to_server, config, config_file_path,
               conn_db, dict_of_commands_for_network_clients, dict_of_clients):
    """Initialize the core application."""
    os.chdir(DefaultValues.SYNTRAF_ROOT_DIR)

    app = Flask(__name__, instance_relative_config=False, static_folder=os.path.abspath('lib/web_ui_kindafixed2/static/'), static_url_path="/static")
    app.config.from_object(st_config.DevelopmentConfig)

    # Initialize CSRF protection
    csrf.init_app(app)

    # Initialize i18n (translations)
    st_i18n.init_app(app, DefaultValues.SYNTRAF_ROOT_DIR)

    # Initialize user database
    db_path = os.path.join(DefaultValues.SYNTRAF_ROOT_DIR, 'users.db')
    try:
        user_mgmt.init_database(db_path)
        log.info(f"User database initialized at {db_path}")
    except Exception as e:
        log.error(f"Failed to initialize user database: {e}")

    # Initialize flask-login plugin
    # login_manager.login_view = "users.login"
    #login_manager.login_message = u"Please log in to access this page."
    #login_manager.login_message_category = "info"
    #login_manager.init_app(app)

    # Initialize SQLAlchemy Plugins
    #db.init_app(app)

    with app.app_context():
        # Include blueprint
        from lib.web_ui_kindafixed2.st_home_bp import st_home_bp

        # Warning, crashed wsgi on linux, no time to investigate further.
        #from lib.web_ui.st_auth_bp import st_auth_bp

        #db.create_all()  # Create sql tables for our data models

        # Register Blueprints
        app.register_blueprint(st_home_bp)
        #app.register_blueprint(st_auth_bp)

        """ Converting a dict of tuple to a dict of arrays for javascript """
        dict_of_arrays_generated_tuples_for_map = {}

        for key, value in _dict_by_group_of_generated_tuple_for_map.items():
            if key not in dict_of_arrays_generated_tuples_for_map:
                dict_of_arrays_generated_tuples_for_map[key] = []
            for tup in value:
                dict_of_arrays_generated_tuples_for_map[key].append([tup[0], tup[1]])

        app.config['threads_n_processes'] = threads_n_processes
        app.config['subprocess_iperf_dict'] = subprocess_iperf_dict
        app.config['_dict_by_node_generated_config'] = _dict_by_node_generated_config
        app.config['_dict_by_group_of_generated_tuple_for_map'] = _dict_by_group_of_generated_tuple_for_map
        app.config['dict_data_to_send_to_server'] = dict_data_to_send_to_server
        app.config['config'] = config
        app.config['config_file_path'] = config_file_path
        app.config['conn_db'] = conn_db
        app.config['dict_of_commands_for_network_clients'] = dict_of_commands_for_network_clients
        app.config['dict_of_clients'] = dict_of_clients
        app.config['dict_of_arrays_generated_tuples_for_map'] = dict_of_arrays_generated_tuples_for_map
        # Set log directory for log viewer
        app.config['log_dir'] = config.get('GLOBAL', {}).get('LOGDIR', '')

        return app
