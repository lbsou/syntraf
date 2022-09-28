from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from lib.web_ui import st_config

# Globally accessible libraries
db = SQLAlchemy()
login_manager = LoginManager()


def create_app(threads_n_processes, subprocess_iperf_dict, _dict_by_node_generated_config,
               _dict_by_group_of_generated_tuple_for_map, dict_data_to_send_to_server, config, config_file_path,
               conn_db, dict_of_commands_for_network_clients, dict_of_clients):
    """Initialize the core application."""
    app = Flask(__name__, instance_relative_config=False)
    app.config.from_object(st_config.DevelopmentConfig)

    # Initialize flask-login plugin
    # login_manager.login_view = "users.login"
    login_manager.login_message = u"Please log in to access this page."
    login_manager.login_message_category = "info"
    login_manager.init_app(app)

    # Initialize SQLAlchemy Plugins
    db.init_app(app)

    with app.app_context():

        # Include blueprint
        from lib.web_ui.st_home_bp import st_home_bp

        # Warning, crashed wsgi on linux, no time to investigate further.
        #from lib.web_ui.st_auth_bp import st_auth_bp

        db.create_all()  # Create sql tables for our data models

        # Register Blueprints
        app.register_blueprint(st_home_bp)
        #app.register_blueprint(st_auth_bp)

        """ Converting a dict of tuple to a dict of arrays for javascript """
        dict_of_arrays_generated_tuples_for_map = {}

        for key, value in _dict_by_group_of_generated_tuple_for_map.items():
            if not key in dict_of_arrays_generated_tuples_for_map: dict_of_arrays_generated_tuples_for_map[key] = []
            for tuple in value:
                dict_of_arrays_generated_tuples_for_map[key].append([tuple[0], tuple[1]])

        dict_of_arrays_generated_tuples_for_map = dict_of_arrays_generated_tuples_for_map

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

        return app
