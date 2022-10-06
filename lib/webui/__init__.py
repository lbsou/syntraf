from flask import Flask
from lib.web_ui import st_config
import os
from lib.st_global import DefaultValues


def create_app(threads_n_processes, subprocess_iperf_dict, _dict_by_node_generated_config,
               _dict_by_group_of_generated_tuple_for_map, dict_data_to_send_to_server, config, config_file_path,
               conn_db, dict_of_commands_for_network_clients, dict_of_clients):
    """Initialize the core application."""
    os.chdir(DefaultValues.SYNTRAF_ROOT_DIR)

    app = Flask(__name__, instance_relative_config=False, static_folder=os.path.abspath('lib/web_ui/static/'), static_url_path="/static")
    app.config.from_object(st_config.DevelopmentConfig)

    with app.app_context():

        # Include blueprint
        from lib.webui.st_home_bp import st_home_bp

        # Register Blueprints
        app.register_blueprint(st_home_bp)

        dict_of_arrays_generated_tuples_for_map = {}
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
