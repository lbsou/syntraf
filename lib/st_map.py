# import networkx as nx
# import matplotlib.pyplot as plt
# import os
# import logging
# from lib.st_global import *
# import sys
# import pathlib
#
# log = logging.getLogger("syntraf." + __name__)
#
#
# def generate_map(_list_tuple_for_map_gen, mesh_group_uid):
#     save_directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "maps")
#     p = pathlib.Path(save_directory)
#
#     try:
#         if not p.is_dir():
#             os.mkdir(save_directory)
#     except Exception as exc:
#         log.error(f"UNABLE TO CREATE DIRECTORY: '{save_directory}' TO SAVE MAPS")
#         sys.exit()
#
#     my_graph = nx.DiGraph()
#     my_graph.add_edges_from(_list_tuple_for_map_gen)
#     pos = nx.spring_layout(my_graph)
#
#     nx.draw(my_graph, pos, node_color='blue', with_labels=True, edge_color='white', font_weight='bold', connectionstyle='arc3, rad = 0.1', cmap=plt.cm.seismic, font_size=15, arrows=True)
#     plt.savefig(os.path.join(save_directory, mesh_group_uid + ".png"), dpi=200, transparent=True, bbox_inches='tight')
#     plt.subplots_adjust(bottom=0.40, left=0.40)
#     plt.clf()
#     log.info(f"MAP FOR GROUP '{mesh_group_uid}' GENERATED SUCCESSFULLY")
#
