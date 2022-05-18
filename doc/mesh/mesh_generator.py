# import networkx as nx
# import matplotlib.pyplot as plt
# from itertools import combinations
#
# fig = plt.figure(figsize=(5,5))
# ax = plt.subplot(111)
# #ax.set_title('Graph - Shapes', fontsize=10)
#
# nodes = range(3)
# g = nx.complete_graph(nodes)
# edges = combinations(nodes, 2)
# g = nx.Graph()
# g.add_nodes_from(nodes)
# g.add_edges_from(edges)
#
# #pos = nx.spring_layout(g)
# pos = nx.circular_layout(g)
# nx.draw(g, pos, node_size=25, node_color='brown', font_size=8, font_weight='bold', width=0.1)
#
# plt.tight_layout()
# #plt.show()
# plt.savefig("Graph.png", format="PNG")