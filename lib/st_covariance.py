# from lib.st_influxdb import *
# import pandas as pd
# from datetime import datetime
# import time
# import pytz
# import numpy as np
# #import seaborn as sns
# import os
# import sys
# #import matplotlib.pyplot as plt
#
#
# log = logging.getLogger(__name__)
#
#
# def init_covar(_config, conn_db):
#     while True:
#         try:
#             dt = datetime.now()
#             timezone = pytz.timezone(DefaultValues.TIMEZONE)
#             dt_tz = timezone.localize(dt)
#             timestamp = dt_tz.astimezone(pytz.timezone("UTC"))
#
#             been_done = []
#             for msg in _config['MESH_GROUP']:
#
#                 # Obtaining the pair_uid
#                 query_pair_uid = f'import "influxdata/influxdb/schema" schema.tagValues(bucket: "{conn_db[0].DB_BUCKET}", tag: "UID", predicate: (r) => r._measurement == "SYNTRAF" and r.MESH_GROUP == "{msg["UID"]}", start: -3d)'
#                 result = conn_db[0].query_api.query(org="DGTI-MSSS", query=query_pair_uid)
#
#                 pair_uids = []
#                 for table in result:
#                     for record in table.records:
#                         pair_uids.append(record.get_value())
#
#                 df = pd.DataFrame(columns=pair_uids, index=pair_uids)
#
#                 for a in pair_uids:
#                     for b in pair_uids:
#                         if not b == a and not (a, b) in been_done:
#
#                             # To keep track of not doing the reverse, which would be useless
#                             been_done.append((a, b))
#                             been_done.append((b, a))
#
#                             query_covar = f'stream1 ='\
#                             f' from'\
#                             f' (bucket: "{conn_db[0].DB_BUCKET}")'\
#                             f' |> range(start: -1800s, stop: now())'\
#                             f' |> filter(fn: (r) => r["_measurement"] == "SYNTRAF")' \
#                             f' |> filter(fn: (r) => r["MESH_GROUP"] == "{msg["UID"]}")' \
#                             f' |> filter(fn: (r) => r["_field"] == "RX_JITTER")'\
#                             f' |> filter(fn: (r) => r["UID"] == "{a}")'\
#                             f' |> drop(columns: ["CLIENT", "MESH_GROUP", "_stop", "_start", "SERVER", "UID", "_field", "_measurement"])'\
#                             f' |> toFloat()'\
#                             f' stream2 ='\
#                             f' from'\
#                             f' (bucket: "{conn_db[0].DB_BUCKET}")'\
#                             f' |> range(start: -1800s, stop: now())'\
#                             f' |> filter(fn: (r) => r["_measurement"] == "SYNTRAF")'\
#                             f' |> filter(fn: (r) => r["MESH_GROUP"] == "{msg["UID"]}")' \
#                             f' |> filter(fn: (r) => r["_field"] == "RX_JITTER")'\
#                             f' |> filter(fn: (r) => r["UID"] == "{b}")'\
#                             f' |> drop(columns: ["CLIENT", "MESH_GROUP", "_stop", "_start", "SERVER", "UID", "_field", "_measurement"])'\
#                             f' |> toFloat()'\
#                             f' cov(x: stream1, y: stream2, on: ["_time"], pearsonr: true)'
#
#                             result = conn_db[0].query_api.query(org="DGTI-MSSS", query=query_covar)
#                             for table in result:
#                                 for record in table.records:
#                                     df.loc[a][b] = round(record.get_value(), 2)
#                                     df.loc[b][a] = round(record.get_value(), 2)
#                                     #insert in influxdb
#                                     try:
#                                         for conn in conn_db:
#                                             json_body = generate_json_covariance(a, b, msg['UID'], timestamp, record.get_value())
#                                             conn.write_api.write(conn.DB_BUCKET, conn.DB_ORG, json_body)
#                                         log.debug(f"COVARIANCE WRITTEN IN INFLUXDB FOR {a}, {b}, {record.get_value()}, {msg['UID']}")
#                                     except Exception as exc:
#                                         print("PROBABLY NO DATAPOINT, THIS SEGMENT OF CODE IS IN EARLY DEV")
#
#                 # df.fillna(0, inplace=True)
#                 # sns.set(font_scale=1.4)
#                 # ax = sns.heatmap(df, annot=True, xticklabels=True, yticklabels=True, vmin=-1, vmax=1, cmap="coolwarm", linewidths=0.5, linecolor="gray", annot_kws={"fontsize":8})
#                 # ax.set(title=f"Covariance of jitter {datetime.now().strftime('%Y/%m/%d %H:%M')}",
#                 #        xlabel="Pair UID B",
#                 #        ylabel="Pair UID A",)
#                 #
#                 # ax.set_xticklabels(ax.get_xmajorticklabels(), fontsize=8)
#                 # ax.set_yticklabels(ax.get_ymajorticklabels(), fontsize=8)
#                 # #plt.figure(figsize=(3.1, 3))
#                 # ax.figure.subplots_adjust(bottom=0.40, left=0.40)
#                 #
#                 # #ax.get_figure()
#                 # ax.get_figure().savefig(os.path.join(DefaultValues.SYNTRAF_ROOT_DIR, f"covariance_{msg['UID']}.png"), dpi=600)
#                 # plt.show()
#             log.info("COVARIANCE PASS IS OVER, SLEEPING FOR 3600 SECONDS")
#             time.sleep(3600)
#         except Exception as exc:
#             #SHOULD manage when database query fail
#             pass
#
#
