v0.2 - Getting things done aka ANT
 [X] Multiple topologies (p2p, mp2p, mesh)
 [X] Iperf3 test
 [X] TOML config file with validation of every field
 [X] Saving metrics to Influxdb2
 [X] Viewing metrics in Grafana dashboard
 [X] Dynamic IP client
 [X] 1 sec resolution  
 [X] Basic webui with :  
    [X] Clients system stats, system infos and status
    [X] Remote action : reconnect


v0.3 - A step back aka MOONWALK
 - iperf3 libiperf integration
 - run as a service in Windows
 - restart compatibility (Windows and Linux)
 [X] fix high loss stability (db insertion not regular)


v0.4 - The makeover aka CINDERELLA
 - Edit clients and groups from webui
 - description field for group and client  
 X Show in webui the potential and actual client bandwidth usage  
 - Integrate client and group editing with visual map
 - Remote action : pause
 X fix memory leak in client status webui [FIXED 2022-07-13 - LBS]


v0.5 - On the other side lies the truth - SUBMARINE
 - udp ping
 - Quic tunnel
 
v0.6 - Better understanding of what's going on - PULSAR
 - Manage alerts
 - saving system stats to database
 - include system stats in Grafana dashboard
 - save client logs to server
 
v0.7 - Add security aka K9
 - User login and user management
 - Group  
 - API security
 - webui compartementalized access
 - client auth

v0.8
 - Edit database retention
 - 

v0.9
 - Update client

v0.91
 - Traduction framework

v1.0
 - mtr extension

- Documentation ++
- Compress config before sending to client








