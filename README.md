# SYNTRAF
Combining the power of IPERF3, INFLUXDB and GRAFANA to measure your network QoE by creating synthetic traffic.

Table of contents
* [Introduction](#introduction)
* [Technologies](#technologies)
* [Scalability](#Scalability)
* [Terminology](#terminology)
* [Use cases](#use-cases)
* [Configuration](#configuration)
* [Setup](#setup)
* [Todo](#todo)

SYNTRAF WEBUI IS STILL UNDER HEAVY DEVELOPMENT AND NON FUNCTIONAL AT THE MOMENT! YOU CAN STILL CONFIGURE EVERYTHING FROM CLI.
LOOKING FOR COLLABORATORS!  
Email me at shadow131 @ hotmail [dot] com  

## Introduction
For a long time, I was looking for an open-source tool to generate synthetic traffic without the pain of managing the connections and reading the results in CLI. SYNTRAF stand for "synthetic traffic" and aim at providing exactly that by generating customizable UDP connection between hosts with iperf3, storing the result in a time series database with influxdb which you can visualize in the tool of your choice (I'm using Grafana).  

You will need a SYNTRAF server to manage the clients and acquire the metrics, and SYNTRAF clients that will establish a control channel to the SYNTRAF server and iperf3 connection to the other clients.  

Configurations are centrally managed by the SYNTRAF server and provided to the clients upon connection.

The connections between the iperf3 clients are authenticated with credentials.  

## Use cases  
Put in place multiple tests between multiple nodes quickly;
Visualize iperf3 results history/live;
Visualize outage on a network;


## Technologies
The tool is :
- developed with Python >= 3.8
- compatible with Linux, MacOSX and Windows
- compatible with influxdb >= 2.0  
- compatible with iperf3 >= 3.9 (and ideally with the version 3.12+ Keepalive)

## Terminology
You will see references to 'CONNECTORS' and 'LISTENERS'. Those are basically substitute words for IPERF CLIENT (CONNECTORS) and IPERF SERVER (LISTENERS) when handled by SYNTRAF.

## Screenshots

![GRAFANA](/doc/images/GRAFANA.png)
![CLIENTS_STATUS](/doc/images/WEBUI_CLIENTS_STATUS.png)
![CLIENTS_STATUS_SYSINFOS](/doc/images/WEBUI_CLIENTS_STATUS_SYSINFOS.png)
![CLIENTS_STATUS_THREAD_INFOS](/doc/images/WEBUI_CLIENTS_STATUS_THREAD_INFOS.png)
![WEBUI_MESHMAPS](/doc/images/WEBUI_MESHMAPS.png)


## Configuration

The configuration file is built with the toml syntax (https://toml.io/en/)  

Here is a description of every variable of the config file.

### SERVER OR CLIENT

#### [GLOBAL]

| VAR                        | DESCRIPTION                                                                                                                                                                                                                                                                                                                                         |DEFAULT|
|:---------------------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| :----------: |
| IPERF3_BINARY_PATH         | Full path to iperf3 binary<br/>Example : ```"c:\\tools\\iperf3.exe"```<br/>Note : Use the double backslash only in Windows. Also you must install a recent version of iperf3. See the notes [here](#install-latest-version-of-iperf)                                                                                                                |AUTODETECT IN $PATH|
| IPERF3_TEMP_DIRECTORY      | Every instance of iperf3 will redirect his output to a different temporary file in this directory. Syntraf will truncate the file every interval, so no worry of outgrowing the disk capacity. If using double quote, you should escape backslash with a backslash, else, use single quote                                                          |NONE|
| IPERF3_RSA_KEY_DIRECTORY   | The directory where the RSA keypair and the credential file will be saved                                                                                                                                                                                                                                                                           |SYNTRAF_ROOT_DIR/crypto/rsa_key_iperf3|
| IPERF3_TIME_SKEW_THRESHOLD | iperf3 authentication will fail if the clock between two nodes is greater than 10 seconds. This parameter is use to change it to a bigger threshold when modifying the clock is not an option. Time skew can make reading graphics difficult as the time between metrics is not aligned. When set on a SERVER, the parameter is pass to the CLIENT. |10 seconds|
| IPERF3_AUTH                | For debugging purpose, you can deactivate iperf3 authentication. Either true or false.                                                                                                                                                                                                                                                              |true|
| LOG_TO                     | stdout, file, all                                                                                                                                                                                                                                                                                                                                   | all|
| LOG_LEVEL                  | debug, info, warning, error, critical                                                                                                                                                                                                                                                                                                               |info|
| LOG_MAX_SIZE_PER_FILE_MB   | Speak for itself                                                                                                                                                                                                                                                                                                                                    |1|
| LOG_FILE_TO_KEEP           | Zero will disable the rotating mechanism and the log file will grow without limit.                                                                                                                                                                                                                                                                  |1|
| WATCHDOG_CHECK_RATE        | Delay, in seconds, to wait between each iteration of the loop that make sure all the threads are running. When loading configuration from server, it can take up to this amount of time before the new config is loaded. Keep it short, but not too short.                                                                                          |NONE|

#### [[DATABASE]] <-- Notice the double bracket (you can create multiple instance of this)

|VAR|DESCRIPTION|DEFAULT|
| :------------- | :---------- | :----------: |
|DB_SERVER|IP or Hostname of the database server|NONE|
|DB_PORT|Port of the database service we are connecting to|NONE|
|DB_TOKEN|InfluxDB2 credential|NONE|
|DB_ORG|InfluxDB2 organization name|NONE|
|DB_BUCKET|InfluxDB2 database name|NONE|
|DB_ENGINE|InfluxDB2 only|NONE|
|DB_USE_WEB_PROXY|http://<ip_or_hostname>:\<port>|NONE|
|DB_SERVER_USE_SSL|Boolean (true / false) without double quote|true|
|DB_CONNECTION_POOL_MAXSIZE|Integer between 1 and 100000|200|


### SERVER ONLY

#### [SERVER]
|VAR| DESCRIPTION                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |DEFAULT|
| :------------- |:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| :----------: |
|BIND_ADDRESS| IPv4 address that the control channel will bind to                                                                                                                                                                                                                                                                                                                                                                                                                                                            |NONE|
|SERVER_PORT| The TCP port of the server (Integer between 1-65534)                                                                                                                                                                                                                                                                                                                                                                                                                                                          |6531|
|TOKEN| One or multiple token that will be use by the client to authenticate.<br/>The following example define two different token, the date here is a description. It is not used by the tool, feel free to put what you want but stay inside this charset (A-Za-z0-9_-). The token must be 5-255 characters. :</br>```{ 2018-01-01 = "md0a9suva0p@dsfjnav^0w43", 2019-01-01 = "md0a9suva066w43" }```<br/>The objective in having multiple token is to allow a progressive rotation in case you need to change them. |NONE|
|MESH_LISTENERS_PORT_RANGE| The port range that will be use by each client when opening iperf3 server. Can be overriden at SERVER_CLIENT level. (Range between 1-65534)                                                                                                                                                                                                                                                                                                                                                                   |15000-16000|
|SERVER_X509_SELFSIGNED_DIRECTORY| In case there is no certificate provided by the admin, SYNTRAF will generate one, this is the directory where it will be saved.                                                                                                                                                                                                                                                                                                                                                                               |SYNTRAF_ROOT_DIR/crypto/certificate_control_channel_server|
|SERVER_X509_CERTIFICATE| The X509 certificate that will be use to make the connection                                                                                                                                                                                                                                                                                                                                                                                                                                                  |NONE|
|SERVER_X509_CA_CHAIN| The CA chain of the X509 certificate that will be use to make the connection                                                                                                                                                                                                                                                                                                                                                                                                                                  |NONE|
|SERVER_X509_PRIVATE_KEY| The private key of the X509 certificate that will be use to make the connection                                                                                                                                                                                                                                                                                                                                                                                                                               |NONE|

#### [[MESH_GROUP]] <-- Notice the double bracket (you can create multiple instance of this)

This clause is a server config that represent a profile for testing in which multiple SERVER_CLIENT can later be made member of. The result is a mesh of iperf3 connection, hence his name.

| VAR               | DESCRIPTION                                                                                                                             |DEFAULT|
|:------------------|:----------------------------------------------------------------------------------------------------------------------------------------| :----------: |
| UID               | Unique identification (A-Za-z0-9_-)                                                                                                     |NONE|
| IPERF3_PROFILE    | A profile can be specified, in which case, it will overwrite the values of DSCP, INTERVAL, PACKET_PER_SECOND, PACKET_SIZE AND BANDWIDTH | NONE|
| DSCP              | Integer value between 0 and 63.<br/>QoS RFC2474                                                                                         |0|
| INTERVAL          | The interval, in seconds, at which iperf3 will report the metrics. This will be the granularity of the data in the graphics in the end. |10|
| PACKET_PER_SECOND | The amount of packet that will be sent every second.                                                                                    |NONE|
| PACKET_SIZE       | Size of the UDP packets in bytes (16-65507)                                                                                             |32|
| BANDWIDTH         | Amount of traffic to exchange between two nodes in one direction in Kbps (end with a 'k') or Mbps (end with a 'm')                      |100k|

Of the last three parameters, only two should be defined, as the third one will be automatically calculated.

#### [[IPERF3_PROFILE]] <-- Notice the double bracket (you can create multiple instance of this)

| VAR               | DESCRIPTION                                                                                                                             |DEFAULT|
|:------------------|:----------------------------------------------------------------------------------------------------------------------------------------| :----------: |
| UID               | Unique identification (A-Za-z0-9_-)                                                                                                     |NONE|
| DSCP              | Integer value between 0 and 63.<br/>QoS RFC2474                                                                                         |0|
| INTERVAL          | The interval, in seconds, at which iperf3 will report the metrics. This will be the granularity of the data in the graphics in the end. |10|
| PACKET_PER_SECOND | The amount of packet that will be sent every second.                                                                                    |NONE|
| PACKET_SIZE       | Size of the UDP packets in bytes (16-65507)                                                                                             |32|
| BANDWIDTH         | Amount of traffic to exchange between two nodes in one direction in Kbps (end with a 'k') or Mbps (end with a 'm')                      |100k|

Of the last three parameters, only two should be defined, as the third one will be automatically calculated.

#### [[SERVER_CLIENT]] <-- Notice the double bracket (you can create multiple instance of this)

This clause is a server config that define a specific node and the related attributes. For the node to be use and receive a config, it must be part of at least one MESH_GROUP.  

| VAR                       | DESCRIPTION                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |         DEFAULT         |
|:--------------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-----------------------:|
| UID                       | Unique identification (A-Za-z0-9_-)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |          NONE           |
| IP_ADDRESS                | The IPv4 address of this client (can be a FQDN)<br/>Used as identification mechanism in combination with the token (authentication) provided by the client. Use "0.0.0.0" for a dynamic IP.                                                                                                                                                                                                                                                                                                                                  |          NONE           |
| MESH_GROUP_UID_LIST       | Define the membership of this client to one or multiple MESH_GROUP<br/>By example, this make a client member of the groups LAB and VoIP : ```MESH_GROUP = ["LAB", "VoIP"]```<br/>A MESH_GROUP with the same UID must exist name must exists in the config.                                                                                                                                                                                                                                                                   |          NONE           |
| INCLUDE_ONLY_CLIENT_UID   | Let you mutually include two clients for a specific GROUP. When that configuration is present, EXCLUDED_CLIENT_UID will be ignored.<br/>By example, the following config will only allow the CENTOS8 client to establish connection to the current SERVER_CLIENT inside the group LAB.<br/> ```INCLUDE_ONLY_CLIENT_UID = {LAB = ["CENTOS8"]}```<br/>You can add multiple exclusions like this:<br/> ```INCLUDE_ONLY_CLIENT_UID = {LAB = ["CENTOS8", "CENTOS8.1"], PROD = ["REDHAT8", "REDHAT8.1"]}```                        |          NONE           |
| EXCLUDED_CLIENT_UID       | Let you mutually exclude two clients. To do so, you only need to specify the exclusion on one of the two SERVER_CLIENT config.<br/>By example, the following config will prevent the CENTOS8 client to establish connection to the current SERVER_CLIENT inside the group LAB.<br/> ```EXCLUDED_CLIENT_UID = {LAB = ["CENTOS8"]}```<br/>You can add multiple exclusions like this:<br/> ```EXCLUDED_CLIENT_UID = {LAB = ["CENTOS8", "CENTOS8.1"], PROD = ["REDHAT8", "REDHAT8.1"]}```                                        |          NONE           |
| OVERRIDE_DST_NODE_IP      | Let you change the IP address of a destination client (can be a FQDN). Normally, SYNTRAF learn the IP address of a client when it register through the control channel, but if, for example, the client is in the same subnet as the server and another client is on the Internet, that client might want to connect to a public IP which is natted to the private IP.<br/><br/> Example of a configuration under a specific SERVER_CLIENT :<br/>```[SERVER_CLIENT.OVERRIDE_DST_NODE_IP]```<br/>```LAB3-VM = "10.2.0.202"``` |          NONE           |
| MAX_BANDWIDTH             | The total bandwidth allowed for that client (one way) <br/> Must be specified in Kbps (K) or Mbps (M)                                                                                                                                                                                                                                                                                                                                                                                                                        |        UNLIMITED        |
| MESH_LISTENERS_PORT_RANGE | The port range that will be use by this client when opening iperf3 server. Normally inherited from the server clause. (Range between 1-65534)                                                                                                                                                                                                                                                                                                                                                                                | USE SERVER LEVEL CONFIG |
| BEHIND_NAT                | If set, SYNTRAF will launch a bidirectionnal connection from this node to the other nodes.                                                                                                                                                                                                                                                                                                                                                                                                                                   |          NONE           |

### CLIENT ONLY

|VAR|DESCRIPTION|DEFAULT|
| :------------- | :---------- | :----------: |
|CLIENT_UID|Unique identification (A-Za-z0-9_-) |NONE|
|SERVER|IPv4 address of the server|NONE|
|SERVER_PORT|The TCP port of the server (Integer between 1-65534)|6531|
|TOKEN|Authentication mechanism with the server. It must be 5-255 characters long.|NONE|

## Setup

### Download the latest version of SYNTRAF

```
git clone https://github.com/lbsou/syntraf.git
```

### Install the required Python modules

First install python and pip
```
yum install python3 pip3
```

The "client_only" variable in the module st_global.py allow you to configure the SYNTRAF package as a client only. This is helpful to have a smaller footprint when installing SYNTRAF or compiling a version for Windows with pyinstaller. 

As a consequence, there is two dependencies file available, choose the one that fit the value of the "client_only" variable. 

Client only instance (client_only=True):
```
pip3 install -r requirements_client.txt
```

Server and/or client instance (client_only=False) : 

```
pip3 install -r requirements_server.txt
```

### Install latest version of Iperf
SYNTRAF use the timestamp functionality of iperf3, and as it was recently added to the tool (july 2020), make sure your version is up to date.  

A keepalive function which enhance the stability of iperf3 and SYNTRAF is recommended. It is still at the stage of Pull Request, but you can get it here:  
``git clone https://github.com/davidBar-On/iperf.git --branch issue-812-835-control-connection-keepalive``  
More information in the Wiki pages  

Ref :  
https://github.com/esnet/iperf/commit/15281f6ad77522c1c790b7535a1e673e05ca9170  
https://github.com/esnet/iperf/pull/1028  
https://github.com/esnet/iperf/issues/909  

#### LINUX and MacOSX

First, depending on the platform, install the prerequisites :

Ubuntu
```
apt install build-essential 
apt install libssl-dev libtool
```

Centos

```
yum groupinstall "Development Tools"
yum install openssl-devel
```

Then you can download (https://github.com/esnet/iperf/tags), compile and install iperf 
```
wget https://github.com/esnet/iperf/archive/refs/tags/3.11.tar.gz  
tar -xvzf 3.11.tar.gz  
cd iperf-3.11 
./configure 
make
make install  
ldconfig  
```

Then you can validate the directory where iperf3 was installed

```
whereis iperf3
```
or
```
find / -name iperf3
```

#### WINDOWS
You can compile iperf3 yourself by following these instructions :

```
Install Cygwin x32 (package Devel --> Install)
Download tarball of the latest version of iperf --> http://downloads.es.net/pub/iperf/
Copy it in c:\cygwin\
Open Cygwin
tar -xvzf iperf.tar.gz -C /iperf-src
cd /iperf-src
sh boostrap.sh
./configure --with-openssl
cd ./src
find ./ -iname "*.[ch]" |xargs -n1 sed -i s'#iprintf#newprintf#g'
cd ..
make && make install
mkdir /iperf
cp -a /usr/local/bin/iperf3.exe /iperf/
cp -a /bin/cygwin1.dll /iperf/
cp -a /bin/cygcrypto-1.1.dll /iperf/
cp -a /bin/cyggcc_s-1.dll /iperf/
cp -a /bin/cygstdc++-6.dll /iperf/
cp -a /bin/cygz.dll /iperf/
```

Thanks to this website for pointing out the iprint replacement trick.
https://www.embeddedsystemtesting.com/2014/08/how-to-compile-iperf3-for-windows.html

Even if a lot of people have been using the Windows flavored version of iperf3, keep in mind that ESnet does not support iperf3 running on Windows.

### Open firewall port 

#### LINUX (CENTOS)

Server (if using the default port) :  
```
firewall-cmd --zone=public --permanent --add-port=6531/tcp
firewall-cmd --reload
```

Client (if using the default port range) :  
```
firewall-cmd --zone=public --permanent --add-port=15000-16000/udp
firewall-cmd --zone=public --permanent --add-port=15000-16000/tcp
firewall-cmd --reload
```

#### Windows
TODO

### Add as service

#### LINUX (CENTOS)
```
vi /etc/systemd/system/syntraf.service
```

```
[Unit]
Description=SYNTRAF
After=syslog.target network.target auditd.service

[Service]
ExecStart=/usr/bin/python3 /opt/syntraf/syntraf.py -c /etc/syntraf.conf -l /opt/syntraf/logs/

[Install]
WantedBy=multi-user.target
```

Automatically open the service on boot, and start it right now.

```
chkconfig syntraf on
systemctl start syntraf
systemctl status syntraf
journalctl -u syntraf -f
tail -f /opt/syntraf/logs/syntraf.log
```

#### Windows

Run SYNTRAF in task scheduler

## Data retention
It's quite common that the more recent the data, the more value is attached to high resolution. This value tend to decrease over time, so we can do some downsampling to save some disk space.

https://docs.influxdata.com/influxdb/v2.0/process-data/get-started/

Let's say we store data at the following downsampling :
  - 1sec interval for 2weeks
  - 10sec interval for 1month
  - 30sec interval for 6month
  - 60sec interval for 1year

That would give us 1 year, 7 month and 2 weeks of data.


```
option task = {name: "SYNTRAF_DOWNSAMPLE_1MIN", every: 1m, offset: 20m}

data = from(bucket: "SYNTRAF")
	|> range(start: -task.every)

data
	|> aggregateWindow(every: 1m, fn: mean)
	|> to(bucket: "SYNTRAF_1MIN")
```

## Scalability

When using SYNTRAF in a mesh topology, the amount of bandwidth can quickly become unwieldy. You must ensure that it won't affect your network!  

The formula to calculate the total bandwidth required to form a complete mesh is as follow (considering we create two independent connections between nodes in SYNTRAF):  

SN=N(N-1)*x Kbps  

You then divide by the number of nodes to obtain the bandwidth usage per nodes.  

|  |  |
| --- | --- |
| 4 nodes: <br />1 056 Kbps=4(4-1)*88 Kbps <br />1 056 / 4 = 264 Kbps / nodes | ![MESH](/doc/mesh/mesh_4_nodes.png) |
| 8 nodes: <br />4 928 Kbps=8(8-1)*88 Kbps <br />4 928 / 8 = 616 Kbps / nodes | ![MESH](/doc/mesh/mesh_8_nodes.png) |
| 16 nodes: <br /> 21 120 Kbps=16(16-1)*88 Kbps <br />21 120 / 16 = 1 320 Kbps / nodes | ![MESH](/doc/mesh/mesh_16_nodes.png) |
| 32 nodes: <br /> 87 296 Kbps=32(32-1)*88 Kbps <br />87 296 / 32 = 2 728 Kbps / nodes | ![MESH](/doc/mesh/mesh_32_nodes.png) | 
| 64 nodes: <br /> 354 816 Kbps=64(64-1)*88 Kbps <br /> 354 816 / 64 = 5 544 Kbps / nodes | ![MESH](/doc/mesh/mesh_64_nodes.png) |

What you should understand : Do not try to create a mesh with too much nodes in it. YOU HAVE BEEN WARNED.  

## FAQ

Q : I don't want to install Python on the machine I want to use as test point. What should I do?  
A : Package it with pyinstaller. Be aware that if you use the '--onefile' switch, the program will hold on a single file, but will take some time to decompress at each startup. I prefer to use "--onedir" and zip it for portability.  
```
pip3 install -U https://github.com/pyinstaller/pyinstaller/archive/develop.zip
pip3 install tornado
pyinstaller /opt/syntraf/syntraf.py --onedir
```  

Ref: https://github.com/pyinstaller/pyinstaller/issues/5004

Q : Do you have an example of a MESH_GROUP to simulate VoIP?  
R : Sure!  
```
https://www.cisco.com/c/en/us/support/docs/voice/voice-quality/7934-bwidth-consume.html
G711  
18 bytes (Ethernet) + 20 bytes (IP), 8 bytes (UDP), 12 bytes (RTP) + 160 bytes (voice) = 218 bytes  
50 pps
87.2Kbps  

Which mean, you will need those configuration inside the MESH_GROUP : 
BANDWIDTH = "87.2K"
PACKET_SIZE = "218"  

The formula : 
BANDWIDTH / 8 * 1024 / PACKET_SIZE
```

## KNOWN ISSUES

https://bytemeta.vip/repo/dmlc/GNNLens2/issues/14  
ImportError: cannot import name 'safe_join' from 'flask' #14  
Since 2.1.0, flask deprecates safe_join, as elaborated in its release note here. For now, a workaround is to degrade flask to an older version like pip install Flask==2.0.3. This should be fixed in the future release of GNNLens2 by either restricting Flask version or follow the latest recommended practice.  
Credit to @SherylHYX for reporting the issue.  

### 'IPERF3: ERROR - TEST AUTHORIZATION FAILED'  
- Clock skew >= 10 seconds (you should apply time sync over all node of the mesh)  
- Bad RSA Key (internally managed, unlikely)  
- Bad User/Password (internally managed, unlikely)  

### 'UserWarning: libuv only supports millisecond timer resolution; all times less will be set to 1 ms self.timer = get_hub().loop.timer(seconds or 0.0, ref=ref, priority=priority)'
Warning, harmless, still not been able to remove this message..


## TODO
- [ ] Better dashboard in Grafana (a table for global view) Grafana GraLLAMA Panel
- [ ] Add user syntraf for running the service.
- Buffer, pacing seront des paramêtres mais ne seront pas des metadata dans influxdb. Port non plus. Donc IP_SRC, IP_DST, TOS


