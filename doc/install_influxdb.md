# Installation of InfluxDB on CentOS 8


## Download package
```
wget https://dl.influxdata.com/influxdb/releases/influxdb-2.0.0-rc.0_linux_amd64.tar.gz
tar xvfz influxdb-2.0.0-rc.0_linux_amd64.tar.gz
cp {influx,influxd} /usr/local/bin/
```

## Add user and directory
```
useradd -rs /bin/false influxdb
mkdir -p /home/influxdb
chown influxdb /home/influxdb
```

## Create a service
```
vi /etc/systemd/system/influxdb.service
```
```
[Unit]
Description=InfluxDB 2
After=network-online.target

[Service]
User=influxdb
Group=influxdb
ExecStart=/usr/local/bin/influxd
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
## Start service
```
systemctl daemon-reload
systemctl start influxdb
systemctl status influxdb
systemctl enable influxdb
```

## Open firewall
```
firewall-cmd --zone=public --permanent --add-port=8086/udp
firewall-cmd --zone=public --permanent --add-port=8086/tcp
firewall-cmd --zone=public --permanent --add-port=9999/tcp
firewall-cmd --reload
```

## Configure
```
http://ip:8086
```
