# Install Grafana on CentOS 8

## Add repository
```
vi /etc/yum.repos.d/grafana.repo
```

```
[grafana]
name=grafana
baseurl=https://packages.grafana.com/oss/rpm
repo_gpgcheck=1
enabled=1
gpgcheck=1
gpgkey=https://packages.grafana.com/gpg.key
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
```

## Install Grafana
```
yum install grafana
```

## Open firewall
```
firewall-cmd --zone=public --permanent --add-port=3000/tcp
firewall-cmd --reload
```

## Start service
```
systemctl daemon-reload
systemctl start grafana-server
systemctl enable grafana-server
```

## Configure

login admin/admin and add datasource
