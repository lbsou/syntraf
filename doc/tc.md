```
yum -y install kernel-modules-extra
reboot
```

https://netbeez.net/blog/how-to-use-the-linux-traffic-control/
qdisc: modify the scheduler (aka queuing discipline)
add: add a new rule
dev eth0: rules will be applied on device eth0
root: modify the outbound traffic scheduler (aka known as the egress qdisc)
netem: use the network emulator to emulate a WAN property
delay: the network property that is modified
200ms: introduce delay of 200 ms

## Induce loss
```
tc qdisc add dev eth0 root netem loss 10%
```

## Induce variable latency
```
tc qdisc add dev enp0s3 root handle 1:0 netem delay 2000ms 1500ms 25%
tc qdisc add dev enp0s3 parent 1:1 pfifo limit 1000
```

## Induce 100ms latency
```
tc qdisc add dev enp0s3 root netem delay 100ms
```

## Delete rule
```
tc qdisc del dev enp0s3 root netem
```

## Show scheduler rules
```
tc -s qdisc
```
