<!--
Brouillon pour ESnet (https://github.com/esnet/iperf) — rien n'a été publié.
1) Le ticket : https://github.com/esnet/iperf/issues/new (le modèle se remplit tout seul, coller la partie TICKET).
   Titre proposé : UDP --bidir: test fails when a reverse-stream packet arrives before the connect reply
2) La PR (facultative) : fork, appliquer 0001-udp-connect-bidir-out-of-order.patch, coller la partie PULL REQUEST.
-->

===================================================================== TICKET

# Context

* Version of iperf3: 3.22.1 (tag 3.22.1, built from source)

* Hardware: x86_64 (Docker containers)

* Operating system (and distribution, if any): Debian 12 (bookworm) on both ends

* Other relevant information (for example, non-default compilers,
  libraries, cross-compiling, etc.): delay and jitter emulated with tc netem on the server side

# Bug Report

* Expected Behavior

A UDP `--bidir` test should start the same way a `-R` test does when the first packet of the reverse stream gets to the client ahead of the connect reply.

* Actual Behavior

The client fails right after the first stream is set up:

```
[  4] local 10.99.0.34 port 38733 connected to 172.30.0.32 port 15910
iperf3: error - unable to read from stream socket:
```

With `--debug` the second stream receives a data packet where it expects the reply:

```
Sending Connect message to Socket 4
Connect received for Socket 4, sz=4, buf=39383736, i=0, max_len_wait_for_reply=4
Sending Connect message to Socket 6
Connect received for Socket 6, sz=4, buf=12770100, i=0, max_len_wait_for_reply=4
State change: State set to 16-IPERF_DONE (from 10-CREATE_STREAMS)
iperf3: error - unable to read from stream socket:
```

On the server side both streams show as connected and the test is already in TEST_RUNNING, so it has started sending the reverse stream.

* Steps to Reproduce

Two Linux hosts or containers, iperf3 3.22.1 on both.

Server (netem on its egress, so the connect reply and the reverse stream see the same jitter):

```
tc qdisc add dev eth0 root netem delay 30ms 12ms
iperf3 -s
```

Client, run it a dozen times:

```
iperf3 -c <server> -u -b 100K -l 218 -t 4 --bidir
```

5 runs out of 12 failed for us. The same 12 runs with `netem delay 30ms 12ms rate 1gbit` (netem then keeps packet order) all passed, and so did 12 runs with no netem at all, so it's the reordering.

* Possible Solution

PR #1260 added the out-of-order tolerance in `iperf_udp_connect()` for reverse mode only:

```c
if (test->reverse) /* In reverse mode allow few packets to have the "accept" response - to handle out of order packets */
    max_len_wait_for_reply += MAX_REVERSE_OUT_OF_ORDER_PACKETS * test->settings->blksize;
```

`--bidir` has the same reverse stream, so the condition should be `test->reverse || test->bidirectional`. With that one-line change the netem test above passed 12 times out of 12. Happy to open a PR with it.

A related but separate case: when the reply itself is lost, the connect message is never resent and the client waits for the 30 s SO_RCVTIMEO. That's what PR #1402 (UDP connect retry) is about, so I'm not trying to address it here.

===================================================================== PULL REQUEST

* Version of iperf3 (or development branch, such as `master` or
  `3.1-STABLE`) to which this pull request applies:

master (tested on 3.22.1)

* Issues fixed (if any):

#<numéro du ticket ci-dessus>

* Brief description of code changes (suitable for use as a commit message):

Allow out-of-order packets while waiting for the UDP connect reply in --bidir mode too

PR #1260 lets the client skip a few early packets of the reverse stream while it waits for the "accept" reply, but only when test->reverse is set. In --bidir mode the server also starts sending the reverse stream right after replying, so a reordered packet makes the client fail with "unable to read from stream socket". Apply the same tolerance when test->bidirectional is set.
