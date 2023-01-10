# SYNTRAF GLOBAL IMPORT
from lib.st_global import DefaultValues, CompilationOptions
from lib.st_conf_validation import *

# BUILTIN IMPORT
import psutil
import time
import logging
import os

log = logging.getLogger("syntraf." + __name__)


def grab_network_usage(interface_name):
    """
    We are going to read the stats of the interface two time, 1 second apart.
    Then, substract the bytes and divide it by the seconds (1).
    This, converted in bits, will give us the bitrate of the interface.
    Finally, dividing this bitrate by the interface speed, will give us the usage percentage
    """

    try:
        listening_time = 0.1

        if_speed_bits = (psutil.net_if_stats()[interface_name]._asdict()['speed']) * 1000 * 1000

        bytes_recv = []
        bytes_sent = []
        stats = psutil.net_io_counters(pernic=True, nowrap=True)[interface_name]
        bytes_sent.append(stats._asdict()['bytes_sent'])
        bytes_recv.append(stats._asdict()['bytes_recv'])

        time.sleep(listening_time)

        stats = psutil.net_io_counters(pernic=True, nowrap=True)[interface_name]
        bytes_sent.append(stats._asdict()['bytes_sent'])
        bytes_recv.append(stats._asdict()['bytes_recv'])

        bytes_sent_rate = bytes_sent[1] - bytes_sent[0]
        bytes_recv_rate = bytes_recv[1] - bytes_recv[0]

        bits_sent_rate = bytes_sent_rate * 8
        bits_recv_rate = bytes_recv_rate * 8


        pct_sent = bits_sent_rate / listening_time / if_speed_bits
        pct_recv = bits_recv_rate / listening_time / if_speed_bits
    except Exception as exc:
        return 0, 0

    return round(pct_sent * 100), round(pct_recv * 100)


def grab_free_memory():
    stats = psutil.virtual_memory()
    return round((stats._asdict()['available'] / stats._asdict()['total']) * 100)


def grab_cpu_usage():
    """
    Fetch the cpu stats two time in a row to obtain the idle status
    and insert it in an array
    """
    stats = psutil.cpu_times_percent(interval=None, percpu=True)
    time.sleep(2)
    stats = psutil.cpu_times_percent(interval=None, percpu=True)

    cpu_status = []
    for cpu in stats:
        cpu_status.append(round(100 - cpu._asdict()['idle']))

    # We return the cpu with the highest usage
    return max(cpu_status)

def aggregate_stats(dataset):
    """
    We want 1hours of max value in the sparkline
    1hours = 3600 seconds
    Stats are polled every 1/2 - 2seconds
    We need 1800 values but only got 200pixels
    So if we have to aggregate (MAX) by bucket of 9 values
    """

    size = len(dataset)
    ratio = round(size / 200)
    cpt = 0
    bucket = []
    aggregated_dataset = []

    # If we have the same or more quantity of datapoints than pixels, we should aggregate
    if size >= 200:
        # looping over the list and incrementing a count so that we know when to aggregate based on ratio value
        for item in dataset:
            if cpt == ratio:
                if len(bucket) >= 1:
                    aggregated_dataset.append(max(bucket))
                    cpt = 0
            else:
                cpt += 1
                bucket.append(item)
    else:
        return dataset

    return aggregated_dataset


class system_stats(object):
    def __init__(self, _config):
        self.timestamp = datetime.now()
        if 'CLIENT' in _config:
            if 'NETWORK_INTERFACE_NAME' in _config['CLIENT']:
                addrs = psutil.net_if_addrs()
                if _config['CLIENT']['NETWORK_INTERFACE_NAME'] in addrs.keys():
                    self.nic = _config['CLIENT']['NETWORK_INTERFACE_NAME']
                    self.if_pct_usage_tx, self.if_pct_usage_rx = grab_network_usage(self.nic)
                else:
                    log.warning(f"THE NIC NAME SPECIFIED '{_config['CLIENT']['NETWORK_INTERFACE_NAME']}' DOES NOT EXIST, UNABLE TO GET NIC STATISTICS")
        try:
            self.mem_pct_free = grab_free_memory()
            self.cpu_pct_usage = grab_cpu_usage()
            self._hasdata = True
        except Exception as exc:
            print(exc)

    def get_hasdata(self):
        return self._hasdata

    def set_hasdata(self, value):
        self._hasdata = value

    def update_stats(self):
        #log.debug(f"UPDATING SYSTEM STATS")
        try:
            # Free memory
            self.mem_pct_free = grab_free_memory()

            # Network usage
            if hasattr(self, 'nic'):
                self.if_pct_usage_tx, self.if_pct_usage_rx = grab_network_usage(self.nic)

            # CPU usage
            self.cpu_pct_usage = grab_cpu_usage()

            self.timestamp = datetime.now()

            self._hasdata = True

        except Exception as exc:
            print(exc)

    #not using vars() because we want a conditional return. Mainly because of the network interface statistics that might be absent.
    def as_dict(self):
        if hasattr(self, 'nic'):
            return {"timestamp": self.timestamp, "nic": self.nic, "mem_pct_free": self.mem_pct_free, "if_pct_usage_rx": self.if_pct_usage_rx, "if_pct_usage_tx": self.if_pct_usage_tx, "cpu_pct_usage": self.cpu_pct_usage}
        else:
            return {"timestamp": self.timestamp, "mem_pct_free": self.mem_pct_free, "if_pct_usage_rx": "NIC name undefined, see NETWORK_INTERFACE_NAME", "if_pct_usage_tx": "NIC name undefined, see NETWORK_INTERFACE_NAME", "cpu_pct_usage": self.cpu_pct_usage}

    hasdata = property(get_hasdata, set_hasdata)


# def spark_line(stats_dict_for_webui):
#     save_spark('cpu_pct_usage', stats_dict_for_webui)
#     save_spark('mem_pct_free', stats_dict_for_webui)
#     save_spark('if_pct_usage_rx', stats_dict_for_webui)
#     save_spark('if_pct_usage_tx', stats_dict_for_webui)

# def save_spark(metric, stats_dict_for_webui):
#     plt.switch_backend('Agg')
#     for key, client in stats_dict_for_webui.items():
#         dataset = list(client[metric])
#         #dataset = aggregate_stats(dataset)
#         #size = len(dataset)
#         #ratio = round(size / 200)
#         #print("Client", key, "Metric", metric, "Size", size, "Ratio", ratio)
#
#
#         f = plt.figure(figsize=(1, 0.5))
#         ax3 = f.add_subplot(1, 1, 1)
#         ax3.plot(dataset, 'y-', linewidth=0.5)
#
#         ax3.axhline(y=0, c='grey', alpha=0.5, linewidth=0.5)
#         #ax3.axhline(y=90, c='red', alpha=0.5, linewidth=0.5)
#         ax3.axhline(y=100, c='grey', alpha=0.5, linewidth=0.5)
#
#         plt.setp(ax3.get_xticklabels(), visible=False)
#         plt.setp(ax3.get_yticklabels(), visible=False)
#         plt.setp(ax3.get_xticklines(), visible=False)
#         plt.setp(ax3.get_yticklines(), visible=False)
#         plt.setp(ax3.spines.values(), visible=False)
#
#         plt.tight_layout()
#         #plt.show()
#
#         x = range(0, len(dataset), 1)
#         plt.fill_between(x, dataset, color='#539ecd', alpha=0.3)
#         plt.savefig(os.path.join(DefaultValues.SYNTRAF_ROOT_DIR, "lib", "static", "stats", f"{key}_{metric}.png"), dpi=200, transparent=True)
#         plt.close()
