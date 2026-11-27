# SYNTRAF GLOBAL IMPORT
from lib.st_global import DefaultValues, CompilationOptions
from lib.st_conf_validation import *

# BUILTIN IMPORT
import psutil
import socket
import time
import logging
import os

log = logging.getLogger("syntraf." + __name__)


def grab_free_memory():
    stats = psutil.virtual_memory()
    return round((stats._asdict()['available'] / stats._asdict()['total']) * 100)


class NicMeter:
    """Débit d'une carte réseau entre deux appels (compteurs d'octets du système) : sur toute la période écoulée,
    pas sur un instant. Le pourcentage n'a de sens que si le système connaît le débit de la carte (souvent inconnu en
    Wi-Fi ou sur une carte virtuelle : 0)."""

    def __init__(self, interface_name, clock=time.monotonic):
        self.interface_name, self._clock, self._prev = interface_name, clock, None

    def sample(self):
        """{"rx_bps", "tx_bps", "speed_mbps"} depuis l'appel précédent ; None au premier appel ou si la carte a disparu."""
        try:
            counters = psutil.net_io_counters(pernic=True, nowrap=True)[self.interface_name]
            speed = psutil.net_if_stats()[self.interface_name].speed or None
        except (KeyError, OSError):
            self._prev = None
            return None
        now = self._clock()
        prev, self._prev = self._prev, (now, counters.bytes_recv, counters.bytes_sent)
        if prev is None or now <= prev[0]:
            return None
        elapsed = now - prev[0]
        return {"rx_bps": max(0, counters.bytes_recv - prev[1]) * 8 / elapsed,
                "tx_bps": max(0, counters.bytes_sent - prev[2]) * 8 / elapsed,
                "speed_mbps": speed}


def nic_percent(bps, speed_mbps):
    """Part du débit de la carte, en % ; None si ce débit est inconnu."""
    return round(bps / (speed_mbps * 1_000_000) * 100, 2) if speed_mbps else None


def grab_cpu():
    """(moyenne des cœurs, cœur le plus chargé) en % sur 2 s : la moyenne dit la charge du poste, le cœur le plus
    chargé révèle un processus (iperf3 compris) qui sature un seul cœur."""
    psutil.cpu_times_percent(interval=None, percpu=True)
    time.sleep(2)
    stats = psutil.cpu_times_percent(interval=None, percpu=True)
    busy = [max(0.0, 100 - cpu._asdict()['idle']) for cpu in stats] or [0.0]
    return round(sum(busy) / len(busy), 1), round(max(busy))


def grab_cpu_usage():
    """Le cœur le plus chargé, en % (valeur envoyée par toutes les versions de sonde)."""
    return grab_cpu()[1]

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


def local_address_towards(host):
    """Adresse locale par laquelle partent les paquets vers host (aucun paquet envoyé : connect() UDP), ou None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((socket.gethostbyname(host), 9))
            return s.getsockname()[0]
    except (OSError, TypeError):
        return None


def interface_for_address(address, addrs):
    for name, entries in addrs.items():
        if any(getattr(e, "address", None) == address for e in entries):
            return name
    return None


def choose_interface(client_config):
    """NETWORK_INTERFACE_NAME s'il existe ; sinon l'interface qui mène au serveur (détectée)."""
    addrs = psutil.net_if_addrs()
    wanted = client_config.get('NETWORK_INTERFACE_NAME')
    if wanted and wanted in addrs:
        return wanted
    if wanted:
        log.warning(f"THE NIC NAME SPECIFIED '{wanted}' DOES NOT EXIST: USING THE INTERFACE TOWARDS THE SERVER")
    address = local_address_towards(client_config.get('SERVER'))
    return interface_for_address(address, addrs) if address else None


class system_stats(object):
    def __init__(self, _config):
        self.timestamp = datetime.now()
        if 'CLIENT' in _config:
            nic = choose_interface(_config['CLIENT'])
            if nic:
                self.nic = nic
                self.nic_meter = NicMeter(nic)
                self.nic_meter.sample()  # référence : le débit se calcule à partir de la mesure suivante
                self.nic_rx_bps = self.nic_tx_bps = self.nic_speed_mbps = None
                self.if_pct_usage_tx = self.if_pct_usage_rx = 0
            else:
                log.warning("NETWORK INTERFACE NOT FOUND: NO NETWORK USAGE STATISTICS")
        try:
            self.mem_pct_free = grab_free_memory()
            self.cpu_pct, self.cpu_pct_usage = grab_cpu()
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

            # Network usage : débit réel depuis la mesure précédente, et part du débit de la carte s'il est connu
            if hasattr(self, 'nic'):
                rates = self.nic_meter.sample()
                if rates:
                    self.nic_rx_bps, self.nic_tx_bps = round(rates["rx_bps"]), round(rates["tx_bps"])
                    self.nic_speed_mbps = rates["speed_mbps"]
                    # anciens champs (serveurs plus anciens) : 0 quand le débit de la carte est inconnu, comme avant
                    self.if_pct_usage_rx = nic_percent(rates["rx_bps"], rates["speed_mbps"]) or 0
                    self.if_pct_usage_tx = nic_percent(rates["tx_bps"], rates["speed_mbps"]) or 0

            # CPU usage : moyenne des cœurs et cœur le plus chargé
            self.cpu_pct, self.cpu_pct_usage = grab_cpu()

            self.timestamp = datetime.now()

            self._hasdata = True

        except Exception as exc:
            print(exc)

    #not using vars() because we want a conditional return. Mainly because of the network interface statistics that might be absent.
    def as_dict(self):
        if hasattr(self, 'nic'):
            return {"timestamp": self.timestamp, "nic": self.nic, "mem_pct_free": self.mem_pct_free, "if_pct_usage_rx": self.if_pct_usage_rx, "if_pct_usage_tx": self.if_pct_usage_tx, "cpu_pct_usage": self.cpu_pct_usage, "cpu_pct": getattr(self, "cpu_pct", None),
                    "nic_rx_bps": self.nic_rx_bps, "nic_tx_bps": self.nic_tx_bps, "nic_speed_mbps": self.nic_speed_mbps}
        else:
            return {"timestamp": self.timestamp, "mem_pct_free": self.mem_pct_free, "if_pct_usage_rx": "Network interface not found, see NETWORK_INTERFACE_NAME", "if_pct_usage_tx": "Network interface not found, see NETWORK_INTERFACE_NAME", "cpu_pct_usage": self.cpu_pct_usage, "cpu_pct": getattr(self, "cpu_pct", None)}

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
