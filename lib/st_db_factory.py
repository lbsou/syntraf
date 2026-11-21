"""Création d'une connexion à une base de données déclarée dans [[DATABASE]] (au démarrage et depuis la webui)."""


def make_db_connection(config, database_uid):
    database = next(d for d in config.get("DATABASE", []) if d["DB_UID"] == database_uid)
    if database["DB_ENGINE"].upper() == "VICTORIAMETRICS":
        from lib.st_victoriametrics import VictoriaMetricsObj
        return VictoriaMetricsObj(config, database_uid)
    from lib.st_influxdb import InfluxObj
    return InfluxObj(config, database_uid)
