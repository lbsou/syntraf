"""Les iperf3 lancés par SYNTRAF ne lui survivent pas.

Sous Windows, un processus qui meurt ne tue pas ses enfants : après un arrêt (mise à jour, redémarrage, plantage),
un iperf3 pouvait rester seul, tenir son port et servir une session dont plus personne ne lisait les mesures (vu en
production : un sens gris sur la carte, et le nouvel écouteur, sans port, relancé toutes les 10 s).

- bind_to_me() : sous Windows, rattache SYNTRAF à un « job object » qui tue tous ses processus enfants à sa mort,
  quelle qu'en soit la cause. Ailleurs, le superviseur arrête déjà tout le groupe de processus (lib/st_updater.py).
- kill_strays(binaire) : au démarrage, arrête les iperf3 de cette installation laissés par une instance précédente
  (même exécutable, chemin exact) : en particulier ceux d'une version sans job object, au passage à celle-ci.
"""
import logging
import os

log = logging.getLogger("syntraf." + __name__)

_JOB = None  # handle du job object : gardé ouvert tant que SYNTRAF vit (sa fermeture tue les enfants)


def _norm(path):
    return os.path.normcase(os.path.realpath(path))


def strays(binary):
    """Processus (psutil) qui exécutent exactement ce binaire, hormis SYNTRAF lui-même."""
    if not binary:
        return []
    import psutil
    target, me = _norm(binary), os.getpid()
    out = []
    for p in psutil.process_iter(["pid", "exe"]):
        try:
            exe = p.info.get("exe")
            if exe and p.pid != me and _norm(exe) == target:
                out.append(p)
        except (psutil.Error, OSError, ValueError):
            continue
    return out


def kill_strays(binary, timeout=5.0):
    """Arrête les processus de ce binaire ; renvoie leurs pid (ceux qui ont pu être arrêtés)."""
    found = strays(binary)
    if not found:
        return []
    import psutil
    for p in found:
        try:
            cmdline = " ".join(p.cmdline()[1:])[:200]
        except psutil.Error:
            cmdline = ""
        log.warning(f"IPERF3 LEFT BY A PREVIOUS RUN (PID {p.pid}{', ' + cmdline if cmdline else ''}): STOPPING IT")
        try:
            p.kill()
        except psutil.Error:
            pass
    gone, still = psutil.wait_procs(found, timeout=timeout)
    for p in still:
        log.error(f"IPERF3 LEFT BY A PREVIOUS RUN (PID {p.pid}) COULD NOT BE STOPPED")
    return sorted(p.pid for p in gone)


def bind_to_me():
    """Windows : SYNTRAF et tous les processus qu'il lancera appartiennent à un job object fermé à sa mort.
    Renvoie True si c'est fait ; False ailleurs que sous Windows, ou en cas d'échec (journalisé)."""
    global _JOB
    if os.name != "nt":
        return False
    if _JOB is not None:
        return True
    import ctypes
    from ctypes import wintypes

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in ("ReadOperationCount", "WriteOperationCount",
                                                      "OtherOperationCount", "ReadTransferCount",
                                                      "WriteTransferCount", "OtherTransferCount")]

    class BASIC_LIMIT(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD)]

    class EXTENDED_LIMIT(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", BASIC_LIMIT), ("IoInfo", IO_COUNTERS),
                    ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
    JobObjectExtendedLimitInformation = 9
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateJobObjectW.restype = wintypes.HANDLE
    k32.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
    k32.SetInformationJobObject.restype = wintypes.BOOL
    k32.SetInformationJobObject.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD)
    k32.AssignProcessToJobObject.restype = wintypes.BOOL
    k32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    k32.CloseHandle.argtypes = (wintypes.HANDLE,)

    job = k32.CreateJobObjectW(None, None)
    if not job:
        log.warning(f"IPERF3 MAY OUTLIVE SYNTRAF: CreateJobObject FAILED ({ctypes.get_last_error()})")
        return False
    info = EXTENDED_LIMIT()
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not (k32.SetInformationJobObject(job, JobObjectExtendedLimitInformation, ctypes.byref(info),
                                        ctypes.sizeof(info))
            and k32.AssignProcessToJobObject(job, k32.GetCurrentProcess())):
        log.warning(f"IPERF3 MAY OUTLIVE SYNTRAF: JOB OBJECT NOT APPLIED ({ctypes.get_last_error()})")
        k32.CloseHandle(job)
        return False
    _JOB = job  # jamais fermé : Windows le ferme à la mort de SYNTRAF, et tue alors ses enfants
    return True
