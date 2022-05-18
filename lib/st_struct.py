from ctypes import *

# from wireless.h
# struct ifreq {
#    char ifr_name[IFNAMSIZ]; /* Interface name */
#    union {
# 	   struct sockaddr ifr_addr;
# 	   struct sockaddr ifr_dstaddr;
# 	   struct sockaddr ifr_broadaddr;
# 	   struct sockaddr ifr_netmask;
# 	   struct sockaddr ifr_hwaddr;
# 	   short           ifr_flags;
# 	   int             ifr_ifindex;
# 	   int             ifr_metric;
# 	   int             ifr_mtu;
# 	   struct ifmap    ifr_map;
# 	   char            ifr_slave[IFNAMSIZ];
# 	   char            ifr_newname[IFNAMSIZ];
# 	   char           *ifr_data;
#    };
# };

IFNAMSIZ = 16

class cl_ifreq(Structure):
    # from if.h
    _fields_ = [
        ("ifr_name", c_char*IFNAMSIZ),
        ("ifr_slave", c_char*IFNAMSIZ)
    ]