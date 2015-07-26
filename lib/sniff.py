#!/usr/bin/env python

import struct
import time
import os
from thread import start_new_thread

DEV_NAME = 'mon0'


def str2mac(s):
    s = b'\0\0' + b''.join([chr(int(x, 16)) for x in s.split(':')])
    return struct.unpack('!Q', s)[0]

def mac2str(mac):
    return ("%02x:"*6)[:-1] % tuple(map(ord, struct.pack('!Q', mac))[2:])


def make_packet_handler(conn):
    from scapy.layers.dot11 import Dot11
    def packet_handler(pkt):
        if pkt.haslayer(Dot11) :
            # beacon packet
            if pkt.type == 0 and pkt.subtype == 8:
                cur = conn.cursor()
                cur.execute("""INSERT INTO beacon_packets (essid, bssid)
                    VALUES (?, ?)""", (pkt.info, str2mac(pkt.addr3)))
                conn.commit()
            # data packet
            if pkt.type == 0b10:
                flags = pkt.sprintf('%Dot11.FCfield%')
                size = len(pkt / Dot11())
                ap_addr = pkt.addr3
                if 'from-DS' in flags and not ('to-DS' in flags):
                    src_addr, dst_addr, bssid = \
                        pkt.addr3, pkt.addr1, pkt.addr2
                elif 'to-DS' in flags and not ('from-DS' in flags):
                    src_addr, dst_addr, bssid = \
                         pkt.addr2, pkt.addr3, pkt.addr1
                # we dont't care about mgmt etc. packages
                elif not ('from-DS' in flags) and not ('to-DS' in flags):
                    src_addr, dst_addr, bssid = \
                         pkt.addr2, pkt.addr1, pkt.addr3
                # broadcast
                if dst_addr == 'ff:ff:ff:ff:ff:ff':
                    return
                cur = conn.cursor()
                cur.execute("""INSERT INTO data_packets (src_addr, dst_addr, bssid, size)
                    VALUES (?, ?, ?, ?)""", (str2mac(src_addr), str2mac(dst_addr), str2mac(bssid), size))
                conn.commit()

    return packet_handler


class ChannelHopper(object):
    _channels = None
    _interval_s = None
    _stop = False
    current_channel = None

    def __init__(self, channels=range(1, 15), interval_s=0.1):
        self._channels = channels
        self._interval_s = interval_s

    def _loop(self):
        i = 0
        while not self._stop:
            self._set_channel(self._channels[i])
            i = (i + 1) % len(self._channels)
            time.sleep(self._interval_s)

    def _set_channel(self, chan):
        os.system('iw dev %s set channel %d' % (DEV_NAME, chan))

    def start(self):
        start_new_thread(self._loop, ())

    def stop(self):
        self._stop = True

def setup_monitor_mode():
    os.system('iw phy phy0 interface add %s type monitor' % DEV_NAME)
    os.system('iw dev wlan0 del')
    os.system('ifconfig %s up' % DEV_NAME)

def teardown_monitor_mode():
    os.system('iw dev %s del' % DEV_NAME)
    os.system('iw phy phy0 interface add wlan0 type managed')

def sniff(db_conn, **kwargs):
    from scapy.all import sniff
    sniff(iface=DEV_NAME, prn=make_packet_handler(db_conn), **kwargs)
