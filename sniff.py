#!/usr/bin/env python

import os
import sqlite3
import struct
import time
from thread import start_new_thread

def str2mac(s):
    s = b'\0\0' + b''.join([chr(int(x, 16)) for x in s.split(':')])
    return struct.unpack('!Q', s)[0]

def mac2str(mac):
    return ("%02x:"*6)[:-1] % tuple(map(ord, struct.pack('!Q', mac))[2:])

def get_db_conn():
    db_filename = 'wlanstat.db' # ':memory:'
    db_is_new = not os.path.exists(db_filename)
    conn = sqlite3.connect(db_filename)

    schema = """CREATE TABLE IF NOT EXISTS data_packets (
        timestamp_utc TIMESTAMP DATETIME DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')),
        -- network/ap ssid
        src_addr UNSIGNED BIG INT NOT NULL,
        -- station/end device address
        dst_addr UNSIGNED BIG INT NOT NULL,
        bssid UNSIGNED BIG INT NOT NULL,
        -- data size sent
        size INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS beacon_packets (
        timestamp_utc TIMESTAMP DATETIME DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')),
        -- text id of ap
        essid TEXT NOT NULL,
        -- address/bssid of ap
        bssid UNSIGNED BIG INT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS beacon_index ON beacon_packets (timestamp_utc);
    CREATE INDEX IF NOT EXISTS data_index ON data_packets (timestamp_utc);
    """
    conn.executescript(schema)
    return conn


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


def channel_hopper():
    # chans = [1, 6, 11]
    chans = range(1, 15)
    i = 0
    while True:
        os.system('iw dev wlan0mon set channel %d' % chans[i])
        i = (i + 1) % len(chans)
        time.sleep(0.5)


if __name__ == '__main__':
    start_new_thread(channel_hopper, ())

    conn = get_db_conn()
    from scapy.all import sniff
    sniff(iface="wlan0mon", prn=make_packet_handler(conn))
