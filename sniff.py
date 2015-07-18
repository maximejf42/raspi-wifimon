#!/usr/bin/env python

from scapy.all import sniff

import time
from scapy.layers.dot11 import Dot11
import os
import sqlite3

def get_db_conn():
    db_filename = 'wlanstat.db' # ':memory:'
    db_is_new = not os.path.exists(db_filename)
    conn = sqlite3.connect(db_filename)

    schema = """CREATE TABLE IF NOT EXISTS data_packets (
        timestamp_utc TIMESTAMP DATETIME DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')),
        bssid TEXT NOT NULL,
        src_addr TEXT NOT NULL,
        dst_addr TEXT NOT NULL,
        from_ds BOOLEAN NOT NULL,
        size INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS beacon_packets (
        timestamp_utc TIMESTAMP DATETIME DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')),
        ap_essid TEXT NOT NULL,
        ap_bssid TEXT NOT NULL
    );
    """
    conn.executescript(schema)
    return conn


def PacketHandler(pkt):
    global conn
    if pkt.haslayer(Dot11) :
        # beacon packet
        if pkt.type == 0 and pkt.subtype == 8:
            cur = conn.cursor()
            cur.execute("""INSERT INTO beacon_packets (ap_essid, ap_bssid)
                VALUES (?, ?)""", (pkt.info, pkt.addr3))
            conn.commit()
        # data packet
        if pkt.type == 0b10:
            flags = pkt.sprintf('%Dot11.FCfield%')
            size = len(pkt / Dot11())
            if 'from-DS' in flags:
                from_ds = True
                src_addr = pkt.addr3
                dst_addr = pkt.addr1
                bssid = pkt.addr2
            elif 'to-DS' in flags:
                from_ds = False
                src_addr = pkt.addr2
                dst_addr = pkt.addr3
                bssid = pkt.addr1
            cur = conn.cursor()
            cur.execute("""INSERT INTO data_packets (bssid, src_addr, dst_addr, from_ds, size)
                VALUES (?, ?, ?, ?, ?)""", (bssid, src_addr, dst_addr, from_ds, size))
            conn.commit()

conn = get_db_conn()
sniff(iface="wlan0mon", prn = PacketHandler)
