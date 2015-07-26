#!/usr/bin/env python

from sniff import str2mac, mac2str
from collections import defaultdict
from oui import OUI
from os.path import exists, dirname, join
import sqlite3

oui = OUI(join(dirname(__file__), 'ieee-oui.txt'))


def get_db_conn():
    db_filename = join(dirname(__file__), 'wlanstat.db') # ':memory:'
    db_is_new = not exists(db_filename)
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


def get_bssid_essid_map(db_conn, timedelta='-5 minutes'):
    """ specified by ``timedelta``
    from now. An SSID can have multiple Access Points / BSSIDs behind it, so a
    dict which maps from SSID to a list of BSSID is returned.
    """
    query = """SELECT DISTINCT essid, bssid
    FROM beacon_packets
    WHERE timestamp_utc > STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW', ?);
    """
    ssids = defaultdict(lambda: [])
    for essid, bssid in db_conn.execute(query, [timedelta]).fetchall():
        ssids[essid].append(bssid)
    return dict(ssids)


def get_activity_per_bssid(db_conn, known_ssids_rev, timedelta='-5 minutes'):
    query = """SELECT
        data_packets.bssid,
        COUNT(data_packets.bssid),
        SUM(data_packets.size)
    FROM data_packets
    WHERE data_packets.timestamp_utc > STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW', ?)
    GROUP BY data_packets.bssid
    """
    activity = db_conn.execute(query, [timedelta]).fetchall()
    activity = dict([(bssid, (npackets, nbytes)) for bssid, npackets, nbytes in activity])
    activity_dict = defaultdict(lambda: (0, 0))
    activity_dict.update(activity)
    return [(mac2str(bssid), essid, oui.manufacturer(essid), activity_dict[bssid])
            for bssid, essid in known_ssids_rev.iteritems()]


def get_total_activity(db_conn, timedelta='-5 minutes'):
    """
    Returns n_packets, n_bytes
    """
    query = """SELECT
        COUNT(bssid),
        SUM(size)
    FROM data_packets
    WHERE data_packets.timestamp_utc > STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW', ?)
    """
    packs, bs = db_conn.execute(query, [timedelta]).fetchall()[0]
    if bs is None:
        bs = 0
    return packs, bs


def cleanup_db(db_conn, timedelta='-5 minutes'):
    """
    Deletes old database entries
    """
    query = """DELETE FROM data_packets
    WHERE timestamp_utc < STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW', ?)
    """
    count = db_conn.execute(query, [timedelta]).rowcount

    query = """DELETE FROM beacon_packets
    WHERE timestamp_utc < STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW', ?)
    """
    count2 = db_conn.execute(query, [timedelta]).rowcount
    db_conn.commit()
    return count, count2


def reverse_dict(d):
    rev = {}
    for k, v in d.iteritems():
        for i in v:
            rev[i] = k
    return rev


if __name__ == '__main__':
    known_ssids = get_bssid_essid_map(conn, '-1 minutes')
    known_ssids_rev = reverse_dict(known_ssids)
    for ap in get_activity_per_bssid(conn, known_ssids_rev, '-1 minutes'):
        print ap
