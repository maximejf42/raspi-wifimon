#!/usr/bin/env python

from sniff import get_db_conn, str2mac, mac2str
from collections import defaultdict
from oui import OUI
import time

oui = OUI('ieee-oui.txt')


def get_bssid_essid_map(db_conn, timedelta='-5 minutes'):
    """
    Find all SSIDs active in the scanner region time specified by ``timedelta``
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


def reverse_dict(d):
    rev = {}
    for k, v in d.iteritems():
        for i in v:
            rev[i] = k
    return rev


if __name__ == '__main__':
    conn = get_db_conn()
    while True:
        known_ssids = get_bssid_essid_map(conn, '-1 minutes')
        known_ssids_rev = reverse_dict(known_ssids)
        for ap in get_activity_per_bssid(conn, known_ssids_rev, '-1 minutes'):
            print ap
        print '\n\n'
        time.sleep(1)
