#!/usr/bin/env python

from lib.sniff import (
    ChannelHopper,
    setup_monitor_mode,
    teardown_monitor_mode,
    sniff,
)
from thread import start_new_thread
import time
from lib.data import (
    get_db_conn,
    get_total_activity,
    cleanup_db
)
from lib import led


def start_new_sniff_thread():
    def f():
        conn = get_db_conn()
        sniff(conn)
    start_new_thread(f, ())

led.setup()
setup_monitor_mode()
hopper = ChannelHopper(interval_s=0.3, channels=[1, 6, 11])
hopper.start()

start_new_sniff_thread()

try:
    conn = get_db_conn()
    while True:
        packs, bs = get_total_activity(conn, '-10 seconds')
        factor = min(bs / 30000., 1) * 0.7 + min(packs / 100., 1) * 0.3
        if factor < 0.1 and packs > 0:
            factor = 0.1
        print packs, bs, factor
        led.set_level_smooth(factor)
        cleanup_db(conn, '-10 seconds')
        time.sleep(1)
except KeyboardInterrupt:
    print 'Teardown...'
    hopper.stop()
    teardown_monitor_mode()
    led.set_level(0)
    print 'Done.'
