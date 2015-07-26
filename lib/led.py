#!/usr/bin/env python

import RPIO
import time
pins = [2, 3, 4, 17, 27, 22, 10, 9, 11, 7]

def setup():
    for p in pins:
        RPIO.setup(p, RPIO.OUT)
        RPIO.output(p, False)


def set_level(x):
    for i, p in enumerate(pins):
        threshold = x * 9.01
        RPIO.output(p, i < threshold)


def r(a, b):
    rev = False
    if a > b:
        b, a = a, b
        rev = True
    l = list(range(a, b + 1))
    if rev:
        return list(reversed(l))
    return l


current_level = 0

def set_level_smooth(x):
    global current_level
    for l in r(int(current_level * 10), int(x * 10))[1:]:
        set_level(l / 10.)
        time.sleep(0.1)
    set_level(x)
    current_level = x
