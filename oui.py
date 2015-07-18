#!/usr/bin/env python

import re

class OUI(object):
    _index = {}
    reg = re.compile(r'\W+([0-9A-Z\-]{8})\W+\(hex\)\W+([^\n]+)')
    def __init__(self, file):
        if isinstance(file, str):
            file = open(file, 'r')
        self._parse_file(file)

    def _parse_file(self, file):
        for l in file.readlines():
            m = self.reg.match(l)
            if m is None:
                continue
            addr = m.group(1).replace('-', '')
            self._index[addr.lower()] = m.group(2)

    def manufacturer(self, addr):
        try:
            return self._index[addr.replace(':', '')[:6].lower()]
        except KeyError:
            return None
