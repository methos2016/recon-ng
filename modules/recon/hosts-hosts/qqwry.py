from recon.core.module import BaseModule

import socket
import logging
from struct import unpack


logging.basicConfig(level=logging.INFO, format="%(message)s")


class qqWry(object):
    def __init__(self, db_file):
        """
        self.data           # ip database content
        self.startindex     # start index
        self.lastindex      # last index
        self.count          # index count
        """

        logging.debug('[+] Initing database [%s]' % db_file)

        with open(db_file, 'r') as dbf:
            self.data = dbf.read()

            self.startindex, self.lastindex = unpack('II', self.data[:8])
            self.count = (self.lastindex - self.startindex) / 7 + 1

    def dichotomy(self, data, kwd, begin, end, index):
        """dichotomy search"""
        if end - begin <= 1:
            logging.debug('[+] search ip index offset')
            return begin

        half = (begin + end) / 2

        i = index + half * 7
        tmp = unpack('I', data[i: i+4])[0]

        if kwd <= tmp:
            return self.dichotomy(data, kwd, begin, half, index)
        else:
            return self.dichotomy(data, kwd, half, end, index)

    def getstring(self, offset):
        """get country / city string"""
        logging.debug('[+] get ip country/city string')
        gb2312_str = self.data[offset:
                               self.data.find('\0', offset)]

        try:
            utf8_str = gb2312_str.decode('gb2312')
            # utf8_str = unicode(gb2312_str, 'gb2312').encode('utf-8')
        except:
            utf8_str = ""
        return utf8_str

    def index(self, ip):
        """get ip index with ip offset"""
        logging.debug('[+] get ip index from database')
        return self.startindex + 7 * (
            self.dichotomy(self.data,
                           # get ip number
                           unpack('!I', socket.inet_aton(ip))[0],
                           0,
                           self.count - 1,
                           self.startindex)
        )

    def record(self, offset):
        """a record = [IP Start] + [IP Offset]"""
        logging.debug('[+] get ip record from databse')
        return unpack('I',
                      "%s\0" % self.data[offset: offset + 3])[0]

    def country_redirect(self, offset):
        """record redirect"""
        byte = ord(self.data[offset])

        if byte == 1 or byte == 2:
            return self.country_redirect(self.record(offset + 1))
        else:
            return self.getstring(offset)

    def country_city(self, offset, ip=0):
        """get country / city from a record"""
        byte = ord(self.data[offset])

        if byte == 1:    # record string
            return self.country_city(self.record(offset+1))

        elif byte == 2:  # record redirect
            return (self.country_redirect(self.record(offset+1)),
                    self.country_redirect(offset+4))
        else:
            return (self.getstring(offset),
                    self.country_redirect(self.data.find('\0', offset) + 1)
                    )

    def ip_files(self, ipf):
        with open(ipf) as f:
            for i in f:
                yield i.strip()

    def ip_location(self, ip):
        # a record = IP_start (4 bytes) + IP_record_offset (3 bytes)
        # get ip record from ip from offset
        (country, city) = self.country_city(
            self.record(self.index(ip) + 4) + 4)

        return (country, city)


class Module(BaseModule):

    meta = {
        'name': 'qqwry ip locator',
        'author': 'Vex Woo (@Nixawk)',
        'description': 'get ip location from qqwry',
        'comments': ('please update ip database qqwry.dat'),
        'options': (
            ('qqwry_db', '/tmp/qqwry.dat', True, 'qqwry ip database'),
            ('ipfile', '/tmp/ips.txt', True, 'ips from file')
        )
    }

    def module_run(self):
        ipdb = self.options['qqwry_db']
        ipfile = self.options['ipfile']

        QQwry = qqWry(ipdb)

        for ip in QQwry.ip_files(ipfile):
            country, city = self.to_unicode(QQwry.ip_location(ip))
            self.output('%s => %s/%s' % (ip, country, city))

            data = {
                'ip_address': self.to_unicode(ip),
                'region': self.to_unicode(city),
                'country': self.to_unicode(country)
            }

            self.insert('hosts', data, data.keys())
