from recon.core.module import BaseModule
from recon.mixins.resolver import ResolverMixin
import socket

class Module(BaseModule, ResolverMixin):

    meta = {
        'name': 'Hostname Resolver',
        'author': 'Vex Woo (@Nixawk)',
        'description': 'Resolves the IP address for a host with socket. Updates the \'hosts\' table with the results.',
        'comments': (
            'Note: Nameserver must be in IP form.',
        ),
        'query': 'SELECT DISTINCT host FROM hosts WHERE host IS NOT NULL AND ip_address IS NULL',
    }

    def module_run(self, hosts):
        for host in hosts:
            name, aliaslist, addresslist = socket.gethostbyname_ex(host)

            if name != host:
                self.output('%s => %s' % (host, name))

            for i in range(0, len(addresslist)):
                data = {
                    'host': self.to_unicode(host),
                    'ip_address': self.to_unicode(addresslist[i])
                }

                self.insert('hosts', data, data.keys())
                self.output('%s => %s' % (host, addresslist[i]))
