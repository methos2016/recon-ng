from recon.core.module import BaseModule
from recon.utils.crypto import aes_decrypt

class Module(BaseModule):

    meta = {
        'name': 'PwnedList - Pwned Domain Credentials Fetcher',
        'author': 'Tim Tomes (@LaNMaSteR53)',
        'description': 'Queries the PwnedList API to fetch all credentials for a domain. Updates the \'credentials\' table with the results.',
        'comments': (
            'API Query Cost: 10,000 queries per request plus 1 query for each account returned.',
        ),
        'query': 'SELECT DISTINCT domain FROM domains WHERE domain IS NOT NULL ORDER BY domain',
    }

    def module_run(self, domains):
        key = self.get_key('pwnedlist_api')
        secret = self.get_key('pwnedlist_secret')
        decrypt_key = secret[:16]
        iv = self.get_key('pwnedlist_iv')
        # setup API call
        method = 'domains.query'
        url = 'https://api.pwnedlist.com/api/1/%s' % (method.replace('.','/'))
        for domain in domains:
            self.heading(domain, level=0)
            payload = {'domain_identifier': domain, 'daysAgo': 0}
            while True:
                # build payload
                pwnedlist_payload = self.build_pwnedlist_payload(payload, method, key, secret)
                # make request
                resp = self.request(url, payload=pwnedlist_payload)
                if resp.json: jsonobj = resp.json
                else:
                    self.error('Invalid JSON response for \'%s\'.\n%s' % (domain, resp.text))
                    break
                if len(jsonobj['accounts']) == 0:
                    self.output('No results returned for \'%s\'.' % (domain))
                    break
                # extract credentials
                for cred in jsonobj['accounts']:
                    username = cred['plain']
                    password = aes_decrypt(cred['password'], decrypt_key, iv) if cred['password'] else cred['password']
                    leak = cred['leak_id']
                    self.add_credentials(username=username, password=password, leak=leak)
                    # clean up the password for output
                    if not password: password = ''
                    self.output('%s:%s' % (username, password))
                # paginate
                if jsonobj['token']:
                    payload['token'] = jsonobj['token']
                    continue
                break
