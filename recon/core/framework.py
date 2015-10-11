from __future__ import print_function
from contextlib import closing
import cmd
import codecs
import inspect
import json
import os
import random
import re
import sqlite3
import string
import subprocess
import sys
import traceback
import logging

# framework libs
from recon.utils.requests import Request
from recon.utils.requests import handle_request_exception

# =================================================
# SUPPORT CLASSES
# =================================================


class Colors(object):
    N = '\033[m'    # native
    R = '\033[31m'  # red
    G = '\033[32m'  # green
    O = '\033[33m'  # orange
    B = '\033[34m'  # blue


class Options(dict):

    def __init__(self, *args, **kwargs):
        self.required = {}
        self.description = {}

        super(Options, self).__init__(*args, **kwargs)

    def __setitem__(self, name, value):
        super(Options, self).__setitem__(name, self._autoconvert(value))

    def __delitem__(self, name):
        super(Options, self).__delitem__(name)
        if name in self.required:
            del self.required[name]
        if name in self.description:
            del self.description[name]

    def _boolify(self, value):
        # designed to throw an exception if value is not a string
        # representation of a boolean
        return {'true': True, 'false': False}[value.lower()]

    def _autoconvert(self, value):
        if value in (None, True, False):
            return value
        elif ((isinstance(value, basestring))
              and
              value.lower() in ('none', "''", '""')):
            return None

        orig = value
        for fn in (self._boolify, int, float):
            try:
                value = fn(value)
                break
            except ValueError:
                pass
            except KeyError:
                pass
            except AttributeError:
                pass

        if type(value) is int and '.' in str(orig):
            return float(orig)
        return value

    def init_option(self, name, value=None, required=False, description=''):
        self[name] = value
        self.required[name] = required
        self.description[name] = description

    def serialize(self):
        data = {}
        for key in self:
            data[key] = self[key]
        return data


# =================================================
# FRAMEWORK CLASS
# =================================================
class FrameworkException(Exception):
    pass


class Framework(cmd.Cmd):
    """Core Framwwork"""

    logging.basicConfig(
        filename='/tmp/debugging.log', level=logging.DEBUG,
        format='[+] %(module)s - %(funcName)s : %(message)s')
    logger = logging.getLogger('Framework')

    prompt = 'core-framework > '

    # When printing help, the doc_header, misc_header, undoc_header, and
    # ruler attributes are used to fotmat the output

    ruler = '='
    lastcmd = ''
    doc_header = 'Commands (type [help|?] <topic>): '
    misc_header = 'Miscellaneous help topics: '
    undoc_header = 'Undocumented commands'
    nohelp = '%s[!] No help on %%s%s' % (Colors.R, Colors.N)

    # mode flags
    _script = 0
    _load = 0
    _spool = None
    _record = None

    # base.py - (self.options = self._global_options)
    _global_options = Options()
    options = Options()

    _loaded_modules = {}
    _home = ''
    app_path = ''
    data_path = ''
    core_path = ''
    workspace = ''
    _summary_counts = {}

    def __init__(self, params):
        self.logger.debug('')

        cmd.Cmd.__init__(self)

        self.do_help.__func__.__doc__ = '''Displays this menu'''

        self._modulename = params
        self.spacer = '  '
        self.time_format = '%Y-%m-%d %H:%M:%S'
        self.rpc_cache = []
        self._exit = 0

    # ==================================================
    # File OPERATION METHODS
    # ==================================================
    def is_writeable(self, filename):
        """check file writeable access"""
        self.logger.debug('')
        return os.access(filename, os.W_OK)

    def is_readable(self, filename):
        """check file readable access"""
        self.logger.debug('')
        return os.access(filename, os.R_OK)

    def open_file(self, filename, mode='r', encoding='utf-8'):
        """open filename and return file object"""
        f = None
        try:
            f = codecs.open(filename, mode, encoding=encoding)
        except:
            pass
        return f

    def read_file(self, filename):
        """read contents from file"""
        f = self.open_file(filename, 'r')
        d = ''
        if 'read' in dir(f):
            d = f.read()
            f.close()

        return d

    def write_file(self, filename, data, mode='a'):
        """write contents to file"""
        f = self.open_file(filename, mode)

        if 'write' in dir(f):
            f.write(data)
            f.close()

            return True

        return False

    def file_exists(self, filename):
        """check file exists or not"""
        return os.path.exists(filename)

    # ==================================================
    # CMD OVERRIDE METHODS
    # ==================================================

    # 1. precmd
    # 2. onecmd
    # 3. parseline
    # 4. postcmd

    def default(self, line):
        """If your class does not include a specific command processor
        for a command, the method default() is called with the entrie
        input line as an argument.
        """
        self.logger.debug('')
        self.do_shell(line)

    def emptyline(self):
        """If the line is empty, emptyline() is called.
        """
        self.logger.debug('')
        return 0

    def precmd(self, line):
        """The default implementation runs the previous command again.
        If the line contains a command, first precmd() is called then
        the processor is looked up and invoked.
        """
        self.logger.debug('')
        if Framework._load:
            print('\r', end='')

        if Framework._script:
            print('%s' % (line))

        if Framework._record:
            Framework._record.write(('%s\n' % (line)).encode('utf-8'))
            Framework._record.flush()

        if Framework._spool:
            Framework._spool.write(
                ('%s%s\n' % (self.prompt, line)).encode('utf-8'))
            Framework._spool.flush()
        return line

    def onecmd(self, line):
        """Each iteration through cmdloop() calls onecmd() to dispatch
        the command to its processor. The actual input line is parsed with
        parseline() to create a tuple containing the command,
        and the remaining portion of the line.
        """
        self.logger.debug('')
        cmd, arg, line = self.parseline(line)

        if not cmd:
            return self.emptyline()

        elif cmd == '':
            return self.default(line)

        elif cmd == 'EOF':
            sys.stdin = sys.__stdin__
            Framework._script = 0
            Framework._load = 0
            return 0

        else:
            self.lastcmd = line
            try:
                func = getattr(self, 'do_%s' % cmd)
            except AttributeError:
                return self.default(line)

            return func(arg)

    # make help menu more attractive
    def print_topics(self, header, cmds, cmdlen, maxcol):
        self.logger.debug('')
        if cmds:
            self.stdout.write("%s\n" % str(header))
            if self.ruler:
                self.stdout.write("%s\n" % str(self.ruler * len(header)))
            for cmd in cmds:
                self.stdout.write(
                    "%s %s\n" % (
                        cmd.ljust(15),
                        getattr(self, 'do_' + cmd).__doc__
                    )
                )
            self.stdout.write("\n")

    # ==================================================
    # SUPPORT METHODS
    # ==================================================

    def to_unicode_str(self, obj, encoding='utf-8'):
        self.logger.debug('')
        # checks if obj is a string and converts if not
        if not isinstance(obj, basestring):
            obj = str(obj)
        else:
            obj = self.to_unicode(obj, encoding)

        return obj

    def to_unicode(self, obj, encoding='utf-8'):
        self.logger.debug('')
        # checks if obj is a unicode string and converts if not
        if isinstance(obj, basestring):
            if not isinstance(obj, unicode):
                obj = unicode(obj, encoding)
        return obj

    def is_hash(self, hashstr):
        hashdict = [
            {'pattern': '^[a-fA-F0-9]{32}$', 'type': 'MD5'},
            {'pattern': '^[a-fA-F0-9]{16}$', 'type': 'MySQL'},
            {'pattern': '^\*[a-fA-F0-9]{40}$', 'type': 'MySQL5'},
            {'pattern': '^[a-fA-F0-9]{40}$', 'type': 'SHA1'},
            {'pattern': '^[a-fA-F0-9]{56}$', 'type': 'SHA224'},
            {'pattern': '^[a-fA-F0-9]{64}$', 'type': 'SHA256'},
            {'pattern': '^[a-fA-F0-9]{96}$', 'type': 'SHA384'},
            {'pattern': '^[a-fA-F0-9]{128}$', 'type': 'SHA512'},
            {'pattern': '^\$[PH]{1}\$.{31}$', 'type': 'phpass'},
            {'pattern': '^\$2[ya]?\$.{56}$', 'type': 'bcrypt'},
        ]
        for hashitem in hashdict:
            if re.match(hashitem['pattern'], hashstr):
                return hashitem['type']
        return False

    def get_random_str(self, length):
        self.logger.debug('')
        return ''.join(random.choice(string.lowercase) for i in range(length))

    def _parse_rowids(self, rowids):
        self.logger.debug('')
        xploded = []
        rowids = [x.strip() for x in rowids.split(',')]
        for rowid in rowids:
            try:
                if '-' in rowid:
                    start = int(rowid.split('-')[0].strip())
                    end = int(rowid.split('-')[-1].strip())
                    xploded += range(start, end+1)
                else:
                    xploded.append(int(rowid))
            except ValueError:
                continue
        return sorted(list(set(xploded)))

    # ==================================================
    # OUTPUT METHODS
    # ==================================================

    def print_exception(self, line=''):
        self.logger.debug('')
        if self._global_options['debug']:
            print('%s%s' % (Colors.R, '-'*60))
            traceback.print_exc()
            print('%s%s' % ('-'*60, Colors.N))
        line = ' '.join(
            [x for x in [
                traceback.format_exc().strip().splitlines()[-1], line
            ] if x])
        self.error(line)

    def error(self, line):
        self.logger.debug('')
        '''Formats and presents errors.'''
        if not re.search('[.,;!?]$', line):
            line += '.'
        line = line[:1].upper() + line[1:]
        print('%s[!] %s%s' % (Colors.R, self.to_unicode(line), Colors.N))

    def output(self, line):
        self.logger.debug('')
        '''Formats and presents normal output.'''
        print('%s[*]%s %s' % (Colors.B, Colors.N, self.to_unicode(line)))

    def alert(self, line):
        self.logger.debug('')
        '''Formats and presents important output.'''
        print('%s[*]%s %s' % (Colors.G, Colors.N, self.to_unicode(line)))

    def verbose(self, line):
        self.logger.debug('')
        '''Formats and presents output if in verbose mode.'''
        if self._global_options['verbose']:
            self.output(line)

    def debug(self, line):
        self.logger.debug('')
        '''Formats and presents output if in debug mode (very verbose).'''
        if self._global_options['debug']:
            self.output(line)

    def heading(self, line, level=1):
        '''Formats and presents styled header text'''
        self.logger.debug('')
        line = self.to_unicode(line)
        # print('')
        if level == 0:
            print(self.ruler*len(line))
            print(line.upper())
            print(self.ruler*len(line))

        if level == 1:
            print('%s%s' % (self.spacer, line.title()))
            print('%s%s' % (self.spacer, self.ruler*len(line)))

    # ==================================================
    # OUTPUT TABLE METHODS
    # ==================================================

    def table_column_check(self, tdata):
        """whether columns lengths are the same or not"""
        self.logger.debug('')
        if len(set([len(x) for x in tdata])) > 1:
            raise FrameworkException('Row lengths not consistent.')

    def table_column_lens(self, header, tdata):
        """get every column max length, and return length list"""
        self.logger.debug('')
        column_lens = []

        cols = len(header)
        for i in range(0, cols):
            _ = [self.to_unicode_str(x[i]) if x[i] else '' for x in tdata]
            column_lens.append(len(max(_, key=len)))

        return column_lens

    def table_title_lens(self, header, title, lens):
        self.logger.debug('')
        cols = len(header)
        title_len = len(title)
        tdata_len = sum(lens) + (3 * (cols - 1))
        diff = title_len - tdata_len
        if diff > 0:
            diff_per = diff / cols
            lens = [x+diff_per for x in lens]
            diff_mod = diff % cols
            for x in range(0, diff_mod):
                lens[x] += 1

        return lens

    def table_sep_fmt(self, header):
        """table separator format"""
        self.logger.debug('')
        return '%s+-%s%%s-+' % (self.spacer, '%s---' * (len(header)-1))

    def table_sep_data(self, lens):
        """table formate data"""
        self.logger.debug('')
        return tuple(['-' * x for x in lens])

    def table_record_fmt(self, header):
        """table record format"""
        self.logger.debug('')
        cols = len(header)
        return '%s| %s%%s |' % (self.spacer, '%s | ' * (cols-1))

    def table_record_data(self, header, rdata, lens):
        """table record data"""
        self.logger.debug('')
        return tuple([
            self.to_unicode_str(rdata[i]).ljust(lens[i])
            if rdata[i] is not None else ''.ljust(lens[i])
            for i in range(0, len(header))
        ])

    def table_header_data(self, header, lens):
        """table header format"""
        self.logger.debug('')
        return tuple([
            header[i].center(lens[i])
            for i in range(0, len(header))
        ])

    def table(self, data, header=[], title=''):
        '''Accepts a list of rows and outputs a table.'''
        self.logger.debug('')

        # table = sep + title + header + records + sep
        tdata = list(data)

        if header:
            tdata.insert(0, header)

        # whether columns lengths are the same or not
        self.table_column_check(tdata)

        header = tdata[0]
        # create a list of max widths for each column
        lens = self.table_column_lens(header, tdata)

        # calculate dynamic widths based on the title
        tdata_len = sum(lens) + (3 * (len(header) - 1))
        lens = self.table_title_lens(header, title, lens)

        # print data with table format

        separator = self.table_sep_fmt(header) % self.table_sep_data(lens)
        print('')
        print(separator)

        # print title columns
        if title:
            print('%s| %s |' % (self.spacer, title.center(tdata_len)))
            print(separator)

        # print header columns
        data_str = self.table_record_fmt(header)

        if header:
            rdata = tdata.pop(0)
            print(data_str % self.table_header_data(rdata, lens))
            print(separator)

        # print record columns
        for rdata in tdata:
            print(data_str % self.table_record_data(header, rdata, lens))

        print(separator)
        print('')

    # ==================================================
    # DATABASE METHODS
    # ==================================================

    def query(self, query, values=(), path=''):
        """Queries the database and returns the results as a list."""
        self.logger.debug('')

        path = path if path else os.path.join(self.workspace, 'data.db')

        self.debug('DATABASE => %s' % (path))
        self.debug('QUERY => %s' % (query))

        with sqlite3.connect(path) as conn:
            with closing(conn.cursor()) as cur:
                if values:
                    self.debug('VALUES => %s' % (repr(values)))
                    cur.execute(query, values)
                else:
                    cur.execute(query)

                # a rowcount of -1 typically refers to a select statement
                if cur.rowcount == -1:
                    results = cur.fetchall()
                # a rowcount of 1 == success and 0 == failure
                else:
                    conn.commit()
                    results = cur.rowcount
                return results

    def get_columns(self, table):
        """get columns names and types"""
        self.logger.debug('')
        sql = 'PRAGMA table_info(\'%s\')' % table
        self.debug('QUERY => %s' % sql)

        return [(name, _type) for (
            cid, name, _type, notnull, dflt_value, pk
        ) in self.query(sql)]

    def get_tables(self):
        """get tables names"""
        self.logger.debug('')
        sql = 'SELECT name FROM sqlite_master WHERE type=\'table\''
        self.debug('QUERY => %s' % sql)

        return [name for (
            name,
        ) in self.query(sql) if name not in ['dashboard']]

    # ==================================================
    # ADD METHODS
    # ==================================================

    def add_domains(self, domain=None):
        '''Adds a domain to the database and returns the affected row count.'''
        self.logger.debug('')
        data = dict(domain=self.to_unicode(domain))
        return self.insert('domains', data, data.keys())

    def add_companies(self, company=None, description=None):
        '''Adds a company to the database
        and returns the affected row count.'''
        self.logger.debug('')

        data = dict(
            company=self.to_unicode(company),
            description=self.to_unicode(description)
        )
        return self.insert('companies', data, ('company',))

    def add_netblocks(self, netblock=None):
        '''Adds a netblock to the database
        and returns the affected row count.'''
        self.logger.debug('')

        data = dict(netblock=self.to_unicode(netblock))
        return self.insert('netblocks', data, data.keys())

    def add_locations(self, latitude=None, longitude=None,
                      street_address=None):
        '''Adds a location to the database
        and returns the affected row count.'''
        data = dict(
            latitude=self.to_unicode(latitude),
            longitude=self.to_unicode(longitude),
            street_address=self.to_unicode(street_address)
        )

        return self.insert('locations', data, data.keys())

    def add_vulnerabilities(self, host=None, reference=None,
                            example=None, publish_date=None,
                            category=None, status=None):
        '''Adds a vulnerability to the database and
        returns the affected row count.'''
        self.logger.debug('')
        data = dict(
            host=self.to_unicode(host),
            reference=self.to_unicode(reference),
            example=self.to_unicode(example),
            publish_date=self.to_unicode(
                publish_date.strftime(self.time_format)
                if publish_date else None),
            category=self.to_unicode(category),
            status=self.to_unicode(status)
        )

        return self.insert('vulnerabilities', data, data.keys())

    def add_ports(self, ip_address=None, host=None, port=None, protocol=None):
        '''Adds a port to the database and returns the affected row count.'''
        self.logger.debug('')
        data = dict(
            ip_address=self.to_unicode(ip_address),
            port=self.to_unicode(port),
            host=self.to_unicode(host),
            protocol=self.to_unicode(protocol)
        )

        return self.insert('ports', data, ('ip_address', 'port', 'host'))

    def add_hosts(self, host=None, ip_address=None,
                  region=None, country=None,
                  latitude=None, longitude=None):
        '''Adds a host to the database and
        returns the affected row count.'''
        self.logger.debug('')
        data = dict(
            host=self.to_unicode(host),
            ip_address=self.to_unicode(ip_address),
            region=self.to_unicode(region),
            country=self.to_unicode(country),
            latitude=self.to_unicode(latitude),
            longitude=self.to_unicode(longitude)
        )

        return self.insert('hosts', data, ('host', 'ip_address'))

    def add_contacts(self, first_name=None, middle_name=None,
                     last_name=None, email=None,
                     title=None, region=None, country=None):
        '''Adds a contact to the database
        and returns the affected row count.'''
        self.logger.debug('')
        data = dict(
            first_name=self.to_unicode(first_name),
            middle_name=self.to_unicode(middle_name),
            last_name=self.to_unicode(last_name),
            title=self.to_unicode(title),
            email=self.to_unicode(email),
            region=self.to_unicode(region),
            country=self.to_unicode(country)
        )

        return self.insert(
            'contacts', data,
            ('first_name', 'middle_name', 'last_name', 'title', 'email'))

    def add_credentials(self, username=None, password=None,
                        _hash=None, _type=None, leak=None):
        '''Adds a credential to the database
        and returns the affected row count.'''
        self.logger.debug('')
        data = dict(
            username=self.to_unicode(username),
            password=self.to_unicode(password),
            hash=self.to_unicode(_hash),
            type=self.to_unicode(_type),
            leak=self.to_unicode(leak)
        )
        if password and not _hash:
            hash_type = self.is_hash(password)
            if hash_type:
                data['hash'] = self.to_unicode(password)
                data['type'] = self.to_unicode(hash_type)
                data['password'] = None
        # add email usernames to contacts
        if username is not None and '@' in username:
            self.add_contacts(
                first_name=None, last_name=None, title=None, email=username)
        return self.insert('credentials', data, data.keys())

    def add_leaks(self, leak_id=None, description=None, source_refs=None,
                  leak_type=None, title=None, import_date=None,
                  leak_date=None, attackers=None, num_entries=None,
                  score=None, num_domains_affected=None, attack_method=None,
                  target_industries=None, password_hash=None,
                  password_type=None, targets=None, media_refs=None):
        '''Adds a leak to the database and returns the affected row count.'''
        self.logger.debug('')
        data = dict(
            leak_id=self.to_unicode(leak_id),
            description=self.to_unicode(description),
            source_refs=self.to_unicode(source_refs),
            leak_type=self.to_unicode(leak_type),
            title=self.to_unicode(title),
            import_date=self.to_unicode(import_date),
            leak_date=self.to_unicode(leak_date),
            attackers=self.to_unicode(attackers),
            num_entries=self.to_unicode(num_entries),
            score=self.to_unicode(score),
            num_domains_affected=self.to_unicode(num_domains_affected),
            attack_method=self.to_unicode(attack_method),
            target_industries=self.to_unicode(target_industries),
            password_hash=self.to_unicode(password_hash),
            password_type=self.to_unicode(password_type),
            targets=self.to_unicode(targets),
            media_refs=self.to_unicode(media_refs)
        )
        return self.insert('leaks', data, data.keys())

    def add_pushpins(self, source=None, screen_name=None,
                     profile_name=None, profile_url=None,
                     media_url=None, thumb_url=None,
                     message=None, latitude=None,
                     longitude=None, time=None):
        '''Adds a pushpin to the database
        and returns the affected row count.'''
        self.logger.debug('')
        data = dict(
            source=self.to_unicode(source),
            screen_name=self.to_unicode(screen_name),
            profile_name=self.to_unicode(profile_name),
            profile_url=self.to_unicode(profile_url),
            media_url=self.to_unicode(media_url),
            thumb_url=self.to_unicode(thumb_url),
            message=self.to_unicode(message),
            latitude=self.to_unicode(latitude),
            longitude=self.to_unicode(longitude),
            time=self.to_unicode(time.strftime(self.time_format))
        )
        return self.insert('pushpins', data, data.keys())

    def add_profiles(self, username=None, resource=None,
                     url=None, category=None, notes=None):
        '''Adds a profile to the database
        and returns the affected row count.'''
        self.logger.debug('')
        data = dict(
            username=self.to_unicode(username),
            resource=self.to_unicode(resource),
            url=self.to_unicode(url),
            category=self.to_unicode(category),
            notes=self.to_unicode(notes)
        )
        return self.insert('profiles', data, ('username', 'url'))

    def add_repositories(self, name=None, owner=None, description=None,
                         resource=None, category=None, url=None):
        '''Adds a repository to the database
        and returns the affected row count.'''
        self.logger.debug('')
        data = dict(
            name=self.to_unicode(name),
            owner=self.to_unicode(owner),
            description=self.to_unicode(description),
            resource=self.to_unicode(resource),
            category=self.to_unicode(category),
            url=self.to_unicode(url)
        )
        return self.insert('repositories', data, data.keys())

    def insert(self, table, data, unique_columns=[]):
        '''Inserts items into database and returns the affected row count.
        table - the table to insert the data into
        data - the information to insert into the database table in the
               form of a dictionary where the keys are the column names
               and the values are the column values
        unique_columns - a list of column names that should be used to
                         determine if the information being inserted is unique
        '''
        # set module to the calling module unless the do_add command was used
        # frame_obj, src_file, line, funcname, src_code, n
        self.logger.debug('')

        funcs = [funcname for (
            frame_obj, src_file, line, funcname, src_code, n
        ) in inspect.stack()]

        if 'do_add' in funcs:
            data['module'] = 'user_defined'
        else:
            data['module'] = self._modulename.split('/')[-1]

        columns = [key for key in data.keys() if data[key]]

        if not columns:
            return 0

        # make sure that module is not seen as a unique column
        unique_columns = [
            key for key in unique_columns
            if key in columns and key != 'module']

        if not unique_columns:
            col_names = '", "'.join(columns)
            col_value = ', '.join('?' * len(columns))
            query = u'INSERT INTO "%s" ("%s") VALUES (%s)' % (
                table, col_names, col_value)
        else:
            col_names = '", "'.join(columns)
            col_value = ', '.join('?' * len(columns))
            condition = ' and '.join(
                ['"%s"=?' % (column) for column in unique_columns])
            query = (
                u'INSERT INTO "%s" ("%s") '
                'SELECT %s WHERE NOT EXISTS(SELECT * FROM "%s" WHERE %s)'
            ) % (table, col_names, col_value, table, condition)

        col_values = [data[column] for column in columns]
        un_col_values = [data[column] for column in unique_columns]

        values = tuple(col_values + un_col_values)

        rowcount = self.query(query, values)

        # increment summary tracker
        if table not in self._summary_counts:
            self._summary_counts[table] = [0, 0]

        self._summary_counts[table][0] += rowcount
        self._summary_counts[table][1] += 1

        # build RPC response
        for key in data.keys():
            if not data[key]:
                del data[key]
        self.rpc_cache.append(data)

        return rowcount

    # ==================================================
    # OPTIONS METHODS
    # ==================================================

    def register_option(self, name, value, required, description):
        self.logger.debug('')

        # Please see base.py (self.options = self._global_options)
        self.options.init_option(
            name=name.lower(), value=value,
            required=required, description=description)
        # needs to be optimized rather than ran on every register
        self._load_config()

    def _validate_options(self):
        self.logger.debug('')
        for option in self.options:
            ops_opt = self.options[option]
            req_opt = self.options.required[option]

            if not type(ops_opt) in [bool, int]:
                if (req_opt is True) and (not ops_opt):
                    exp = 'Value required for \'%s\' option.' % option.upper()
                    raise FrameworkException(exp)
        return

    def _json_loads(self, data):
        """load json data"""
        conf_data = {}
        try:
            conf_data = json.loads(data)
        except ValueError:
            pass
        return conf_data

    def _load_config(self):
        """load config from file"""
        self.logger.debug('')
        conf_path = os.path.join(self.workspace, 'config.dat')

        if self.file_exists(conf_path):
            cf = self._json_loads(self.read_file(conf_path))

            for key in self.options:
                if (self._modulename in cf) and (key in cf[self._modulename]):
                    self.options[key] = cf[self._modulename][key]

    def _save_config(self, name):
        """save config to file"""
        self.logger.debug('')

        conf_path = os.path.join(self.workspace, 'config.dat')
        config_data = {}

        if self.file_exists(conf_path):
            config_data = self._json_loads(self.read_file(conf_path))
        else:
            self.write_file(conf_path, '', mode='a')  # create new conf file

        # create a container for the current module
        if self._modulename not in config_data:
            config_data[self._modulename] = {}

        # set the new option value in the config
        config_data[self._modulename][name] = self.options[name]

        # remove the option if it has been unset
        if config_data[self._modulename][name] is None:
            del config_data[self._modulename][name]

        # remove the module container if it is empty
        if not config_data[self._modulename]:
            del config_data[self._modulename]

        # write the new config data to the config file
        f = self.open_file(conf_path, mode='w')
        if f:
            json.dump(config_data, f, indent=4)

    # ==================================================
    # API KEY METHODS
    # ==================================================

    def get_key(self, name):
        self.logger.debug('')
        rows = self._query_keys(
            'SELECT value FROM keys WHERE name=? AND value NOT NULL', (name,))

        if not rows:
            raise FrameworkException(
                'API key \'%s\' not found. '
                'Add API keys with the \'keys add\' command.' % (name))
        return rows[0][0]

    def add_key(self, name, value):
        self.logger.debug('')
        result = self._query_keys(
            'UPDATE keys SET value=? WHERE name=?', (value, name))
        if not result:
            return self._query_keys(
                'INSERT INTO keys VALUES (?, ?)', (name, value))
        return result

    def delete_key(self, name):
        self.logger.debug('')
        return self._query_keys('DELETE FROM keys WHERE name=?', (name,))

    def _query_keys(self, query, values=()):
        self.logger.debug('')
        path = os.path.join(self._home, 'keys.db')
        result = self.query(query, values, path)
        # filter out tokens when not called from the get_key method
        funcs = [funcname for (
            frame_obj, src_file, line, funcname, src_code, n
        ) in inspect.stack()]

        if type(result) is list and 'get_key' not in funcs:
            result = [x for x in result if not x[0].endswith('_token')]
        return result

    def _list_keys(self):
        self.logger.debug('')
        keys = self._query_keys('SELECT * FROM keys')
        tdata = []
        for key in sorted(keys):
            tdata.append(key)
        if tdata:
            self.table(tdata, header=['Name', 'Value'])

    # ==================================================
    # REQUEST METHODS
    # ==================================================
    def handle_req_exception(self, func, *args, **kwargs):
        return handle_request_exception(self, func, *args, **kwargs)

    def request(self, url, method='GET', timeout=None,
                payload=None, headers=None,
                cookiejar=None, auth=None,
                content='', redirect=True, agent=None):
        self.logger.debug('')
        request = Request()
        request.user_agent = agent or self._global_options['user-agent']
        request.debug = self._global_options['debug']
        request.proxy = self._global_options['proxy']
        request.timeout = timeout or self._global_options['timeout']
        request.redirect = redirect
        return request.send(
            url, method=method, payload=payload, headers=headers,
            cookiejar=cookiejar, auth=auth, content=content)

    # ==================================================
    # SHOW METHODS
    # ==================================================

    def show_modules(self, param):
        # process parameter according to type
        self.logger.debug('')
        if type(param) is list:
            modules = param
        elif param:
            modules = [
                x for x in Framework._loaded_modules if x.startswith(param)]
            if not modules:
                self.error('Invalid module category.')
                return
        else:
            modules = Framework._loaded_modules
        # display the modules
        # key_len = len(max(modules, key=len)) + len(self.spacer)
        last_category = ''
        for module in sorted(modules):
            category = module.split('/')[0]
            if category != last_category:
                # print header
                last_category = category
                self.heading(last_category)
            # print module
            print('%s%s' % (self.spacer*2, module))
        print('')

    def show_dashboard(self):
        self.logger.debug('')
        rows = self.query('SELECT * FROM dashboard ORDER BY 1')
        if rows:
            # display activity table
            tdata = []
            for row in rows:
                tdata.append(row)
            self.table(
                tdata,
                header=['Module', 'Runs'],
                title='Activity Summary')
            # display summary results table
            tables = self.get_tables()
            tdata = []
            for table in tables:
                count = self.query('SELECT COUNT(*) FROM "%s"' % (table))[0][0]
                tdata.append([table.title(), count])
            self.table(
                tdata,
                header=['Category', 'Quantity'],
                title='Results Summary')
        else:
            self.output('This workspace has no record of activity.')

    def show_schema(self):
        '''Displays the database schema'''
        self.logger.debug('')
        tables = self.get_tables()
        for table in tables:
            columns = self.get_columns(table)
            self.table(columns, title=table)

    def show_options(self, options=None):
        '''Lists options'''
        self.logger.debug('')
        if options is None:
            options = self.options
        if options:
            pattern = '%s%%s  %%s  %%s  %%s' % (self.spacer)
            key_len = len(max(options, key=len))
            if key_len < 4:
                key_len = 4
            val_len = len(
                max([self.to_unicode_str(options[x])
                     for x in options], key=len))
            if val_len < 13:
                val_len = 13
            print('')
            print(pattern % (
                'Name'.ljust(key_len),
                'Current Value'.ljust(val_len),
                'Required',
                'Description'))
            print(pattern % (
                self.ruler*key_len,
                (self.ruler*13).ljust(val_len),
                self.ruler*8,
                self.ruler*11))
            for key in sorted(options):
                value = options[key] if options[key] is not None else ''
                reqd = 'no' if options.required[key] is False else 'yes'
                desc = options.description[key]
                print(pattern % (
                    key.upper().ljust(key_len),
                    self.to_unicode_str(value).ljust(val_len),
                    self.to_unicode_str(reqd).ljust(8),
                    desc))
            print('')
        else:
            print('')
            print('%sNo options available for this module.' % (self.spacer))
            print('')

    def _get_show_names(self):
        self.logger.debug('')
        # Any method beginning with "show_" will be parsed
        # and added as a subcommand for the show command.
        prefix = 'show_'
        return [x[len(prefix):]
                for x in self.get_names() if x.startswith(prefix)]

    # ==================================================
    # COMMAND METHODS
    # ==================================================

    def do_exit(self, params):
        '''Exits the framework'''
        self.logger.debug('')
        self._exit = 1
        return True

    # alias for exit
    def do_back(self, params):
        '''Exits the current context'''
        self.logger.debug('')
        return True

    def do_set(self, params):
        '''Sets module options'''
        self.logger.debug('')
        options = params.split()
        if len(options) < 2:
            self.help_set()
            return
        name = options[0].lower()
        if name in self.options:
            value = ' '.join(options[1:])
            self.options[name] = value
            print('%s => %s' % (name.upper(), value))
            self._save_config(name)
        else:
            self.error('Invalid option.')

    def do_unset(self, params):
        '''Unsets module options'''
        self.logger.debug('')
        self.do_set('%s %s' % (params, 'None'))

    # ------------------
    # KEYS METHODS
    # ------------------
    def add_keys(self, params):
        """Add api keys"""
        if len(params) == 2:
            if self.add_key(params[0], params[1]):
                self.output('Key \'%s\' added.' % (params[0]))
        else:
            print('\nUsage: keys add <name> <value>\n')

    def del_keys(self, params):
        """Delete api keys"""
        if len(params) == 1:
            if self.delete_key(params[0]):
                self.output('Key \'%s\' deleted.' % (params[0]))
        else:
            print('\nUsage: keys delete <name>\n')

    def do_keys(self, params):
        '''Manages framework API keys'''
        self.logger.debug('')

        if not params:
            self.help_keys()
            return
        params = params.split()
        arg = params.pop(0).lower()

        if arg == 'list':
            self._list_keys()
        elif arg == 'add':
            self.add_keys(params)
        elif arg == 'delete':
            self.del_keys(params)
        else:
            self.help_keys()

    def do_query(self, params):
        '''Queries the database'''
        self.logger.debug('')
        if not params:
            self.help_query()
            return
        with sqlite3.connect(os.path.join(self.workspace, 'data.db')) as conn:
            with closing(conn.cursor()) as cur:
                self.debug('QUERY => %s' % (params))
                try:
                    cur.execute(params)
                except sqlite3.OperationalError as e:
                    self.error(
                        'Invalid query. %s %s' % (type(e).__name__, e.message))
                    return
                if cur.rowcount == -1 and cur.description:
                    tdata = cur.fetchall()
                    if not tdata:
                        self.output('No data returned.')
                    else:
                        header = tuple([x[0] for x in cur.description])
                        self.table(tdata, header=header)
                        self.output('%d rows returned' % (len(tdata)))
                else:
                    conn.commit()
                    self.output('%d rows affected.' % (cur.rowcount))

    def do_show(self, params):
        '''Shows various framework items'''
        self.logger.debug('')
        if not params:
            self.help_show()
            return
        _params = params
        params = params.lower().split()
        arg = params[0]
        params = ' '.join(params[1:])
        if arg in self._get_show_names():
            func = getattr(self, 'show_' + arg)
            if arg == 'modules':
                func(params)
            else:
                func()
        elif _params in self.get_tables():
            self.do_query('SELECT ROWID, * FROM "%s"' % (_params))
        else:
            self.help_show()

    def parse_table_values(self, params):
        """prase table and values"""
        # params = table + ' ' + values
        table = ''
        values = ''

        for t in self.get_tables():
            if params.startswith(t):
                table = t
                values = params[len(t) + 1:]
                break
        return (table, values)

    def avoid_builtins(self, name):
        """sanitize column names to avoid conflicts with builtins"""
        if name in ['hash', 'type']:
            name = '_%s' % name

        return name

    def create_table_records(self, columns, values):
        """"""
        record = {}
        if len(columns) == len(values):
            for i in range(0, len(columns)):
                key = self.avoid_builtins(columns[i][0])
                record[key] = values[i]
        else:
            for (column_name, column_type) in columns:
                try:
                    key = self.avoid_builtins(column_name)
                    value = raw_input('%s (%s): ' % (column_name, column_type))
                    record[key] = value
                except KeyboardInterrupt:
                    print('')
                    return
                finally:
                    # ensure proper output for resource scripts
                    if Framework._script:
                        print('%s' % (value))

        return record

    def do_add(self, params):
        '''Adds records to the database'''
        self.logger.debug('')

        if not params:
            self.help_add()
            return

        (table, values) = self.parse_table_values(params)

        if not table:
            self.error('table is inavailable')
            return

        if not hasattr(self, 'add_%s' % table):
            self.error('Please show schema for details.')
            return

        columns = [x for x in self.get_columns(table) if x[0] != 'module']
        values = values.split('~')

        record = self.create_table_records(columns, values)

        # add record to the database
        func = getattr(self, 'add_' + table)
        func(**record)

    def do_delete(self, params):
        '''Deletes records from the database'''
        self.logger.debug('')
        table = ''
        # search params for table names
        for table_name in self.get_tables():
            if params.startswith(table_name):
                params = params[len(table_name)+1:]
                table = table_name
                break
        if table:
            # get rowid from parameters
            if params:
                rowids = self._parse_rowids(params)
            # get rowid from interactive input
            else:
                try:
                    # prompt user for data
                    params = raw_input('rowid(s) (INT): ')
                    rowids = self._parse_rowids(params)
                except KeyboardInterrupt:
                    print('')
                    return
                finally:
                    # ensure proper output for resource scripts
                    if Framework._script:
                        print('%s' % (params))
            # delete record(s) from the database
            for rowid in rowids:
                self.query('DELETE FROM %s WHERE ROWID IS ?' % (table),
                           (rowid,))
        else:
            self.help_delete()

    def do_search(self, params):
        '''Searches available modules'''
        self.logger.debug('')
        if not params:
            self.help_search()
            return
        text = params.split()[0]
        self.output('Searching for \'%s\'...' % (text))
        modules = [x for x in Framework._loaded_modules if text in x]
        if not modules:
            self.error('No modules found containing \'%s\'.' % (text))
        else:
            self.show_modules(modules)

    def record_start(self, arg):
        """starts to record commands to file"""
        if Framework._record:
            self.output('Recording is already started.')
        else:
            if len(arg.split()) > 1:
                filename = ' '.join(arg.split()[1:])
                Framework._record = self.open_file(filename, mode='ab')
                self.output('Recording to \'%s\'.' % (Framework._record.name))
            else:
                self.help_record()

    def record_stop(self):
        """stops to record commands to file"""
        if Framework._record:
            self.output('Stop recording to \'%s\'.' % (Framework._record))
            Framework._record = None
        else:
            self.output('Recording is already stopped.')

    def record_status(self):
        status = 'started' if Framework._record else 'stopped'
        self.output('Command recording is %s.' % (status))

    def do_record(self, params):
        '''Records commands to a resource file'''
        self.logger.debug('')
        if not params:
            self.help_record()
            return

        arg = params.lower()
        if arg.split()[0] == 'start':
            self.record_start(arg)
        elif arg == 'stop':
            self.record_stop()
        elif arg == 'status':
            self.record_status()
        else:
            self.help_record()

    def spool_start(self, arg):
        """starts to write outout to file"""
        if Framework._spool:
            self.output('Spooling is already started.')
        else:
            if len(arg.split()) > 1:
                filename = ' '.join(arg.split()[1:])
                Framework._spool = self.open_file(filename, mode='ab')
                self.output('Spooling to \'%s\'.' % (Framework._spool.name))
            else:
                self.help_spool()

    def spool_stop(self):
        """stops to write outout to file"""
        if Framework._spool:
            self.output('Spooling stopped. Output saved to \'%s\'.' % (
                Framework._spool.name))
            Framework._spool = None
        else:
            self.output('Spooling is already stopped.')

    def spool_status(self):
        """spool status"""
        status = 'started' if Framework._spool else 'stopped'
        self.output('Output spooling is %s.' % (status))

    def do_spool(self, params):
        '''Spools output to a file'''
        self.logger.debug('')
        if not params:
            self.help_spool()
            return

        arg = params.lower()
        if arg.split()[0] == 'start':
            self.spool_start(arg)
        elif arg == 'stop':
            self.spool_stop()
        elif arg == 'status':
            self.spool_status()
        else:
            self.help_spool()

    def do_shell(self, params):
        '''Executes shell commands'''
        self.logger.debug('')
        proc = subprocess.Popen(
            params, shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE)
        self.output('Command: %s' % (params))
        stdout = proc.stdout.read()
        stderr = proc.stderr.read()
        if stdout:
            print('%s%s%s' % (Colors.O, stdout, Colors.N), end='')
        if stderr:
            print('%s%s%s' % (Colors.R, stderr, Colors.N), end='')

    def do_resource(self, params):
        '''Executes commands from a resource file'''
        self.logger.debug('')
        if not params:
            self.help_resource()
            return
        if os.path.exists(params):
            sys.stdin = open(params)
            Framework._script = 1
        else:
            self.error('Script file \'%s\' not found.' % (params))

    def do_load(self, params):
        '''Loads selected module'''
        self.logger.debug('')
        if not params:
            self.help_load()
            return
        # finds any modules that contain params
        if params in Framework._loaded_modules:
            modules = [params]
        else:
            modules = [x for x in Framework._loaded_modules if params in x]

        # notify the user if none or multiple modules are found
        if len(modules) != 1:
            if not modules:
                self.error('Invalid module name.')
            else:
                self.output('Multiple modules match \'%s\'.' % params)
                self.show_modules(modules)
            return
        import StringIO
        # compensation for stdin being used for scripting and loading
        if Framework._script:
            end_string = sys.stdin.read()
        else:
            end_string = 'EOF'
            Framework._load = 1
        sys.stdin = StringIO.StringIO('load %s\n%s' % (modules[0], end_string))
        return True
    do_use = do_load

    def do_pdb(self, params):
        '''Starts a Python Debugger session'''
        self.logger.debug('')
        import pdb
        pdb.set_trace()

    # ==================================================
    # HELP METHODS
    # ==================================================

    def help_keys(self):
        self.logger.debug('')
        print(getattr(self, 'do_keys').__doc__)
        print('')
        print('Usage: keys [list|add|delete]')
        print('')

    def help_load(self):
        self.logger.debug('')
        print(getattr(self, 'do_load').__doc__)
        print('')
        print('Usage: [load|use] <module>')
        print('')
    help_use = help_load

    def help_record(self):
        self.logger.debug('')
        print(getattr(self, 'do_record').__doc__)
        print('')
        print('Usage: record [start <filename>|stop|status]')
        print('')

    def help_spool(self):
        self.logger.debug('')
        print(getattr(self, 'do_spool').__doc__)
        print('')
        print('Usage: spool [start <filename>|stop|status]')
        print('')

    def help_resource(self):
        self.logger.debug('')
        print(getattr(self, 'do_resource').__doc__)
        print('')
        print('Usage: resource <filename>')
        print('')

    def help_query(self):
        self.logger.debug('')
        print(getattr(self, 'do_query').__doc__)
        print('')
        print('Usage: query <sql>')
        print('')
        print('SQL examples:')
        print('%s%s' % (
            self.spacer, 'SELECT columns|* FROM table_name'))
        print('%s%s' % (
            self.spacer,
            'SELECT columns|* FROM table_name WHERE some_column=some_value'))
        print('%s%s' % (
            self.spacer,
            'DELETE FROM table_name WHERE some_column=some_value'))
        print('%s%s' % (
            self.spacer,
            ('INSERT INTO table_name (column1, column2,...) '
             'VALUES (value1, value2,...)')))
        print('%s%s' % (
            self.spacer,
            'UPDATE table_name SET column1=value1, column2=value2,... '
            'WHERE some_column=some_value'))
        print('')

    def help_search(self):
        self.logger.debug('')
        print(getattr(self, 'do_search').__doc__)
        print('')
        print('Usage: search <string>')
        print('')

    def help_set(self):
        self.logger.debug('')
        print(getattr(self, 'do_set').__doc__)
        print('')
        print('Usage: set <option> <value>')
        self.show_options()

    def help_unset(self):
        self.logger.debug('')
        print(getattr(self, 'do_unset').__doc__)
        print('')
        print('Usage: unset <option>')
        self.show_options()

    def help_shell(self):
        self.logger.debug('')
        print(getattr(self, 'do_shell').__doc__)
        print('')
        print('Usage: [shell|!] <command>')
        print('...or just type a command at the prompt.')
        print('')

    def help_show(self):
        self.logger.debug('')
        options = sorted(self._get_show_names() + self.get_tables())
        print(getattr(self, 'do_show').__doc__)
        print('')
        print('Usage: show [%s]' % ('|'.join(options)))
        print('')

    def help_add(self):
        self.logger.debug('')
        print(getattr(self, 'do_add').__doc__)
        print('')
        print('Usage: add <table> [values]')
        print('')
        print('optional arguments:')
        print('%svalues => \'~\' delimited string representing column values '
              '(exclude rowid, module)' % (self.spacer))
        print('')

    def help_delete(self):
        self.logger.debug('')
        print(getattr(self, 'do_delete').__doc__)
        print('')
        print('Usage: delete <table> [rowid(s)]')
        print('')
        print('optional arguments:')
        print('%srowid(s) => \',\' delimited values or \'-\' delimited ranges '
              'representing rowids' % (self.spacer))
        print('')

    # ==================================================
    # COMPLETE METHODS
    # ==================================================

    def complete_keys(self, text, line, *ignored):
        self.logger.debug('')
        args = line.split()
        options = ['list', 'add', 'delete']
        if 1 < len(args) < 4:
            if args[1].lower() in options[1:]:
                return [x[0] for x in self._query_keys('SELECT name FROM keys')
                        if x[0].startswith(text)]
            if args[1].lower() in options[:1]:
                return []
        return [x for x in options if x.startswith(text)]

    def complete_load(self, text, *ignored):
        self.logger.debug('')
        return [x for x in Framework._loaded_modules if x.startswith(text)]
    complete_use = complete_load

    def complete_record(self, text, *ignored):
        self.logger.debug('')
        return [x for x in ['start', 'stop', 'status'] if x.startswith(text)]
    complete_spool = complete_record

    def complete_set(self, text, *ignored):
        self.logger.debug('')
        return [x.upper() for x in self.options
                if x.upper().startswith(text.upper())]
    complete_unset = complete_set

    def complete_show(self, text, line, *ignored):
        self.logger.debug('')
        args = line.split()
        if len(args) > 1 and args[1].lower() == 'modules':
            if len(args) > 2:
                return [x for x in Framework._loaded_modules
                        if x.startswith(args[2])]
            else:
                return [x for x in Framework._loaded_modules]
        options = sorted(self._get_show_names() + self.get_tables())
        return [x for x in options if x.startswith(text)]

    def complete_add(self, text, *ignored):
        self.logger.debug('')
        tables = sorted(self.get_tables())
        return [x for x in tables if x.startswith(text)]
    complete_delete = complete_add
