from recon.core.module import BaseModule

import urlparse
import codecs
import sqlite3
import os


class Module(BaseModule):

    authors = []
    svnurls = []
    svndirs = []
    prevurl = ""
    svnhost = ""

    meta = {
        'name': 'svn entries dumper',
        'author': 'Vex Woo (@Nixawk)',
        'description': 'find (.svn/entries) and (wc.db) svn disclosure',
        'comments': (
            'Files: .svn/entries, .svn/wc.db',
            'Google Dorks:',
            '\tinurl:.svn/entries',
            '\tinurl:.svn/wc.db ext:db'
        ),
        'options': (
            ('url', 'http://www.demo.com', True, 'target host'),
            ('svn_entries', True, True, 'dump .svn/entries records'),
            ('svn_wcdb', False, True, 'dump wc.db records')
        )
    }

    def module_run(self):
        url = self.options['url']
        entries = self.options['svn_entries']
        wcdb = self.options['svn_wcdb']
        output = "%s%s%s" % (
            self.workspace, os.sep, self._modulename.split('/')[-1])

        self.output("svn entries save in %s" % output)

        try:
            if entries:
                self.entries(url, output)

            if wcdb:
                self.wcdb(url, output)

        except KeyboardInterrupt:
            raise KeyboardInterrupt
        except:
            pass

    def createdir(self, dir):
        """create direcroty if it does not exists
        """
        self.debug("createdir")
        if not os.path.exists(dir):
            os.makedirs(dir)

        return dir

    def savefile(self, filepath, data):
        """write data to local file
        """
        self.debug("savefile")
        self.output("save file %s" % filepath)

        self.createdir(os.path.dirname(filepath))

        with codecs.open(filepath, 'w', 'utf-8') as f:
            f.write(data)

    def saveinfo(self, output):
        """save svn self.authors/entries
        """
        self.debug("saveinfo")
        self.savefile("%s/%s/developer.txt" % (output, self.svnhost),
                      "\n".join(self.authors))
        self.savefile("%s/%s/svn_entries.txt" % (output, self.svnhost),
                      "\n".join(self.svnurls))

    def svn_host(self, url):
        """parse url to a host/domain
        """
        self.debug("svn_host")

        if not self.prevurl:
            self.prevurl = url
            self.svnhost = urlparse.urlparse(self.prevurl).netloc

        return self.svnhost, self.prevurl

    def svn_authors(self, author):
        """svn self.authors handler
        """
        self.debug("svn_authors")
        if author not in self.authors:
            self.output("Author: %s" % author)
            self.authors.append(author)

        return self.authors

    def svn_files(self, url, filename, output):
        """svn files handler
        """
        self.debug("svn_files")
        if filename:
            svn_url = "%s/.svn/text-base/%s.svn-base" % (url, filename)
            svn_path = "%s/%s" % (url, filename)

            if svn_url not in self.svnurls:
                svn_data = self.request(svn_url).text
                svn_path = svn_path.replace(self.prevurl,
                                            "%s/%s" % (output, self.svnhost))
                svn_path = svn_path.replace(".svn-base", "")
                # download svn file
                self.savefile(svn_path, svn_data)
                self.svnurls.append(svn_url)

        return self.svnurls

    def svn_dirs(self, url, dirname):
        """svn dir handler
        """
        self.debug("svn_dirs")
        if dirname:
            svn_dir = "%s/%s" % (url, dirname)

            if svn_dir not in self.svndirs:
                self.output(svn_dir)
                self.svndirs.append(svn_dir)
                self.entries(svn_dir)

        return self.svndirs

    def entries(self, url, output):
        """dump .svn/rntries records
        """
        self.debug("svn entries dump")

        svnentries = "%s/.svn/entries" % url
        self.output(svnentries)

        resp = self.request(svnentries)
        prev_line = ""

        self.svn_host(url)

        if resp.status_code != 200:
            self.output("(%s) - %s" % (resp.status_code, url))
        else:
            self.output(url)

            for line in resp.text.splitlines():
                # svn - code developer
                if line == "has-props":
                    self.svn_self.authors(prev_line)

                # svn - source code file
                elif line == "file":
                    self.svn_files(url, prev_line, output)

                # svn - svn dir
                elif line == "dir":
                    self.svn_dirs(url, prev_line)

                prev_line = line

            # save svn developers / dirs information
            self.saveinfo(output)

        return self.authors, self.svnurls, self.svndirs

    def read_wcdb(self, dbfile):
        """read svn entries and self.authors from local wc.db
        """
        self.debug("read_wcdb")
        conn = sqlite3.connect(dbfile)
        c = conn.cursor()

        sql = ('select local_relpath, ".svn/pristine/"'
               ' || substr(checksum,7,2) || "/" || '
               'substr(checksum,7) || ".svn-base" '
               'as alpha from NODES where kind="file";')

        c.execute(sql)
        svn_entries = c.fetchall()

        # developer / self.authors
        sql = 'select distinct changed_author from nodes;'
        c.execute(sql)
        self.authors = [r[0] for r in c.fetchall()]

        c.close()

        return svn_entries, self.authors

    def wcdb_authors(self, authors):
        """handle authos in wc.db
        """
        self.debug("wcdb_authors")
        for author in authors:
            if author[0] not in self.authors:
                self.authors.append(author[0])

        return self.authors

    def wcdb_entries(self, url, entries, output):
        """wc.db entries handler
        """
        self.debug("wcdb_entries")
        for local_relpath, alpha in entries:
            if local_relpath and alpha:
                svn_url = "%s/%s" % (url, alpha)
                svn_path = "%s/%s" % (url, local_relpath)

                if svn_url not in self.svnurls:
                    self.svnurls.append(svn_url)
                    svn_data = self.request(svn_url).text
                    svn_path = svn_path.replace(
                        self.prevurl, "%s/%s" % (output, self.svnhost))
                    svn_path = svn_path.replace(".svn-base", "")
                    self.savefile(svn_path, svn_data)
                    self.svnurls.append(svn_url)

        return self.svnurls

    def wcdb(self, url, output):
        """get svn entries from remote wc.db
        """
        self.debug("wcdb")
        wcdburl = "%s/.svn/wc.db" % url
        self.output(wcdburl)
        resp = self.request(wcdburl)

        self.svn_host(url)

        if resp.status_code != 200:
            self.output("(%s) - %s" % (resp.status_code, url))
        else:
            wcdb_data = self.request(url).raw
            wcdb_path = url.replace(
                self.prevurl, "%s/%s/wc.db" % (output, self.svnhost))
            self.savefile(wcdb_path, wcdb_data)

            svn_entries, self.authors = self.read_wcdb(wcdb_path)

            self.wcdb_self.authors(self.authors)
            self.wcdb_entries(url, svn_entries)

        self.saveinfo(output)

        return self.authors, self.svnurls, self.svndirs
