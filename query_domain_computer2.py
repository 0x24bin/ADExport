#!/usr/bin/env python

import os
import sys
import re
import time
import sqlite3
import logging
from datetime import datetime, timedelta, tzinfo
from calendar import timegm
from dnslib import DNSHelper
from optparse import OptionParser

reload(sys)
sys.setdefaultencoding('utf8')

dnsRoot = '.example.com'
dnsServers = [] # (ip1,53),(ip2,53)
dnsTimeout = 1.5
codePage = 'gbk'
queryLimit = 0 # 0 means unlimited
netPrefix = ''
logger = None

class xapp:
    @staticmethod
    def init_logger(logfile, level=logging.INFO):
        logger = logging.getLogger()
        hdlr = logging.FileHandler(logfile)
        formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        hdlr.setFormatter(formatter)
        logger.addHandler(hdlr)
        logger.setLevel(level)
        return logger

# http://support.microsoft.com/kb/167296
# How To Convert a UNIX time_t to a Win32 FILETIME or SYSTEMTIME
EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
HUNDREDS_OF_NANOSECONDS = 10000000
ZERO = timedelta(0)
HOUR = timedelta(hours=1)
class UTC(tzinfo):
    def utcoffset(self, dt):
        return ZERO

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return ZERO
    
utc = UTC()
def dt_to_filetime(dt):
    if (dt.tzinfo is None) or (dt.tzinfo.utcoffset(dt) is None):
        dt = dt.replace(tzinfo=utc)
    ft = EPOCH_AS_FILETIME + (timegm(dt.timetuple()) * HUNDREDS_OF_NANOSECONDS)
    return ft + (dt.microsecond * 10)

def filetime_to_dt(ft):
    # Get seconds and remainder in terms of Unix epoch
    (s, ns100) = divmod(ft - EPOCH_AS_FILETIME, HUNDREDS_OF_NANOSECONDS)
    # Convert to datetime object
    dt = datetime.utcfromtimestamp(s)
    # Add remainder in as microseconds. Python 3.2 requires an integer
    dt = dt.replace(microsecond=(ns100 // 10))
    return dt

def convert_time(s):
    #06/20/2017 03:15:04 -> 2017-06-20 03:15:04
    i = s.find(' ')
    if i>0:
        m = s[0:i].split('/')
        if len(m)==3:
            return '%s-%s-%s%s' % (m[2],m[0],m[1], s[i:])
    return s

class AdExporter:
    global logger
    def get_hostaddr(self, name):
        helper = DNSHelper(dnsServers)
        addrs = helper.resolv_addr(name, dnsTimeout)
        return addrs

    def parse_dc(self, hn, dn):
        str1='CN=Servers,CN='
        str2=',CN=Sites,'
        idx1=dn.find(str1)
        idx2=dn.find(str2)
        if idx1<0 or idx2<idx1:
            return None
        site = dn[idx1+len(str1):idx2]
        if hn[-len(dnsRoot):].lower()!=dnsRoot:
            return None
        
        hs = hn[0:-len(dnsRoot)].split('.')
        subd = ''
        hname = ''
        addr = ''
        if len(hs)>1:
            subd = hs[-1]
            hname = '.'.join(hs[0:-1])
        elif hs:
            hname = hs[0]
            
        addrs = self.get_hostaddr(hn)
        if addrs and addrs[0]:
            addr = addrs[0]
        return (site, subd, hname, addr)

    def get_dc(self, server=None, user=None, passwd=None):
        dsquery = 'dsquery.exe * forestroot -attr "cn" "distinguishedName" "dNSHostName" "whenCreated" "whenChanged" -filter "(&(objectclass=server)(objectcategory=server))" -q -L -limit 0'
        if server and user and passwd:
            dsquery += ' -s %s -u %s -p %s' % (server, user, passwd)
        logger.info( 'cmd: %s' % (dsquery) )

        servers = []
        output = os.popen(dsquery)
        lines = output.read().decode(codePage).encode('utf-8') ##ATTENTION: CODING PAGE
        
        for oo in lines.replace('\r','').split('cn: '):
            o = oo.strip().split('\n')
            if len(o)!=5:
                continue
            dn = o[1].replace('distinguishedName: ','')
            hn = o[2].replace('dNSHostName: ','')
            rs = self.parse_dc(hn,dn)
            if rs:
                servers.append( [
                    dnsRoot.strip('.'),
                    hn, dn,
                    convert_time( o[3].replace('whenCreated: ','') ),
                    convert_time( o[4].replace('whenChanged: ','') ),
                    rs[0], rs[1], rs[2], rs[3] ]
            )
        return servers

    def get_computers(self, server='', user='', passwd='', subdom=''):
        days_before = 25
        ts = datetime.fromtimestamp(time.time()-3600*24*days_before)
        attrs='"cn" "distinguishedName" "dNSHostName" "whenCreated" "lastLogonTimestamp" "lastLogon" "objectGUID" "operatingSystem" "operatingSystemServicePack" "operatingSystemVersion" "description"'
        timestamp= '%u' % dt_to_filetime(ts)
        
        params = ' -q -L -limit ' + str(queryLimit)
        if subdom:
            params += ' -domain %s' % (subdom)
        if server and user and passwd:
            params += ' -s %s -u %s -p %s' % (server, user, passwd)
            
        filters='"(&(objectclass=computer)(objectcategory=computer)(lastLogonTimeStamp>='+timestamp+')(!userAccountControl:1.2.840.113556.1.4.803:=2))"'
        dsquery='dsquery.exe * -attr %s -filter %s %s' % (attrs, filters, params)
        logger.info( 'cmd: %s' % (dsquery) )
        
        output = os.popen(dsquery)
        ostr = output.read()
        try:
            lines = ostr.decode(codePage).encode('utf-8') ##ATTENTION: CODING PAGE
        except Exception as e:
            logger.error('decode: %s, %r' %(str(e), ostr))
            raise
        results = []
        for oo in lines.replace('\r','').split('cn: '):
            o = oo.strip().split('\n')
            if len(o)!=11:
                continue
            lastLogonTs = o[4].replace('lastLogonTimestamp: ','')
            lastLogon = o[5].replace('lastLogon: ','')
            if lastLogon<lastLogonTs:
                lastLogon = lastLogonTs
            try:
                lastLogonTime = filetime_to_dt(long(lastLogon)).strftime('%Y-%m-%d %H:%M:%S')
            except:
                lastLogonTime = ''
            guid = o[6].replace('objectGUID: ','')[1:-1].replace('-','')
            results.append([
                dnsRoot.strip('.'),
                o[0],
                subdom,
                o[1].replace('distinguishedName: ',''),
                o[2].replace('dNSHostName: ','').strip('.'),###dNSHostName
                convert_time( o[3].replace('whenCreated: ','') ),
                lastLogonTime,
                guid,              
                o[7].replace('operatingSystem: ',''),
                o[8].replace('operatingSystemServicePack: ',''),
                o[9].replace('operatingSystemVersion: ',''),
                o[10].replace('description:','').strip().replace('\t',' '),
                '', #ipaddr
                '*', #ipaddr2
            ])
        return results

    def save_addrs(self, names, computers, resolved):
        global netPrefix
        for n,a in resolved.items():
            i = names.get(n,-1)
            if i>=0:
                if a:
                    ip = ''
                    b = set()
                    if netPrefix:
                        for x in a:
                            if x.find(netPrefix)==0 and not ip:
                                ip = x
                            else:
                                b.add(x)
                    else:
                        ip = a[0]
                        b = a[1:]
                    computers[i][-2]=ip
                    computers[i][-1]='|'.join(list(b))
                elif computers[i][-1]=='*':
                    computers[i][-1]==''
                
    def resolv_addrs(self, subdom, computers, servers):
        dns = set()
        for s in servers:
            if s[6] == subdom and s[8]:
                dns.add(s[8])
        if len(dns)==0:
            for s in dnsServers:
                dns.add(s[0])
                
        names = dict()
        for i in xrange(len(computers)):
            names[computers[i][4].lower()] = i

        helper = DNSHelper([])
        resolved = helper.resolv_parallel(names=set(names.keys()), servers=list(dns), speed=1000, logger=logger)
        self.save_addrs(names, computers, resolved)
        
        if len(names)-len(resolved)>3:
            for s in dnsServers:
                dns.add(s[0])
            lefts = set()
            for n in names:
                if n not in resolved:
                    lefts.add(n)
            resolved2 = helper.resolv_parallel(names=lefts, servers=list(dns), speed=1000, logger=logger)
            logger.info('re-sent %d names, %d resolved' % (len(lefts), len(resolved2)))
            self.save_addrs(names, computers, resolved2)
            
            lefts2 = set()
            for n in lefts:
                if n not in resolved2:
                    lefts2.add(n)
            if len(lefts2)<3:
                return
            resolved3 = helper.resolv_parallel(names=lefts2, servers=list(dns), speed=1000, logger=logger)
            logger.info('re-sent %d names, %d resolved' % (len(lefts2), len(resolved3)))
            self.save_addrs(names, computers, resolved3)
            
        ##
        ## DONE ##
        ##
        
class datawriter:
    global logger
    isql = '''
         CREATE TABLE IF NOT EXISTS controllers (
                id INT PRIMARY KEY,
                dnsroot TEXT NOT NULL,
                dnsname TEXT NOT NULL,
                distname TEXT NOT NULL,
                created TEXT NOT NULL,
                changed TEXT NOT NULL,
                site TEXT NOT NULL,
                subdomain TEXT NOT NULL,
                hostname TEXT NOT NULL,
                ipaddr TEXT NOT NULL,
                ctime TEXT NOT NULL);
                
        CREATE TABLE IF NOT EXISTS computers (
                id INT PRIMARY KEY,
                dnsroot TEXT NOT NULL,
                cname TEXT NOT NULL,
                subdomain TEXT NOT NULL,
                distname TEXT NOT NULL,
                dnsname TEXT NOT NULL,
                created TEXT NOT NULL,
                lastlogon TEXT NOT NULL,
                guid TEXT NOT NULL,
                osname TEXT NOT NULL,
                osspx TEXT NOT NULL,
                osver TEXT NOT NULL,
                descri TEXT NOT NULL,
                ipaddr TEXT NOT NULL,
                ipaddr2 TEXT NOT NULL,
                ctime TEXT NOT NULL);
        '''

    def __init__(self, datafile):
        self.conn = sqlite3.connect(datafile)
        self.conn.text_factory = str
        self.cur = self.conn.cursor()
        self.cur.executescript(datawriter.isql)
        
    def save_dc(self, data):
        if len(data)>0:
            try:
                now = int(time.time())
                sql = 'INSERT OR IGNORE INTO controllers(dnsroot,dnsname,distname,created,changed,site,subdomain,hostname,ipaddr,ctime) \
                        VALUES(?,?,?,?,?,?,?,?,?,'+str(now)+')'
                self.cur.executemany(sql, data)
                self.conn.commit()
            except Exception as e:
                logger.error ( 'dw.save_dc: %s' % (str(e)) )
        else:
            logger.info( '!dw.save_dc: no data.' )

    def save_computers(self, data):
        if len(data)>0:
            try:
                now = int(time.time())
                sql = 'INSERT OR IGNORE INTO computers(dnsroot,cname,subdomain,distname,dnsname,created,lastlogon,guid,osname,osspx,osver,descri,ipaddr,ipaddr2,ctime)\
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,'+str(now)+')'
                self.cur.executemany(sql, data)
                self.conn.commit()
            except Exception as e:
                logger.error ( 'dw.save_computers: %s' % (str(e)) )
        else:
            logger.info( '!dw.save_computers: no data.' )    
            
    def close(self):
        self.conn.close()



def main():
    global dnsRoot,dnsServers,dnsTimeout,codePage,logger
    global netPrefix
    options = OptionParser(usage='%prog [options]', description='query_domain_computer.py')
    options.add_option('-r', '--root', type='string', default='', help='dns root(eg: example.com)')
    options.add_option('-n', '--nameserver', type='string', default='', help='name servers(eg: 8.8.4.4,8.8.8.8)')
    options.add_option('-t', '--timeout', type='float', default=1.5, help='dns query timeout seconds(default: 1.5s)')
    options.add_option('-s', '--server', type='string', default='', help='domain controler dsquery to connect')
    options.add_option('-u', '--user', type='string', default='', help='username dsquery to login server')
    options.add_option('-p', '--password', type='string', default='', help='password for user')
    options.add_option('-a', '--all', type='int', default=1, help='include all sub domains(default: 1)')
    options.add_option('-d', '--database', type='string', default='adinfo.db', help='database file(default: adinfo.db)')
    options.add_option('-c', '--codepage', type='string', default='gbk', help='data codepage(default: gbk)')
    options.add_option('-l', '--logfile', type='string', default='adquery.log', help='logfile name(default: adquery.log)')
    options.add_option('-w', '--network', type='string', default='', help='network prefix')
    
    opts, args = options.parse_args()
    if not opts.root or not opts.nameserver:
        options.print_help()
        return -1
    logger = xapp.init_logger(opts.logfile)
    
    dw = datawriter(opts.database)
    
    dnsRoot = '.'+opts.root.lower().strip('.')
    dnsServers = [(s.strip(),53) for s in opts.nameserver.split(',')]
    dnsTimeout = opts.timeout
    codePage = opts.codepage
    netPrefix = opts.network
    
    aex = AdExporter()
    servers = aex.get_dc(opts.server, opts.user, opts.password)

    dw.save_dc(servers)
    if opts.all:
        subdoms = sorted(set([s[6] for s in servers]))
    else:
        subdoms = ['']

    for subdom in subdoms:
        computers = aex.get_computers(opts.server, opts.user, opts.password, subdom)
        if len(computers)>0:
            aex.resolv_addrs(subdom, computers, servers)
            dw.save_computers(computers)
    dw.close()
    logger.info('main: export done.')
if __name__=='__main__':
    main()
    
