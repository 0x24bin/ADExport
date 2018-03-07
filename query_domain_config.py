#!/usr/bin/env python
#coding: gbk
import os,sys,time,re
from datetime import datetime, timedelta, tzinfo
from calendar import timegm
from dnslib import DNSHelper
from optparse import OptionParser

dnsRoot = '.example.com'
dnsServers = [] # (ip1,53),(ip2,53)
dnsTimeout = 1.5

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

def get_hostaddr(name):
    helper = DNSHelper(dnsServers)
    addrs = helper.resolv_addr(name, dnsTimeout)
    return addrs

def parse_dc(hn,dn):
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

    addrs = get_hostaddr(hn.decode('gb2312').encode('utf-8'))
    if addrs and addrs[0]:
        addr = addrs[0]
    return (site, subd, hname, addr)

def get_dc(server=None, user=None, passwd=None):
    dsquery = 'dsquery.exe * forestroot -attr "cn" "distinguishedName" "dNSHostName" "whenCreated" "whenChanged" -filter "(&(objectclass=server)(objectcategory=server))" -q -L -limit 0'
    if server and user and passwd:
        dsquery += ' -s %s -u %s -p %s' % (server, user, passwd)
    print dsquery

    servers = []
    output = os.popen(dsquery)
    lines = output.read()
    for oo in lines.replace('\r','').split('cn: '):
        o = oo.strip().split('\n')
        if len(o)!=5:
            continue
        dn = o[1].replace('distinguishedName: ','')
        hn = o[2].replace('dNSHostName: ','')
        rs = parse_dc(hn,dn)
        if rs:
            servers.append( [hn, dn,
            o[3].replace('whenCreated: ',''),
            o[4].replace('whenChanged: ',''),
            rs[0], rs[1], rs[2], rs[3] ]
        )
    return servers


def parse_member(lines):
    o = {'sAMAccountName':'', 'sAMAccountType':'', 'userAccountControl':'', 'userPrincipalName':'', 'member':[], 'objectCategory':'', 'lastLogon':'', 'whenCreated':'', 'whenChanged':'', 'description':'', 'group':False,
         'accountStatus':'','isInAdAdmin':'N/A', }
    for ln in lines.strip().replace('\r','').split('\n'):
        idx = ln.find(': ')
        if idx<=0:
            continue
        k = ln[0:idx].strip()
        v = ln[idx+2:].strip()
        if k=='member':
            o[k].append(v)
        elif k=='lastLogon' and len(v)>6:
            o[k] = filetime_to_dt(long(v)).strftime('%m/%d/%Y %H:%M:%S')
        else:
            o[k] = v
    if o['objectCategory'].find('CN=Group')>=0:
        o['group'] = True
    if not o['objectCategory']:
        o = None
    return o

visted = dict()
def get_admins(server='', user='', passwd='', subdom=''):
    global visted
    
    params = ' -q -L -limit 0'
    if subdom:
        params += ' -domain %s' % (subdom)
    if server and user and passwd:
        params += ' -s %s -u %s -p %s' % (server, user, passwd)
        
    dsquery = 'dsquery.exe * -attr "sAMAccountName" "sAMAccountType" "userPrincipalName" "userAccountControl" "objectCategory" "member" "lastLogon" "whenCreated" "whenChanged" "description" -filter "(&(objectSid=S-1-5-32-544))"'
    dsquery += params
    print dsquery

    rs = {}
    output = os.popen(dsquery)
    lines = output.read()
    oo = parse_member(lines)

    k = '%sS-1-5-32-544' % (subdom+'_' if subdom else '')
    rs[k] = oo
    visted[k] = oo

    queues = []
    if oo and oo['member']:
        queues += oo['member']
    while len(queues)>0:
        dn = queues.pop()
        if dn in visted and dn.find('CN=Domain Admins')<0:
            rs[dn] = visted[dn]
            continue
        dsquery = 'dsquery.exe * "%s" -attr "sAMAccountName" "sAMAccountType" "userPrincipalName" "userAccountControl" "objectCategory" "member" "lastLogon" "whenCreated" "whenChanged" "description"' % (dn)
        dsquery += params
        print dsquery
        
        output = os.popen(dsquery)
        lines = output.read()
        oo =  parse_member(lines)
        if not oo:
            visted[dn] = None
            continue
        rs[dn] = oo
        visted[dn] = oo
        if oo['member']:
            queues += oo['member']
    return rs

def save_dc(servers, path):
    header='"dNSHostName","distinguishedName","whenCreated","whenChanged","siteName","subDomain","hostName","iPAddr"'
    fw = open(path, 'wb')
    fw.write(header+'\r\n')
    for s in servers:
        fw.write('"%s"\r\n' % ('","'.join(s)))
    fw.close()

def get_type(val):
    typs = []
    try:
        ival = long(val)
        if (ival==0):
            typs.append('DOMAIN')
        elif (ival==0x10000000):
            typs.append('GROUP')
        elif (ival==0x20000000):
            typs.append('ALIAS')
        elif (ival==0x30000000):
            typs.append('USER')
        elif (ival==0x30000000):
            typs.append('NORMALUSER')
        elif (ival==0x30000001):
            typs.append('MACHINE')
        elif (ival==0x30000002):
            typs.append('TRUST')
    except:
        pass
    return '|'.join(typs)

def get_status(val):
    status = []
    try:
        ival = int(val)
        if (ival&512):
            status.append('NORMAL')
        if (ival&2):
            status.append('DISABLED')
        if (ival&16):
            status.append('LOCKOUT')
        if (ival&8388608):
            status.append('PWDEXPIRED')
    except:
        pass
    return '|'.join(status)

def set_account_flags(rs):
    da = None
    for r in rs:
        o = rs[r]
        if not o:
            continue
        if o['sAMAccountName']=="Domain Admins":
            da = o
            break
  
    for r in rs:
        o = rs[r]
        if not o:
            continue
        o['accountStatus'] = get_status(o['userAccountControl'])
        o['sAMAccountType'] = get_type( o['sAMAccountType'] )

        if not o['group']:
            o['member'] = []
            if da and r in da['member']:
                o['isInAdAdmin'] = True
            else:
                o['isInAdAdmin'] = False

def save_admin(dnsRoot, admins, path):
    header = '"dnsRoot","subDomain","sAMAccountName","sAMAccountType","userPrincipalName","userAccountControl","accountStatus","isInAdAdmin","distinguishedName","group","member","whenCreated","whenChanged","lastLogon","description"'
    fw = open(path, 'wb')
    fw.write(header+'\r\n')
    for (s,rs) in admins:
        for r in rs:
            o = rs[r]
            if not o:
                print '+Error: %s,None' % (r)
                continue
            
            ss = '"%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s"' % (dnsRoot,s,o["sAMAccountName"], o["sAMAccountType"],
                                                                        o["userPrincipalName"],
                                                                        o["userAccountControl"], o["accountStatus"],str(o["isInAdAdmin"]),
                                                                        r, str(o["group"]),
                                                                   ';'.join(o["member"]),
                                                                   o["whenCreated"],o["whenChanged"],o["lastLogon"],
                                                                   o["description"].replace('\r','').replace('"','""'))
            fw.write(ss+'\r\n')
    fw.close()
    
def main():
    global dnsRoot,dnsServers,dnsTimeout

    options = OptionParser(usage='%prog [options]', description='resolv.py')
    options.add_option('-r', '--root', type='string', default='', help='dns root(eg: example.com)')
    options.add_option('-n', '--nameserver', type='string', default='', help='name servers(eg: 8.8.4.4,8.8.8.8)')
    options.add_option('-t', '--timeout', type='float', default=1.5, help='dns query timeout seconds')
    options.add_option('-s', '--server', type='string', default='', help='domain controler dsquery to connect')
    options.add_option('-u', '--user', type='string', default='', help='username dsquery to login server')
    options.add_option('-p', '--password', type='string', default='', help='password for user')
    options.add_option('-a', '--all', type='int', default=1, help='include all sub domain')
    options.add_option('-d', '--database', type='string', default='.', help='database file')   
        
    opts, args = options.parse_args()
    if not opts.root or not opts.nameserver:
        options.print_help()
        return -1
        
    dnsRoot = '.'+opts.root.lower().strip('.')
    dnsServers = [(s.strip(),53) for s in opts.nameserver.split(',')]
    dnsTimeout = opts.timeout

    datestr = datetime.today().strftime('%Y%m%d')
    dcpath = '%s/%s_servers_%s.csv' % (opts.database, opts.root, datestr)
    admpath = '%s/%s_admins_%s.csv' % (opts.database, opts.root, datestr)
    
    servers = get_dc(opts.server,opts.user,opts.password)
    
    save_dc(servers, dcpath)
    if opts.all:
        subdoms = sorted(set([s[5] for s in servers]))
    else:
        subdoms = ['']
    admins = []    
    for subdom in subdoms:
        rs = get_admins(opts.server,opts.user,opts.password,subdom)
        try:
            set_account_flags(rs)
        except Exception as e:
            print '+Error set flags: %s' % (str(e))
        admins.append((subdom, rs))
        #for r in rs:
        #    print r,'=>',rs[r]
        #    print
    save_admin(dnsRoot, admins, admpath)
    
if __name__=='__main__':
    main()
    
