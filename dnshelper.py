# -*- coding: utf-8 -*-
import time
import socket
from dnslib import DNSQuestion,DNSRecord,QTYPE

##########################################################################
class DNSHelper(object):
    def __init__(self, servers):
        """  @servers: ( (ip,port),(ip,port),... )
        """
        self.servers = servers
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
    def get_result(self, response, qtype):
        retval = []
        qname = response.get_q().get_qname()
        if qname:
            qname = str(qname).lower()
        for rr in response.rr:
            #print str(rr.rdata)
            if rr.rtype == getattr(QTYPE, qtype):
                retval.append( (str(rr.rname).lower(), qtype, str(rr.rdata).lower()) )
            elif rr.rtype == getattr(QTYPE, 'CNAME'):
                retval.append( (str(rr.rname).lower(), 'CNAME', str(rr.rdata).lower()) )
        return qname,retval
    
    def query_all(self, question, qtype, timeout):
        data = question.pack()
        nlen = len(self.servers)
        idx,rcnt = 0,0
        endtime = time.time() + timeout
        results = []
        while rcnt<nlen and endtime>time.time():
            r,w,x = select.select([self.sock], [self.sock] if idx<nlen else [], [], 0.15)
            if w and idx<nlen:
                self.sock.sendto(data, self.servers[idx])
                idx += 1
            if r:
                try:
                    packet,server = self.sock.recvfrom(65535)
                    rcnt += 1
                    response = DNSRecord.parse(bytearray(packet))
                    qname, retarr = self.get_result(response, qtype)
                    if retarr:
                        results.append( (server[0], qtype, retarr) )
                except socket.timeout:
                    #print '>>>---%s' % (str(e)) 
                    pass
                except Exception as e:
                    #print '>>> %s' % (str(e)) 
                    pass
        return results

    def resolv_addr(self, qname, timeout=1.5):
        question = DNSRecord(q=DNSQuestion(qname, getattr(QTYPE, 'A')))
        aws = self.query_all(question, 'A', timeout)
        addr = set()
        for s,q,ar in aws:
            for rn,qt,rd in ar:
                if qt=='A':
                    addr.add(rd)
        return sorted(addr)
    
    def resolv_a(self, qname, timeout=1.5):
        question = DNSRecord(q=DNSQuestion(qname, getattr(QTYPE, 'A')))
        return self.query_all(question, 'A', timeout)

    def resolv_ns(self, qname, timeout=1.5):
        question = DNSRecord(q=DNSQuestion(qname, getattr(QTYPE, 'NS')))
        return self.query_all(question, 'NS', timeout)
        
    def resolv_mx(self, qname, timeout=1.5):
        question = DNSRecord(q=DNSQuestion(qname, getattr(QTYPE, 'MX')))
        return self.query_all(question, 'MX', timeout)
    
    ## names: set of names, servers: list of dns ip addresses        
    def resolv_parallel(self, names, servers, speed = 1000, logger = None):
        import time
        
        qtype = 'A'
        queue = list(names)
        nameservers = [(s, 53) for s in servers]
        goodservers = set()
        resolved = dict()
        idx = 0
        count = 0
        wait = False
        sent = 0
        recvd = 0
        lasttime = time.time()
        starttime = lasttime
        totaltime = 0
        firstdone = 0
        lefts = None
        if logger:
            logger.info('[dnslib]names: %d, nameservers: %d' % (len(names), len(servers)))
        while True:
            now = time.time()
            period = now - lasttime
            totaltime  = now - starttime

            if totaltime<0.500 and sent>=5*len(nameservers) and recvd<5*len(nameservers):
                wait = True
                
            if count >= speed:
                wait = True
            
            if period>=1.0: 
                count = 0
                wait = False
                lasttime = time.time()
                #if logger:
                #    logger.info('stepping 1 second')
                    
            if recvd==0 and totaltime>3.0: ## all servers are unresponsable, we'll quit
                if logger:
                    logger.warn('[dnslib]!all nameservers down')
                break
             #all names resolved
            if len(resolved)>=len(names):
                break
            elif len(queue)==0:
                if firstdone==0:
                    firstdone = time.time()
                elif lefts is None and time.time()-firstdone>1.4:
                    lefts = list( names - set(resolved.keys()) )
                    if logger:
                        logger.info('[dnslib]retrying %d names' % (len(lefts)))
                    for n in lefts:
                        queue.append(n)
            
            if firstdone>0 and now-firstdone>=3.0: #wait some seconds when all requests sent
                if logger:
                    logger.info('[dnslib]retry timed out')
                break
            
            r,w,x = select.select([self.sock], [self.sock] if len(queue)>0 and not wait else [], [], 0.001)
            if w and len(queue)>0:
                if recvd>0 and totaltime>=0.500 and len(goodservers)<len(nameservers):
                    #remove unresponsable servers after 0.500 seconds
                    if logger:
                        logger.warn('[dnslib]setting nameservers (%d -> %d)' % (len(nameservers), len(goodservers)) )
                    nameservers = [(s, 53) for s in goodservers]
                    idx = 0
                name = queue.pop()
                qs = DNSRecord(q=DNSQuestion(name, getattr(QTYPE, qtype)))
                try:
                    self.sock.sendto(qs.pack(), nameservers[idx])
                except Exception as e:
                    if logger:
                        logger.error('[dnslib]!sendto(%s)' % (str(nameservers[idx])))
                    raise
                sent += 1
                count += 1
                idx += 1
                if idx >= len(nameservers):
                    idx = 0
            if r:
                try:
                    packet,server = self.sock.recvfrom(65535)
                    response = DNSRecord.parse(bytearray(packet))
                    qname = response.get_q().get_qname()
                    if qname:
                        recvd += 1
                        qname = str(qname).lower().rstrip('.')
                        goodservers.add(server[0])
                        addrs = []
                        for rr in response.rr:
                            if rr.rtype == getattr(QTYPE, qtype):
                                addrs.append(str(rr.rdata))
                        resolved[qname] = addrs
                except Exception as e:
                    if logger:
                        logger.warn('[dnslib]!exp: %s' % (str(e)))
                    pass
        ########### while done ##############
        if logger:
            logger.info('[dnslib]%d names, %d resolved, done' % (len(names), len(resolved)))
        return resolved
                    
                    
    def resolv_many(self, names, qtype='A', timeout=2.0):
        nlen = len(self.servers) * len(names)
        scnt,rcnt = 0,0
        i,j = 0,0
        results = []
        endtime = time.time() + timeout
        while rcnt<nlen and endtime>time.time():
            r,w,x = select.select([self.sock], [self.sock] if scnt<nlen else [], [], 0.33)
            if w and scnt<nlen:
                qs = DNSRecord(q=DNSQuestion(names[i], getattr(QTYPE, qtype)))
                self.sock.sendto(qs.pack(), self.servers[j])
                scnt += 1
                j = j + 1
                if j>= len(self.servers):
                    i = i + 1
                    j = 0
            if r:
                packet,server = self.sock.recvfrom(65535)
                rcnt += 1
                try:
                    response = DNSRecord.parse(bytearray(packet))
                    qname, retarr = self.get_result(response, qtype)
                    if retarr:
                        results.append( (server[0], qtype, retarr, qname) )
                except:
                    pass
        return results
#############################################################     
