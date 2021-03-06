'''
Objects for parsing a list of HTTPFlows into data suitable for writing to a
HAR file.
'''

import dpkt
from logging import getLogger
logging = getLogger(__name__)
import math

from datetime import datetime
from pcaputil import ms_from_dpkt_time, ms_from_dpkt_time_diff, to_int
from pagetracker import PageTracker
import http
import settings

class HttpErrorRecord(object):
    """ Error that happens while processing HTTP session """
    def __init__(self, internal_error):
        self.timestamp = datetime.now()
        self.internal_error = internal_error
    
    def __repr__(self):
        return "HttpErrorRecord(timestamp='%s', internal_error='%s')" % \
            (str(self.timestamp), self.internal_error) 
    def __str__(self):
        return self.__repr__()

class Entry(object):
    '''
    represents an HTTP request/response in a form suitable for writing to a HAR
    file.
    Members:
    * request = http.Request
    * response = http.Response
    * page_ref = string
    * startedDateTime = python datetime
    * time = from sending of request to end of response, milliseconds
    * total_time = time, including DNS, blocking and request/resonse time, milliseconds
    * time_blocked
    * time_dnsing
    * time_connecting
    * time_sending
    * time_waiting
    * time_receiving
    '''

    def __init__(self, request, response):
        self.request = request
        self.response = response
        self.pageref = None
        self.ts_start = ms_from_dpkt_time(request.ts_connect)

        if request.ts_connect is None:
            self.startedDateTime = None
        else:
            self.startedDateTime = datetime.utcfromtimestamp(request.ts_connect)
        # calculate other timings
        self.time_blocked = -1
        self.time_dnsing = -1
        self.time_waiting = -1
        self.time_receiving = -1
        self.time = -1
        self.total_time = -1

        self.time_connecting = (
            ms_from_dpkt_time_diff(request.ts_connect_end, request.ts_connect))
        self.time_gap = (
            ms_from_dpkt_time_diff(request.ts_start, request.ts_connect_end))
        self.time_sending = (
            ms_from_dpkt_time_diff(request.ts_end, request.ts_start))

        if response is not None:
            self.time_waiting = (
                ms_from_dpkt_time_diff(response.ts_start, request.ts_end))
            self.time_receiving = (
                ms_from_dpkt_time_diff(response.ts_end, response.ts_start))
            if request.ts_connect:
                self.time = ms_from_dpkt_time_diff(response.ts_end, request.ts_connect)

    def json_repr(self):
        '''
        return a JSON serializable python object representation of self.
        '''
        d = {
            'time': to_int(self.total_time),
            'request': self.request,
            'response': self.response,
            'timings': {
                'blocked': to_int(self.time_blocked),
                'dns': to_int(self.time_dnsing),
                'connect': to_int(self.time_connecting),
                '_gap': to_int(self.time_gap),
                'send': to_int(self.time_sending),
                'wait': to_int(self.time_waiting),
                'receive': to_int(self.time_receiving)
            },
            'cache': {},
        }
        if self.startedDateTime:
            # Z means time is in UTC
            d['startedDateTime'] = self.startedDateTime.isoformat() + 'Z'
        if self.pageref:
            d['pageref'] = self.pageref
        return d

    def add_dns(self, dns_query):
        '''
        Adds the info from the dns.Query to this entry

        Assumes that the dns.Query represents the DNS query required to make
        the request. Or something like that.
        '''
        if self.time_dnsing == -1:
            self.time_dnsing = ms_from_dpkt_time(dns_query.duration())
        else:
            self.time_dnsing += ms_from_dpkt_time(dns_query.duration())
    
    def calc_total_time(self):
        ''' 
        Calculates total_time, including DNS, blocking and request/response time.
        '''
        total_time = self.time
        if self.time_dnsing != -1 and total_time != -1:
            total_time = total_time + self.time_dnsing
        if self.time_blocked != -1 and total_time != -1:
            total_time = total_time + self.time_blocked
        self.total_time = total_time

class UserAgentTracker(object):
    '''
    Keeps track of how many uses each user-agent header receives, and provides
    a function for finding the most-used one.
    '''

    def __init__(self):
        self.data = {}  # {user-agent string: number of uses}

    def add(self, ua_string):
        '''
        Either increments the use-count for the user-agent string, or creates a
        new entry. Call this for each user-agent header encountered.
        '''
        if ua_string in self.data:
            self.data[ua_string] += 1
        else:
            self.data[ua_string] = 1

    def dominant_user_agent(self):
        '''
        Returns the agent string with the most uses.
        '''
        if not len(self.data):
            return None
        elif len(self.data) == 1:
            return self.data.keys()[0]
        else:
            # return the string from the key-value pair with the biggest value
            return max(self.data.iteritems(), key=lambda v: v[1])[0]


class HttpSession(object):
    '''
    Represents all http traffic from within a pcap.

    Members:
    * user_agents = UserAgentTracker
    * user_agent = most-used user-agent in the flow
    * flows = [http.Flow]
    * entries = [Entry], all http request/response pairs
    '''

    def __init__(self, packetdispatcher, drop_response_bodies=False):
        '''
        Parses http.flows from packetdispatcher, and parses those for HAR info
        '''
        self.errors = []
        # parse http flows
        self.flows = []
        for flow in packetdispatcher.tcp.flows():
            try:
                self.flows.append(http.Flow(flow, drop_response_bodies))
            except http.Error as error:
                self.errors.append(HttpErrorRecord(error))
                logging.warning(error)
            except dpkt.dpkt.Error as error:
                self.errors.append(HttpErrorRecord(error))
                logging.warning(error)
        # combine the messages into a list
        pairs = reduce(lambda p, f: p+f.pairs, self.flows, [])
        # set-up
        self.user_agents = UserAgentTracker()
        if settings.process_pages:
            self.page_tracker = PageTracker()
        else:
            self.page_tracker = None
        self.entries = []
        # sort pairs on request.ts_connect
        pairs.sort(
            key=lambda pair: pair.request.ts_connect
        )
        # iter through messages and do important stuff
        for msg in pairs:
            entry = Entry(msg.request, msg.response)
            # if msg.request has a user-agent, add it to our list
            if 'user-agent' in msg.request.msg.headers:
                self.user_agents.add(msg.request.msg.headers['user-agent'])
            # if msg.request has a referer, keep track of that, too
            if self.page_tracker:
                entry.pageref = self.page_tracker.getref(entry)
            # add it to the list, if we're supposed to keep it.
            if entry.response or settings.keep_unfulfilled_requests:
                self.entries.append(entry)
        self.user_agent = self.user_agents.dominant_user_agent()
        # handle DNS AFTER sorting
        # this algo depends on first appearance of a name
        # being the actual first mention
        names_mentioned = set()
        dns = packetdispatcher.udp.dns
        page_times = {}
        for entry in self.entries:
            name = entry.request.host
            # if this is the first time seeing the name
            if name not in names_mentioned:
                if name in dns.by_hostname:
                    # Handle multiple DNS queries for now just use last one, 
                    # i.e. for IPv4/IPv6 addresses
                    for d in dns.by_hostname[name]:
                        entry.add_dns(d)
                names_mentioned.add(name)
            entry.calc_total_time()
            # handle page network load time
            p_time = page_times.get(entry.pageref, (entry.ts_start, 0))
            page_times[entry.pageref] = (min(p_time[0], entry.ts_start), 
                                         max(p_time[1], entry.ts_start + entry.total_time))

        # write page network load times
        for page in self.page_tracker.pages:
            p_time = page_times.get(page.pageref, None)
            if p_time:
                page.network_load_time = p_time[1] - p_time[0] 

    def json_repr(self):
        '''
        return a JSON serializable python object representation of self.
        '''
        d = {
            'log': {
                'version': '1.1',
                'creator': {
                    'name': 'pcap2har',
                    'version': '0.1'
                },
                'browser': {
                    'name': self.user_agent,
                    'version': 'mumble'
                },
                'entries': sorted(self.entries, key=lambda x: x.ts_start)
            }
        }
        if self.page_tracker:
            d['log']['pages'] = self.page_tracker
        return d
