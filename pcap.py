import dpkt
import logging as log
import os
import shutil
import tcp

from datetime import datetime
from pcaputil import *
from socket import inet_ntoa

from packetdispatcher import PacketDispatcher

class PcapIncompletePacketError(Exception):
    """ Incomplete packet error. """

class PcapErrorRecord(object):
    """ Error that happens while pasing pcap stream. """
    def __init__(self, packet, packet_ts=None, packet_number=None, internal_error=None):
        """
        Args:
            packet: pcap packet object;
            packet_ts: original packet timestamp;
            packet_number: relative packet number, numbering starts from the pcap file beginning;
            internal_error: error that happened inside the processor;
            timestamp: the time of PcapErrorRecord object creation.
         """
        self.timestamp = datetime.now()
        self.packet_ts = packet_ts
        self.packet = packet
        self.packet_number = packet_number
        self.internal_error = internal_error

    def __repr__(self):
        return "PcapErrorRecord(packet='%s', packet_ts='%s', packet_number=%s, timestamp='%s', internal_error='%s')" % \
            ('...', self.packet_ts, self.packet_number, str(self.timestamp), self.internal_error) 
    def __str__(self):
        return self.__repr__()

class PcapParser(object):
    def __init__(self):
        self.errors = [] # store errors for later inspection

    def parse(self, dispatcher, filename=None, reader=None):
        '''
        Parses the passed pcap file or pcap reader.

        Adds the packets to the PacketDispatcher. Keeps a list

        Args:
        dispatcher = PacketDispatcher
        reader = pcaputil.ModifiedReader or None
        filename = filename of pcap file or None

        check for filename first; if there is one, load the reader from that. if
        not, look for reader.
        '''
        if filename:
            f = open(filename, 'rb')
            try:
                pcap = ModifiedReader(f)
            except dpkt.dpkt.Error as e:
                log.warning('Failed to parse pcap file %s' % filename)
                return
        elif reader:
            pcap = reader
        else:
            raise 'Either a filename or pcap reader is required'
         #now we have the reader; read from it
        packet_count = 1 # start from 1 like Wireshark

        try:
            for packet in pcap:
                ts = packet[0]  # timestamp
                buf = packet[1] # frame data
                hdr = packet[2] # libpcap header
                # discard incomplete packets
                if hdr.caplen != hdr.len:
                    # log packet number so user can diagnose issue in wireshark
                    self.errors.append(PcapErrorRecord(packet, 
                                                       ts, 
                                                       packet_count,
                                                       PcapIncompletePacketError()))
                    log.warning('ParsePcap: discarding incomplete packet, # %d' % packet_count)
                    continue
                # parse packet
                try:
                    # handle SLL packets, thanks Libo
                    dltoff = dpkt.pcap.dltoff
                    if pcap.dloff == dltoff[dpkt.pcap.DLT_LINUX_SLL]:
                        eth = dpkt.sll.SLL(buf)
                    # otherwise, for now, assume Ethernet
                    else:
                        eth = dpkt.ethernet.Ethernet(buf)
                    dispatcher.add(ts, buf, eth)
                # catch errors from this packet
                except dpkt.Error as e:
                    self.errors.append(PcapErrorRecord(packet, ts, packet_count, e))
                    log.warning('Error parsing packet: %s. On packet #%s' %
                                (e, packet_count))
                packet_count += 1
        except dpkt.dpkt.NeedData as error:
            log.warning(error)
            log.warning('A packet in the pcap file was too short')
            self.errors.append(PcapErrorRecord(None, internal_error=error))
