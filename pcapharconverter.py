import json

from har import JsonReprEncoder
from httpsession import HttpSession
from packetdispatcher import PacketDispatcher
from pcap import PcapParser
from pcaputil import ModifiedReader

class PcapHarConverter(object):
    """ Representation of PCAP file in the HAR format """

    def __init__(self, fileobj, drop_response_bodies=False):
        """
        Converts PCAP file to HAR format and keeps intermediate HttpSession object.

        Args:
            fileobj: file-like object, containing PCAP stream;
            drop_response_bodies: drop bodies in the HTTP response objects.
        """
        # PCAP 1Mb ~ 0.7s
        self.errors = []

        # parse pcap file
        dispatcher = PacketDispatcher()
        freader = ModifiedReader(fileobj)
        pcap_parser= PcapParser()
        pcap_parser.parse(dispatcher, reader=freader)
        self.errors.extend(pcap_parser.errors)
        dispatcher.finish()
         
        # arrange packets into http session
        self.session = HttpSession(dispatcher, drop_response_bodies)
        self.errors.extend(self.session.errors)

    def get(self):
        """ Returns HttpSession object."""
        return self.session

    def dumps(self):
        """ Returns HAR (JSON-based) formatted string. """
        return json.dumps(self.session, cls=JsonReprEncoder, indent=2, encoding='utf8', sort_keys=True)
    
    def dump(self, fp):
        """ Serializes HAR object to file. """
        json.dump(self.session, fp, cls=JsonReprEncoder, indent=2, encoding='utf8', sort_keys=True)
