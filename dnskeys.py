#!/usr/bin/python

import getdns
import hashlib

dnssec_status = {
    "GETDNS_DNSSEC_SECURE" : 400,
    "GETDNS_DNSSEC_BOGUS" : 401,
    "GETDNS_DNSSEC_INDETERMINATE" : 402,
    "GETDNS_DNSSEC_INSECURE" : 403,
    "GETDNS_DNSSEC_NOT_PERFORMED" : 404
}

def buildOtrFingerprintHostname(jid):
    """
    Build the hostname where the OTR fingerprint should be stored in a
    text record if it has been published. Don't forget, it's always
    possible that the name will not exist.
    """
    parts = jid.split('@')
    hostname  = hashlib.sha224(parts[0]).hexdigest()
    hostname += "._otrfingerprint."
    hostname += parts[1]
    hostname += ".iain.getdnsapi.net"
    return hostname

def lookupOtrFingerprintRecords(hostname):
    """
    Use getdns to lookup the OTR fingerprints on a hostname and verify
    the validity of the records using DNSSEC. This function returns an
    list of tuples containing the text of the record and a boolean
    showing whether or not DNSSEC validation was successful.
    """
    ctx = getdns.context_create()
    extensions = { "dnssec_return_status" : getdns.GETDNS_EXTENSION_TRUE }
    query_results = getdns.general(ctx, hostname, getdns.GETDNS_RRTYPE_TXT, extensions=extensions)
    records = []
    for reply in query_results['replies_tree']:
        dnssec_valid = True if reply['dnssec_status'] == 400 else False
        for answer in reply['answer']:
            if 'txt_strings' in answer['rdata'].keys():
                for record in answer['rdata']['txt_strings']:
                    if record[0:7] == "v=otr1 ":
                        records.append((record, dnssec_valid))
    return records

def parseOtrFingerprintRecord(value):
    """
    Extract fingerprints from an OTR fingerprint record's value.
    """
    parts = value.split(" ")
    fingerprints = []
    for part in parts:
        if part[0:2] == "f:":
            fingerprints.append(part[2:])
    return fingerprints

def getOtrFingerprints(jid):
    """
    Returns a list of tuples containing OTR fingerprints published in
    DNS for a Jabber ID and whether or not DNSSEC validation was
    successfully performed for each fingerprint.
    """
    hostname = buildOtrFingerprintHostname(jid)
    records = lookupOtrFingerprintRecords(hostname)
    fingerprints = []
    for record, dnssec_valid in records:
        for fingerprint in parseOtrFingerprintRecord(record):
            fingerprints.append((fingerprint, dnssec_valid))
    return fingerprints

