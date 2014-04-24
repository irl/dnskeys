#!/usr/bin/python

import commondns

def buildOpenPGPFingerprintHostname(uid):
    """
    Build the hostname where the OpenPGP fingerprint should be stored in a text
    record if it has been published. Don't forget, it's always possible that
    the name will not exist.
    """
    parts = uid.split('@', 1)
    hostname  = parts[0]
    hostname += "._pka."
    hostname += parts[1]
    hostname += ".iain.getdnsapi.net"
    return hostname

def lookupOpenPGPFingerprintRecords(hostname):
    """
    TODO: Update
    """
    records = []
    for record, dnssec_valid in commondns.lookupTextRecords(hostname):
        if record[0:7] == "v=pka1;":
            records.append((record, dnssec_valid))
    return records

def parseOpenPGPFingerprintRecord(value):
    """
    Extract fingerprints from an OpenPGP fingerprint record's value.
    """
    parts = value.split(";")
    fingerprint = None
    uri = None
    for part in parts:
        if part[0:4] == "fpr=":
            fingerprint = part[4:]
        if part[0:4] == "uri=":
            uri = part[4:]
    if fingerprint == None:
        return None, None
    if uri == None:
        return fingerprint, None
    return fingerprint, uri

def getOpenPGPFingerprints(uid):
    """
    Returns a list of tuples containing OpenPGP fingerprints published in
    DNS for a Jabber ID and whether or not DNSSEC validation was
    successfully performed for each fingerprint.
    """
    hostname = buildOpenPGPFingerprintHostname(uid)
    records = lookupOpenPGPFingerprintRecords(hostname)
    fingerprints = []
    for record, dnssec_valid in records:
        fingerprint, uri = parseOpenPGPFingerprintRecord(record)
        fingerprints.append((fingerprint, uri, dnssec_valid))
    return fingerprints

