#!/usr/bin/python

import getdns

def lookupTextRecords(hostname):
    """
    Use getdns to lookup the OpenPGP fingerprints on a hostname and verify
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
                    records.append((record, dnssec_valid))
    return records

