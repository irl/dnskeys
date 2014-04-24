dnskeys
=======

A Python Library for Authenticating Keys using DNS. This library was
written by Iain Learmonth and Sathyanarayanan Gunasekaran at the
Kings of Code Hack Battle 2014 with the support of Versign.

The library provides functions to retrieve and validate fingerprints
for the following crypto systems:

 * OTR (via otr1 TXT records)
 * OpenPGP (via pka1 TXT records)

DNSSEC validation information is passed to the application to allow for
the application to make trust decisions based on the user's
preferences instead of hard-coding trust decisions.

If time permits, it will retrieve and validate S/MIME fingerprints too.

