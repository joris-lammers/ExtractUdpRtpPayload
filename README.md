# ExtractUdpRtpPayload
[![Build Status](https://travis-ci.org/joris-lammers/ExtractUdpRtpPayload.svg?branch=master)](https://travis-ci.org/joris-lammers/ExtractUdpRtpPayload)

Mainly used for extracting MPEG Transport Stream from pcap file (TS usually 
transmitted over UDP or RTP) but can also be used to extract UDP payload of any
other protocol or data that gets transported over UDP/RTP. However, the file
names it creates end in `.ts`.

Currently, this project heavily depends on libpcap and that is something I want
to replace by using a native go library for pcap handling rather than a wrapper
around libpcap.

Enjoy!
