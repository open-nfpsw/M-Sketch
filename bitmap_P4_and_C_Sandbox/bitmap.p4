/*
 * Copyright (C) 2017, ACANETS LAB, University of Massachusetts Lowell
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 *
 */

#define ETHERTYPE_IPV4 0x0800
#define TCP_PROTO 0x06
#define UDP_PROTO 0x11

//==========================================================================================================
//Header
//==========================================================================================================
header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}
header ethernet_t ethernet;
//==========================================================================================================
header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr : 32;
    }
}
header ipv4_t ipv4;
//==========================================================================================================
header_type tcp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        seqNo : 32;
        ackNo : 32;
        dataOffset : 4;
        res : 4;
        flags : 8;
        window : 16;
        checksum : 16;
        urgentPtr : 16;
    }
}
header tcp_t tcp;
//==========================================================================================================
header_type udp_t {
	fields {
		srcPort : 16;
        dstPort : 16;
		udplen : 16;
		udpchk : 16;
	}
}
header udp_t udp;
//==========================================================================================================
header_type bitmap_report_t {
    fields {
		device : 16;
		reason : 16;
		bitmap_count : 32;
	}
}
header bitmap_report_t bitmap_report;
metadata bitmap_report_t bitmap_report_meta;
//==========================================================================================================
//Parser
//==========================================================================================================
parser start {
    return parse_ethernet;
}

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        //No default, so drop it if not ipv4 packet
    }
}

parser parse_ipv4 {
    extract(ipv4);
    return select(latest.protocol) {
        TCP_PROTO : parse_tcp;
        UDP_PROTO : parse_udp;
        //No default, so drop it if not tcp or udp
    }
}

parser parse_tcp {
	extract(tcp);
	return parse_bitmap_report;
}

parser parse_udp {
	extract(udp);
	return parse_bitmap_report;
}

parser parse_bitmap_report
{
	extract(bitmap_report);
	return ingress;
}

//==========================================================================================================
//Ingress
//==========================================================================================================
primitive_action primitive_bitmap_finder();
action do_bitmap_finder() {
	primitive_bitmap_finder();
	//add_header(bitmap_report); //we alreay assume that the received packet has the header bitmap_report
	modify_field(bitmap_report.device, 0xffff);   
	modify_field(bitmap_report.reason, 0xffff);  
	modify_field(bitmap_report.bitmap_count, bitmap_report_meta.bitmap_count);
}

table bitmap_finder {
	actions {
		do_bitmap_finder;
	}
}
//==========================================================================================================
action do_forward(port) {
    modify_field(standard_metadata.egress_spec, port);
}

action do_drop()
{
	drop();
}

table forward {
    reads {
        standard_metadata.ingress_port : exact;
    }
    actions {
		do_forward;
		do_drop;
    }
}
//==========================================================================================================
control ingress {
	apply(bitmap_finder);
	apply(forward);
}

//==========================================================================================================
//Egress
//==========================================================================================================

