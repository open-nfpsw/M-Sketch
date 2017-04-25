/*
 * Copyright (C) 2017, ACANETS LAB, UML
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
#define CM_ROW_ELEM_COUNT	8 //NOTE: The following hash value has 16 bit
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
header_type hh_report_t {
	fields {
		device : 16;
		reason : 16;
		in_time : 32;
		srcAddr : 32;
		dstAddr : 32;
		hh_count : 32;
		out_time : 32;
	}
}
header hh_report_t hh_report;
//==========================================================================================================
//Hash Functions
//==========================================================================================================
field_list hashvalue_list1 
{
	ipv4.srcAddr;
	ipv4.dstAddr;    
}
//
field_list hashvalue_list2 
{
	ipv4.srcAddr;
	ipv4.dstAddr;
	ipv4.version;
	ipv4.ihl;
	ipv4.diffserv;
	ipv4.totalLen;
	ipv4.protocol;      
}
//
field_list hashvalue_list3 
{
	ipv4.srcAddr;
	ipv4.dstAddr;
	ipv4.totalLen;
	ipv4.protocol;      
}
//
field_list_calculation ipv4_hash1 
{
    input { hashvalue_list1; }
    algorithm : crc16;
    output_width : 16;
}
//
field_list_calculation ipv4_hash2 {
    input { hashvalue_list2; }
    algorithm : csum16;
    output_width : 16;
}
//
field_list_calculation ipv4_hash3 {
    input { hashvalue_list3; }
    algorithm : csum16;
    output_width : 16;
}
//==========================================================================================================
//Sketch Data
//==========================================================================================================
register r1 { width : 32; instance_count : CM_ROW_ELEM_COUNT; }
register r2 { width : 32; instance_count : CM_ROW_ELEM_COUNT; }
register r3 { width : 32; instance_count : CM_ROW_ELEM_COUNT; }
register hh_r { width : 32; instance_count: 3; } //0: srcAddr, 1: dstAddr, 2: count

@pragma netro reglocked r1;
@pragma netro reglocked r2;
@pragma netro reglocked r3;
@pragma netro reglocked hh_r;
//
header_type counter_table_metadata_t
{
	fields
	{     
		h_v1 : 16;
		count1 : 32;
		h_v2 : 16;
		count2 : 32;
		h_v3 : 16;
		count3 : 32;
		count_min : 32;  
	}
}
metadata counter_table_metadata_t counter_table_metadata;
//
header_type heavy_hitter_t 
{ 
	fields
	{
		srcAddr : 32;
		dstAddr : 32;
		count : 32;
	}
}
metadata heavy_hitter_t heavy_hitter;
//
header_type intrinsic_metadata_t {
	fields {
		ingress_global_tstamp : 32;
	}
}
metadata intrinsic_metadata_t intrinsic_metadata;
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
	return parse_hh_report;
}

parser parse_udp {
	extract(udp);
	return parse_hh_report;
}

parser parse_hh_report
{
	extract(hh_report);
	return ingress;
}

//==========================================================================================================
//Actions
//==========================================================================================================
action do_hh_encap() 
{
	//add_header(hh_report); //we alreay assume that the received packet has the header hh_report 
	modify_field(hh_report.device, 0xffff);   
	modify_field(hh_report.reason, 0xffff); 
	modify_field(hh_report.srcAddr, heavy_hitter.srcAddr); 
	modify_field(hh_report.dstAddr, heavy_hitter.dstAddr); 
	modify_field(hh_report.hh_count, heavy_hitter.count);
}
@pragma netro no_lookup_caching do_hh_encap;
//
action do_update_cm()
{
	//get the hash value, use the p4 1.1 version
	modify_field_with_hash_based_offset(counter_table_metadata.h_v1, 0, ipv4_hash1, CM_ROW_ELEM_COUNT);
	modify_field_with_hash_based_offset(counter_table_metadata.h_v2, 0, ipv4_hash2, CM_ROW_ELEM_COUNT);
	modify_field_with_hash_based_offset(counter_table_metadata.h_v3, 0, ipv4_hash3, CM_ROW_ELEM_COUNT);
	//read the counter value from the register counter table
	register_read(counter_table_metadata.count1, r1, counter_table_metadata.h_v1);
	register_read(counter_table_metadata.count2, r2, counter_table_metadata.h_v2);
	register_read(counter_table_metadata.count3, r3, counter_table_metadata.h_v3);
	//update the counter value
	add_to_field(counter_table_metadata.count1, 0x01);
	add_to_field(counter_table_metadata.count2, 0x01);
	add_to_field(counter_table_metadata.count3, 0x01);
	//write back the register
	register_write(r1, counter_table_metadata.h_v1, counter_table_metadata.count1);
	register_write(r2, counter_table_metadata.h_v2, counter_table_metadata.count2);
	register_write(r3, counter_table_metadata.h_v3, counter_table_metadata.count3);
}
@pragma netro no_lookup_caching do_update_cm;
//
action do_find_min1()
{
	modify_field(counter_table_metadata.count_min, counter_table_metadata.count1);
}
@pragma netro no_lookup_caching do_find_min1;
//
action do_find_min2()
{
	modify_field(counter_table_metadata.count_min, counter_table_metadata.count2);
}
@pragma netro no_lookup_caching do_find_min2;
//
action do_find_min3()
{
	modify_field(counter_table_metadata.count_min, counter_table_metadata.count3);
}
@pragma netro no_lookup_caching do_find_min3;
//
action do_read_hh()
{
    register_read(heavy_hitter.srcAddr, hh_r, 0);
    register_read(heavy_hitter.dstAddr, hh_r, 1);
    register_read(heavy_hitter.count, hh_r, 2);
}
@pragma netro no_lookup_caching do_read_hh;
//
action do_update_hh()
{
    modify_field(heavy_hitter.srcAddr, ipv4.srcAddr);
    modify_field(heavy_hitter.dstAddr, ipv4.dstAddr);
    modify_field(heavy_hitter.count, counter_table_metadata.count_min);
    	
    register_write(hh_r, 0, heavy_hitter.srcAddr);
    register_write(hh_r, 1, heavy_hitter.dstAddr);
    register_write(hh_r, 2, heavy_hitter.count);
}
@pragma netro no_lookup_caching do_update_hh;
//
action do_forward(port) 
{
    modify_field(standard_metadata.egress_spec, port);
}
//
action do_drop()
{
	drop();
}
//==========================================================================================================
//Tables
//==========================================================================================================
table forward 
{
    reads 
    {
        standard_metadata.ingress_port : exact;
    }
    actions 
    {
		do_forward;
		do_drop;
    }
}
//
table update_cm
{
	actions
	{
		do_update_cm;
	}
}
//
table find_min1
{
	actions
	{
		do_find_min1;
	}
}
//
table find_min2
{
	actions
	{
		do_find_min2;
	}
}
//
table find_min3
{
	actions
	{
		do_find_min3;
	}
}
//
table read_hh
{
	actions
	{
		do_read_hh;
	}
}
//
table update_hh
{
	actions
	{
		do_update_hh;
	}
}
//
table hh_encap
{
	actions
	{
		do_hh_encap;
	}
}
//==========================================================================================================
//Time collection
//==========================================================================================================
action do_start_tstamp()
{
	modify_field(hh_report.in_time, intrinsic_metadata.ingress_global_tstamp);
}
//
table start_tstamp
{
	actions
	{
		do_start_tstamp;
	}
}
//==========================================================================================================
action do_end_tstamp()
{
	modify_field(hh_report.out_time, intrinsic_metadata.ingress_global_tstamp);
}
//
table end_tstamp
{
	actions
	{
		do_end_tstamp;
	}
}
//==========================================================================================================
//Ingress
//==========================================================================================================
control ingress 
{
    apply(forward);
    if(hh_report.device != 0xffff) 
    {
        //update the cm sketch
        apply(update_cm); 
        //find the minimum
        apply(find_min1);
        if(counter_table_metadata.count_min > counter_table_metadata.count2)
        {
    	    apply(find_min2);
        }
        if(counter_table_metadata.count_min > counter_table_metadata.count3)
        {
    	    apply(find_min3);
        }
        //update the heavy hitter
        apply(read_hh);
        if(heavy_hitter.count < counter_table_metadata.count_min)
        {
    	    apply(update_hh);
        }
        //encap the hh info into the header
        apply(hh_encap);
        apply(start_tstamp);
    }
    else
    {
        apply(end_tstamp);
    }
}

//==========================================================================================================
//Egress
//==========================================================================================================

