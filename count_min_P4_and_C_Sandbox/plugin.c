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
//=============================================================================================================
#include <stdint.h>
#include <nfp/me.h>
#include <nfp/mem_atomic.h>
#include <pif_common.h>
#include "pif_plugin.h"
//=============================================================================================================
#define SKETCH_COLUMN_COUNT 128
#define SKETCH_COLUMN_COUNT_MASK (SKETCH_COLUMN_COUNT-1)
struct Heavy_Hitter {
    uint32_t srcAddr;
    uint32_t dstAddr;
    uint32_t count;
};
__export __mem static struct Heavy_Hitter heavy_hitter;            
__export __mem static int32_t sketch[3][SKETCH_COLUMN_COUNT];     
//=============================================================================================================
uint32_t hash_func1(uint32_t srcAddr, uint32_t dstAddr)
{
	return (srcAddr ^ dstAddr) & SKETCH_COLUMN_COUNT_MASK;
}

uint32_t hash_func2(uint32_t srcAddr, uint32_t dstAddr)
{
	return (srcAddr | dstAddr) & SKETCH_COLUMN_COUNT_MASK;
}

uint32_t hash_func3(uint32_t srcAddr, uint32_t dstAddr)
{
	return (srcAddr & dstAddr) & SKETCH_COLUMN_COUNT_MASK;
}
//=============================================================================================================
int pif_plugin_primitive_hh_finder(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
	
	//update sketch
	__xread uint32_t in_xfer_sketch;
	__gpr uint32_t out_reg_sketch0, out_reg_sketch1, out_reg_sketch2, out_reg_sketch_min;
	__xwrite uint32_t out_xfer_sketch;
	__xread struct Heavy_Hitter in_xfer_hh;
	__gpr struct Heavy_Hitter out_reg_hh;
	__xwrite struct Heavy_Hitter out_xfer_hh;

	PIF_PLUGIN_ipv4_T *ipv4_header = pif_plugin_hdr_get_ipv4(headers);
	uint32_t srcAddr = PIF_HEADER_GET_ipv4___srcAddr(ipv4_header);
	uint32_t dstAddr = PIF_HEADER_GET_ipv4___dstAddr(ipv4_header);
	uint32_t hv0 = hash_func1(srcAddr, dstAddr);
	uint32_t hv1 = hash_func2(srcAddr, dstAddr);
	uint32_t hv2 = hash_func3(srcAddr, dstAddr);
	
	
	mem_read_atomic(&in_xfer_sketch, &sketch[0][hv0], sizeof(uint32_t));
	out_reg_sketch0 = in_xfer_sketch;
	out_reg_sketch0 += 1;
	out_xfer_sketch = out_reg_sketch0;
	mem_write_atomic(&out_xfer_sketch, &sketch[0][hv0], sizeof(uint32_t));
	
	
	mem_read_atomic(&in_xfer_sketch, &sketch[1][hv1], sizeof(uint32_t));
	out_reg_sketch1 = in_xfer_sketch;
	out_reg_sketch1 += 1;
	out_xfer_sketch = out_reg_sketch1;
	mem_write_atomic(&out_xfer_sketch, &sketch[1][hv1], sizeof(uint32_t));
	
	
	mem_read_atomic(&in_xfer_sketch, &sketch[2][hv2], sizeof(uint32_t));
	out_reg_sketch2 = in_xfer_sketch;
	out_reg_sketch2 += 1;
	out_xfer_sketch = out_reg_sketch2;
	mem_write_atomic(&out_xfer_sketch, &sketch[2][hv2], sizeof(uint32_t));
	
	
	out_reg_sketch_min = out_reg_sketch0;
	if(out_reg_sketch_min > out_reg_sketch1) { out_reg_sketch_min = out_reg_sketch1; }
	if(out_reg_sketch_min > out_reg_sketch2) { out_reg_sketch_min = out_reg_sketch2; }
	
	
	//update heavy hitter
	mem_read_atomic(&in_xfer_hh, &heavy_hitter, sizeof(struct Heavy_Hitter));
	out_reg_hh = in_xfer_hh;
	if(out_reg_hh.count < out_reg_sketch_min)
	{
		out_reg_hh.count = out_reg_sketch_min;
		out_reg_hh.srcAddr = srcAddr;
		out_reg_hh.dstAddr = dstAddr;
		
		out_xfer_hh = out_reg_hh;
		mem_write_atomic(&out_xfer_hh, &heavy_hitter, sizeof(struct Heavy_Hitter));
	}
	
	pif_plugin_meta_set__hh_report_meta__srcAddr(headers, heavy_hitter.srcAddr); //do they have pif_plugin_header_set?
	pif_plugin_meta_set__hh_report_meta__dstAddr(headers, heavy_hitter.dstAddr);
	pif_plugin_meta_set__hh_report_meta__hh_count(headers, heavy_hitter.count);

    return PIF_PLUGIN_RETURN_FORWARD;
}
