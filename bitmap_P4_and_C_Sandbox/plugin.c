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
#define BITMAP_COLUMN_COUNT 128
#define BITMAP_COLUMN_COUNT_MASK (BITMAP_COLUMN_COUNT-1)
struct Bitmap {
    uint32_t count;
};
__export __mem static struct Bitmap bitmap;                     //atomic? only 1 ME?
__export __mem static int32_t sketch[BITMAP_COLUMN_COUNT];      //atomic? only 1 ME?
//=============================================================================================================
uint32_t hash_func1(uint32_t srcAddr, uint32_t dstAddr)
{
	return (srcAddr ^ dstAddr) & BITMAP_COLUMN_COUNT_MASK;
}
//=============================================================================================================
int pif_plugin_primitive_bitmap_finder(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
	//update sketch
	uint32_t i;
	__xread struct Bitmap in_xfer_bitmap;
	__gpr struct Bitmap out_reg_bitmap;
	__xwrite struct Bitmap out_xfer_bitmap;
	PIF_PLUGIN_ipv4_T *ipv4_header = pif_plugin_hdr_get_ipv4(headers);
	uint32_t srcAddr = PIF_HEADER_GET_ipv4___srcAddr(ipv4_header);
	uint32_t dstAddr = PIF_HEADER_GET_ipv4___dstAddr(ipv4_header);
	uint32_t hv0 = hash_func1(srcAddr, dstAddr);
	
	__xread uint32_t in_xfer_sketch;
	__gpr uint32_t out_reg_sketch;
	__gpr uint32_t count_reg_sketch = 0;
	__xwrite uint32_t out_xfer_sketch;
	
	mem_read32(&in_xfer_sketch, &sketch[hv0], sizeof(uint32_t));
	out_reg_sketch = in_xfer_sketch;
	if(out_reg_sketch == 0)
	{
		out_reg_sketch = 1;
		out_xfer_sketch = out_reg_sketch;
		mem_write32(&out_xfer_sketch, &sketch[hv0], sizeof(uint32_t));
	}
	
	//count how many 1s
	for(i=0; i<BITMAP_COLUMN_COUNT; i++)
	{
		mem_read32(&in_xfer_sketch, &sketch[i], sizeof(uint32_t));
		out_reg_sketch = in_xfer_sketch;
		count_reg_sketch += out_reg_sketch;
	}
	
	//update bitmap count
	mem_read32(&in_xfer_bitmap, &bitmap, sizeof(struct Bitmap));
	out_reg_bitmap = in_xfer_bitmap;
	if(out_reg_bitmap.count != count_reg_sketch)
	{
		out_reg_bitmap.count = count_reg_sketch;
		out_xfer_bitmap = out_reg_bitmap;
		mem_write32(&out_xfer_bitmap, &bitmap, sizeof(struct Bitmap));
	}
	pif_plugin_meta_set__bitmap_report_meta__bitmap_count(headers, bitmap.count);

    return PIF_PLUGIN_RETURN_FORWARD;
}
