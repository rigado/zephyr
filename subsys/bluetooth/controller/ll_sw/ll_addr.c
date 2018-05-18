/*
 * Copyright (c) 2016-2018 Nordic Semiconductor ASA
 * Copyright (c) 2016 Vinayak Kariappa Chettimada
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stddef.h>
#include <string.h>

#include <zephyr/types.h>
#include <bluetooth/hci.h>
#include <bluetooth/crypto.h>
#include <misc/slist.h>
#include <soc.h>

#include "util/util.h"

#include "ll_sw/pdu.h"
#include "ll_sw/ctrl.h"

static u8_t pub_addr[BDADDR_SIZE];
static u8_t rnd_addr[BDADDR_SIZE];

u8_t *ll_addr_get(u8_t addr_type, u8_t *bdaddr)
{
	u8_t * ret_ptr = NULL;

	if (addr_type <= 1) 
	{
		const int valid_pub_addr 	= (!buffer_all_equal(pub_addr, BDADDR_SIZE, 0x00) 
										&& !buffer_all_equal(pub_addr, BDADDR_SIZE, 0xff));
		const int valid_rnd_addr 	= (!buffer_all_equal(rnd_addr, BDADDR_SIZE, 0x00) 
										&& !buffer_all_equal(rnd_addr, BDADDR_SIZE, 0xff));
		const int req_pub_addr 		= (addr_type == 0);

		//public request with a valid public address or random req with invalid random address
		if ((req_pub_addr && valid_pub_addr)
			|| (!req_pub_addr && !valid_rnd_addr)) 
		{
			ret_ptr = pub_addr;
		}
		//otherwise return the random address
		else 
		{
			ret_ptr = rnd_addr;	
 		}
 	}
 
	//memcpy address if valid pointer
	if (bdaddr && ret_ptr) 
	{
		memcpy(bdaddr, ret_ptr, BDADDR_SIZE);
	}	
 
	return ret_ptr;
}

u32_t ll_addr_set(u8_t addr_type, u8_t const *const bdaddr)
{
	if (ll_adv_is_enabled() ||
	    (ll_scan_is_enabled() & (BIT(1) | BIT(2)))) {
		return BT_HCI_ERR_CMD_DISALLOWED;
	}

	if (addr_type) {
		memcpy(rnd_addr, bdaddr, BDADDR_SIZE);
	} else {
		memcpy(pub_addr, bdaddr, BDADDR_SIZE);
	}

	return 0;
}

void ll_addr_init(void)
{
	u8_t mac[BDADDR_SIZE] = {0};

#if defined(CONFIG_SOC_FAMILY_NRF)
	/* Read address from nRF5-specific storage */
	mac[0] = (NRF_FICR->DEVICEADDR[0] >> 0)  & 0xff;
	mac[1] = (NRF_FICR->DEVICEADDR[0] >> 8)  & 0xff;
	mac[2] = (NRF_FICR->DEVICEADDR[0] >> 16) & 0xff;
	mac[3] = (NRF_FICR->DEVICEADDR[0] >> 24) & 0xff;
	mac[4] = (NRF_FICR->DEVICEADDR[1] >> 0)  & 0xff;
	mac[5] = (NRF_FICR->DEVICEADDR[1] >> 8)  & 0xff;
#else
	//random mac, though I think the only ble support is on nrf5x...
	bt_rand(mac, sizeof(mac));
#endif

	//set upper 2 bits on MSB
	mac[5] |= 0xc0;

	//set the random static addr
	ll_addr_set(1,mac);
}
