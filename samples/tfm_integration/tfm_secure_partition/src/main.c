/*
 * Copyright (c) 2021 Nordic Semiconductor ASA.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <tfm_veneers.h>
#include <tfm_ns_interface.h>

#include <hal/nrf_rtc.h>

#include "dummy_partition.h"

#define TIMER_PIN 10
#define DEBUG_PIN 11
static void my_timer_handler(struct k_timer *dummy)
{
}

static K_TIMER_DEFINE(my_timer, my_timer_handler, NULL);

void main(void)
{
	uint8_t digest[32];

    k_timer_start(&my_timer, K_USEC(100), K_USEC(300));

	for (int key = 0; key < 6; key++) {
		psa_status_t status = dp_secret_digest(key, digest, sizeof(digest));

		if (status == PSA_ERROR_INVALID_ARGUMENT && key == 5) {
			printk("No valid secret for key, received expected error code\n");
		} else if (status != PSA_SUCCESS) {
			printk("Status: %d\n", status);
		} else {
			printk("Digest: ");
			for (int i = 0; i < 32; i++) {
				printk("%02x", digest[i]);
			}
			printk("\n");
		}
	}
}
