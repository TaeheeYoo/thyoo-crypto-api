/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef ASM_X86_ARIA_AVX_H
#define ASM_X86_ARIA_AVX_H

#include <linux/types.h>

struct aria_avx_ops {
	void (*aria_encrypt_16way)(const void *ctx, u8 *dst, const u8 *src);
	void (*aria_decrypt_16way)(const void *ctx, u8 *dst, const u8 *src);
	void (*aria_ctr_crypt_16way)(const void *ctx, u8 *dst, const u8 *src,
				     u8 *keystream, u8 *iv);
};
#endif
