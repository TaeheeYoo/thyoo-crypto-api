/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef ASM_X86_ARIA_AVX_H
#define ASM_X86_ARIA_AVX_H

#include <linux/types.h>

asmlinkage void aria_aesni_avx_encrypt_16way(const void *ctx, u8 *dst,
					     const u8 *src);
asmlinkage void aria_aesni_avx_decrypt_16way(const void *ctx, u8 *dst,
					     const u8 *src);
asmlinkage void aria_aesni_avx_ctr_crypt_16way(const void *ctx, u8 *dst,
					       const u8 *src,
					       u8 *keystream, u8 *iv);
asmlinkage void aria_aesni_avx_gfni_encrypt_16way(const void *ctx, u8 *dst,
						  const u8 *src);
asmlinkage void aria_aesni_avx_gfni_decrypt_16way(const void *ctx, u8 *dst,
						  const u8 *src);
asmlinkage void aria_aesni_avx_gfni_ctr_crypt_16way(const void *ctx, u8 *dst,
						    const u8 *src,
						    u8 *keystream, u8 *iv);

asmlinkage void aria_aesni_avx2_encrypt_32way(const void *ctx, u8 *dst,
					      const u8 *src);
asmlinkage void aria_aesni_avx2_decrypt_32way(const void *ctx, u8 *dst,
					      const u8 *src);
asmlinkage void aria_aesni_avx2_ctr_crypt_32way(const void *ctx, u8 *dst,
						const u8 *src,
						u8 *keystream, u8 *iv);
asmlinkage void aria_aesni_avx2_gfni_encrypt_32way(const void *ctx, u8 *dst,
						   const u8 *src);
asmlinkage void aria_aesni_avx2_gfni_decrypt_32way(const void *ctx, u8 *dst,
						   const u8 *src);
asmlinkage void aria_aesni_avx2_gfni_ctr_crypt_32way(const void *ctx, u8 *dst,
						     const u8 *src,
						     u8 *keystream, u8 *iv);

struct aria_avx_ops {
	void (*aria_encrypt_16way)(const void *ctx, u8 *dst, const u8 *src);
	void (*aria_decrypt_16way)(const void *ctx, u8 *dst, const u8 *src);
	void (*aria_ctr_crypt_16way)(const void *ctx, u8 *dst, const u8 *src,
				     u8 *keystream, u8 *iv);
	void (*aria_encrypt_32way)(const void *ctx, u8 *dst, const u8 *src);
	void (*aria_decrypt_32way)(const void *ctx, u8 *dst, const u8 *src);
	void (*aria_ctr_crypt_32way)(const void *ctx, u8 *dst, const u8 *src,
				     u8 *keystream, u8 *iv);
	void (*aria_encrypt_64way)(const void *ctx, u8 *dst, const u8 *src);
	void (*aria_decrypt_64way)(const void *ctx, u8 *dst, const u8 *src);
	void (*aria_ctr_crypt_64way)(const void *ctx, u8 *dst, const u8 *src,
				     u8 *keystream, u8 *iv);


};
#endif
