/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Glue Code for the AVX2/AES-NI/GFNI assembler implementation of the ARIA Cipher
 *
 * Copyright (c) 2022 Taehee Yoo <ap420073@gmail.com>
 */

#include <crypto/algapi.h>
#include <crypto/internal/simd.h>
#include <crypto/aria.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/types.h>

#include "ecb_cbc_helpers.h"
#include "aria-avx.h"

asmlinkage void aria_aesni_avx512_gfni_encrypt_64way(const void *ctx, u8 *dst,
						   const u8 *src);
asmlinkage void aria_aesni_avx512_gfni_decrypt_64way(const void *ctx, u8 *dst,
						   const u8 *src);
asmlinkage void aria_aesni_avx512_gfni_ctr_crypt_64way(const void *ctx, u8 *dst,
						     const u8 *src,
						     u8 *keystream, u8 *iv);

struct aria_avx_ops aria_ops;

static int ecb_do_encrypt(struct skcipher_request *req, const u32 *rkey)
{
	ECB_WALK_START(req, ARIA_BLOCK_SIZE, ARIA_AESNI_PARALLEL_BLOCKS);
	ECB_BLOCK(ARIA_AESNI_AVX512_PARALLEL_BLOCKS, aria_ops.aria_encrypt_64way);
	ECB_BLOCK(ARIA_AESNI_AVX2_PARALLEL_BLOCKS, aria_ops.aria_encrypt_32way);
	ECB_BLOCK(ARIA_AESNI_PARALLEL_BLOCKS, aria_ops.aria_encrypt_16way);
	ECB_BLOCK(1, aria_encrypt);
	ECB_WALK_END();
}

static int ecb_do_decrypt(struct skcipher_request *req, const u32 *rkey)
{
	ECB_WALK_START(req, ARIA_BLOCK_SIZE, ARIA_AESNI_PARALLEL_BLOCKS);
	ECB_BLOCK(ARIA_AESNI_AVX512_PARALLEL_BLOCKS, aria_ops.aria_decrypt_64way);
	ECB_BLOCK(ARIA_AESNI_PARALLEL_BLOCKS, aria_ops.aria_decrypt_16way);
	ECB_BLOCK(1, aria_decrypt);
	ECB_WALK_END();
}

static int aria_avx512_ecb_encrypt(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct aria_ctx *ctx = crypto_skcipher_ctx(tfm);

	return ecb_do_encrypt(req, ctx->enc_key[0]);
}

static int aria_avx512_ecb_decrypt(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct aria_ctx *ctx = crypto_skcipher_ctx(tfm);

	return ecb_do_decrypt(req, ctx->dec_key[0]);
}

static int aria_avx512_set_key(struct crypto_skcipher *tfm, const u8 *key,
			    unsigned int keylen)
{
	return aria_set_key(&tfm->base, key, keylen);
}

static int aria_avx512_ctr_encrypt(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct aria_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct skcipher_walk walk;
	unsigned int nbytes;
	int err;

	err = skcipher_walk_virt(&walk, req, false);

	while ((nbytes = walk.nbytes) > 0) {
		const u8 *src = walk.src.virt.addr;
		u8 *dst = walk.dst.virt.addr;

		while (nbytes >= ARIA_AESNI_AVX512_PARALLEL_BLOCK_SIZE) {
			u8 keystream[ARIA_AESNI_AVX512_PARALLEL_BLOCK_SIZE];

			kernel_fpu_begin();
			aria_ops.aria_ctr_crypt_64way(ctx, dst, src, keystream,
						      walk.iv);
			kernel_fpu_end();
			dst += ARIA_AESNI_AVX512_PARALLEL_BLOCK_SIZE;
			src += ARIA_AESNI_AVX512_PARALLEL_BLOCK_SIZE;
			nbytes -= ARIA_AESNI_AVX512_PARALLEL_BLOCK_SIZE;
		}

		while (nbytes >= ARIA_AESNI_AVX2_PARALLEL_BLOCK_SIZE) {
			u8 keystream[ARIA_AESNI_AVX2_PARALLEL_BLOCK_SIZE];

			kernel_fpu_begin();
			aria_ops.aria_ctr_crypt_32way(ctx, dst, src, keystream,
						      walk.iv);
			kernel_fpu_end();
			dst += ARIA_AESNI_AVX2_PARALLEL_BLOCK_SIZE;
			src += ARIA_AESNI_AVX2_PARALLEL_BLOCK_SIZE;
			nbytes -= ARIA_AESNI_AVX2_PARALLEL_BLOCK_SIZE;
		}

		while (nbytes >= ARIA_AESNI_PARALLEL_BLOCK_SIZE) {
			u8 keystream[ARIA_AESNI_PARALLEL_BLOCK_SIZE];

			kernel_fpu_begin();
			aria_ops.aria_ctr_crypt_16way(ctx, dst, src, keystream,
						      walk.iv);
			kernel_fpu_end();
			dst += ARIA_AESNI_PARALLEL_BLOCK_SIZE;
			src += ARIA_AESNI_PARALLEL_BLOCK_SIZE;
			nbytes -= ARIA_AESNI_PARALLEL_BLOCK_SIZE;
		}

		while (nbytes >= ARIA_BLOCK_SIZE) {
			u8 keystream[ARIA_BLOCK_SIZE];

			memcpy(keystream, walk.iv, ARIA_BLOCK_SIZE);
			crypto_inc(walk.iv, ARIA_BLOCK_SIZE);

			aria_encrypt(ctx, keystream, keystream);

			crypto_xor_cpy(dst, src, keystream, ARIA_BLOCK_SIZE);
			dst += ARIA_BLOCK_SIZE;
			src += ARIA_BLOCK_SIZE;
			nbytes -= ARIA_BLOCK_SIZE;
		}

		if (walk.nbytes == walk.total && nbytes > 0) {
			u8 keystream[ARIA_BLOCK_SIZE];

			memcpy(keystream, walk.iv, ARIA_BLOCK_SIZE);
			crypto_inc(walk.iv, ARIA_BLOCK_SIZE);

			aria_encrypt(ctx, keystream, keystream);

			crypto_xor_cpy(dst, src, keystream, nbytes);
			dst += nbytes;
			src += nbytes;
			nbytes = 0;
		}
		err = skcipher_walk_done(&walk, nbytes);
	}

	return err;
}

static struct skcipher_alg aria_algs[] = {
	{
		.base.cra_name		= "__ecb(aria)",
		.base.cra_driver_name	= "__ecb-aria-avx512",
		.base.cra_priority	= 600,
		.base.cra_flags		= CRYPTO_ALG_INTERNAL,
		.base.cra_blocksize	= ARIA_BLOCK_SIZE,
		.base.cra_ctxsize	= sizeof(struct aria_ctx),
		.base.cra_module	= THIS_MODULE,
		.min_keysize		= ARIA_MIN_KEY_SIZE,
		.max_keysize		= ARIA_MAX_KEY_SIZE,
		.setkey			= aria_avx512_set_key,
		.encrypt		= aria_avx512_ecb_encrypt,
		.decrypt		= aria_avx512_ecb_decrypt,
	}, {
		.base.cra_name		= "__ctr(aria)",
		.base.cra_driver_name	= "__ctr-aria-avx512",
		.base.cra_priority	= 600,
		.base.cra_flags		= CRYPTO_ALG_INTERNAL,
		.base.cra_blocksize	= 1,
		.base.cra_ctxsize	= sizeof(struct aria_ctx),
		.base.cra_module	= THIS_MODULE,
		.min_keysize		= ARIA_MIN_KEY_SIZE,
		.max_keysize		= ARIA_MAX_KEY_SIZE,
		.ivsize			= ARIA_BLOCK_SIZE,
		.chunksize		= ARIA_BLOCK_SIZE,
		.walksize		= 16 * ARIA_BLOCK_SIZE,
		.setkey			= aria_avx512_set_key,
		.encrypt		= aria_avx512_ctr_encrypt,
		.decrypt		= aria_avx512_ctr_encrypt,
	}
};

static struct simd_skcipher_alg *aria_simd_algs[ARRAY_SIZE(aria_algs)];

static int __init aria_avx512_init(void)
{
	const char *feature_name;

	if (!boot_cpu_has(X86_FEATURE_AVX) ||
	    !boot_cpu_has(X86_FEATURE_AVX2) ||
	    !boot_cpu_has(X86_FEATURE_AVX512F) ||
	    !boot_cpu_has(X86_FEATURE_AVX512VL) ||
	    !boot_cpu_has(X86_FEATURE_AES) ||
	    !boot_cpu_has(X86_FEATURE_GFNI) ||
	    !boot_cpu_has(X86_FEATURE_OSXSAVE)) {
		pr_info("AVX512/GFNI or AES-NI instructions are not detected.\n");
		return -ENODEV;
	}

	if (!cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM |
			       XFEATURE_MASK_AVX512, &feature_name)) {
		pr_info("CPU feature '%s' is not supported.\n", feature_name);
		return -ENODEV;
	}

	aria_ops.aria_encrypt_16way = aria_aesni_avx_gfni_encrypt_16way;
	aria_ops.aria_decrypt_16way = aria_aesni_avx_gfni_decrypt_16way;
	aria_ops.aria_ctr_crypt_16way = aria_aesni_avx_gfni_ctr_crypt_16way;
	aria_ops.aria_encrypt_32way = aria_aesni_avx2_gfni_encrypt_32way;
	aria_ops.aria_decrypt_32way = aria_aesni_avx2_gfni_decrypt_32way;
	aria_ops.aria_ctr_crypt_32way = aria_aesni_avx2_gfni_ctr_crypt_32way;
	aria_ops.aria_encrypt_64way = aria_aesni_avx512_gfni_encrypt_64way;
	aria_ops.aria_decrypt_64way = aria_aesni_avx512_gfni_decrypt_64way;
	aria_ops.aria_ctr_crypt_64way = aria_aesni_avx512_gfni_ctr_crypt_64way;

	return simd_register_skciphers_compat(aria_algs,
					      ARRAY_SIZE(aria_algs),
					      aria_simd_algs);
}

static void __exit aria_avx512_exit(void)
{
	simd_unregister_skciphers(aria_algs, ARRAY_SIZE(aria_algs),
				  aria_simd_algs);
}

module_init(aria_avx512_init);
module_exit(aria_avx512_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Taehee Yoo <ap420073@gmail.com>");
MODULE_DESCRIPTION("ARIA Cipher Algorithm, AVX512/AES-NI/GFNI optimized");
MODULE_ALIAS_CRYPTO("aria");
MODULE_ALIAS_CRYPTO("aria-aesni-avx512");
