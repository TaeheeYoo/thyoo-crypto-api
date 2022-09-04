/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _CRYPTO_ECB_CBC_HELPER_H
#define _CRYPTO_ECB_CBC_HELPER_H

#include <crypto/internal/skcipher.h>
#include <asm/fpu/api.h>

/*
 * Mode helpers to instantiate parameterized skcipher ECB/CBC modes without
 * having to rely on indirect calls and retpolines.
 */

#define ECB_CBC_WALK_MAX	4096

#define ECB_WALK_START(req, bsize, fpu_blocks) do {			\
	void *ctx = crypto_skcipher_ctx(crypto_skcipher_reqtfm(req));	\
	unsigned int walked_bytes = 0;					\
	const int __bsize = (bsize);					\
	struct skcipher_walk walk;					\
	int err;							\
									\
	err = skcipher_walk_virt(&walk, (req), false);			\
	while (walk.nbytes > 0) {					\
		const u8 *src = walk.src.virt.addr;			\
		u8 __maybe_unused buf[(bsize)];				\
		u8 *dst = walk.dst.virt.addr;				\
		unsigned int nbytes;					\
		bool do_fpu;						\
									\
		if (walk.nbytes - walked_bytes >= ECB_CBC_WALK_MAX)	\
			nbytes = ECB_CBC_WALK_MAX;			\
		else							\
			nbytes = walk.nbytes - walked_bytes;		\
		walked_bytes += nbytes;					\
									\
		do_fpu = (fpu_blocks) != -1 &&				\
			 nbytes >= (fpu_blocks) * __bsize;		\
		if (do_fpu) kernel_fpu_begin()

#define CBC_WALK_START(req, bsize, fpu_blocks)				\
	ECB_WALK_START(req, bsize, fpu_blocks)

#define ECB_WALK_ADVANCE(blocks) do {					\
	dst += (blocks) * __bsize;					\
	src += (blocks) * __bsize;					\
	nbytes -= (blocks) * __bsize;					\
} while (0)

#define ECB_BLOCK(blocks, func) do {					\
	while (nbytes >= (blocks) * __bsize) {				\
		(func)(ctx, dst, src);					\
		ECB_WALK_ADVANCE(blocks);				\
	}								\
} while (0)

#define CBC_ENC_BLOCK(func) do {					\
	const u8 *__iv = walk.iv;					\
	while (nbytes >= __bsize) {					\
		crypto_xor_cpy(dst, src, __iv, __bsize);		\
		(func)(ctx, dst, dst);					\
		__iv = dst;						\
		ECB_WALK_ADVANCE(1);					\
	}								\
	memcpy(walk.iv, __iv, __bsize);					\
} while (0)

#define CBC_DEC_BLOCK(blocks, func) do {				\
	while (nbytes >= (blocks) * __bsize) {				\
		const u8 *__iv = src + ((blocks) - 1) * __bsize;	\
		if (dst == src)						\
			__iv = memcpy(buf, __iv, __bsize);		\
		(func)(ctx, dst, src);					\
		crypto_xor(dst, walk.iv, __bsize);			\
		memcpy(walk.iv, __iv, __bsize);				\
		ECB_WALK_ADVANCE(blocks);				\
	}								\
} while (0)

#define ECB_WALK_END()							\
		if (do_fpu) kernel_fpu_end();				\
		if (walked_bytes < walk.nbytes) continue;		\
		err = skcipher_walk_done(&walk, nbytes);		\
		walked_bytes = 0;					\
	}								\
	return err;							\
} while (0)

#define CBC_WALK_END() ECB_WALK_END()

#endif
