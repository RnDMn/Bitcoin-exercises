/*
 * SHA-256 hash in C
 *
 * Copyright (c) 2017 Project Nayuki. (MIT License)
 * https://www.nayuki.io/page/fast-sha2-hashes-in-x86-assembly
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * - The above copyright notice and this permission notice shall be included in
 *   all copies or substantial portions of the Software.
 * - The Software is provided "as is", without warranty of any kind, express or
 *   implied, including but not limited to the warranties of merchantability,
 *   fitness for a particular purpose and noninfringement. In no event shall the
 *   authors or copyright holders be liable for any claim, damages or other
 *   liability, whether in an action of contract, tort or otherwise, arising from,
 *   out of or in connection with the Software or the use or other dealings in the
 *   Software.
 */

 /*
  *   **Slightly modified by RnDMn for his purpose.
  */

#ifndef Sha256_HPP_
#define Sha256_HPP_

#define BLOCK_SIZE 64 	/* Sizes in bytes */
#define HASH_SIZE 32
#define UINT32_SIZE 4

#define STATE_LEN 8	/* Lenghts in words */
#define BLOCK_LEN 16

class SHA256 final
{
  /*--- The actual hash ---*/
private:
  uint32_t hash[STATE_LEN];

  /*--- Initialize H0 values with Sha256 constants ---*/
public:
  static void sha256Init(uint32_t state[8]);
  
  /*--- Sha256, double Sha256, direct functions (with auto-padding) and retrieve method ---*/
public:
  void sha256Hash(const uint8_t message[], size_t len);
  void sha256Dhash(const uint8_t message[], size_t len);
  void sha256GetHash(uint8_t *output);

  /*--- 2 compression function variants: uchar array as input; 1024 bit uint32 block (manual padding requiered)---*/
public:
  static void sha256Compress(uint32_t state[8], const uint8_t block[64]);
  static void sha256StCompress(uint32_t state[8], const uint32_t block[16]);
private:
  static void sha256CompressCommon(uint32_t state[8], uint32_t schedule[64]); /* private common part*/

};


/*--- Macro definition of schedules and rounds defined in SHA256 algorithm spec. ---*/
#ifndef ROTR32
#define ROTR32(x, n)  (((0U + (x)) << (32 - (n))) | ((x) >> (n)))  // Assumes that x is uint32_t and 0 < n < 32
#endif

#ifndef SCHEDULE
#define SCHEDULE(i)  \
	schedule[i] = 0U + schedule[i - 16] + schedule[i - 7]  \
		+ (ROTR32(schedule[i - 15], 7) ^ ROTR32(schedule[i - 15], 18) ^ (schedule[i - 15] >> 3))  \
		+ (ROTR32(schedule[i - 2], 17) ^ ROTR32(schedule[i - 2], 19) ^ (schedule[i - 2] >> 10));
#endif

#ifndef ROUND
#define ROUND(a, b, c, d, e, f, g, h, i, k) \
	h = 0U + h + (ROTR32(e, 6) ^ ROTR32(e, 11) ^ ROTR32(e, 25)) + (g ^ (e & (f ^ g))) + UINT32_C(k) + schedule[i];  \
	d = 0U + d + h;  \
	h = 0U + h + (ROTR32(a, 2) ^ ROTR32(a, 13) ^ ROTR32(a, 22)) + ((a & (b | c)) | (b & c));
#endif

	/*------------------------------------------------------------------*/


/*--- macros to convert previous hash and merkle root from uint8_t array to uint32_t array*/
#define BE32PHASH_ENCODE(i)  \
	block1[i+1] = (uint32_t)prevhash[i * 4 + 0] << 24  \
	            | (uint32_t)prevhash[i * 4 + 1] << 16  \
	            | (uint32_t)prevhash[i * 4 + 2] <<  8  \
	            | (uint32_t)prevhash[i * 4 + 3] <<  0;

#define BE32MROOT_ENCODE(i)  \
	block1[i+9] = (uint32_t)merkleRoot[i * 4 + 0] << 24  \
	            | (uint32_t)merkleRoot[i * 4 + 1] << 16  \
	            | (uint32_t)merkleRoot[i * 4 + 2] <<  8  \
	            | (uint32_t)merkleRoot[i * 4 + 3] <<  0;


#endif /* SHA256_HPP_ */
