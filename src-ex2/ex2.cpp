

#include <iostream>
#include <algorithm>
#include <compat/byteswap.h>
#include <util/strencodings.h>
#include <crypto/common.h>
#include "Sha256.h"




// ********************************************************************************************
// * SHA256 compression function and midstates exercise                                       *
// *                                                                                          *
// * ****** genesis block:                                                                    *
// * {                                                                                        *
// * \"hash\": \"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f\",          *
// * \"ver\": 1,                                                                              *
// * \"prev_block\": \"0000000000000000000000000000000000000000000000000000000000000000\",    * 
// * \"mrkl_root\": \"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b\",     *
// * \"time\": 1231006505,                                                                    *
// * \"bits\": 486604799,                                                                     *
// * \"nonce\": 2083236893,                                                                   *
// * \"n_tx\": 1,                                                                             *
// * \"size\": 285,                                                                           *
// * \"tx\": [ (....)                                                                         *
// *                                                                                          *
// * Expected Hash: 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f          *
// *                                                                                          *
// * Expected int. Hash: 6dd6c5716cc8e24313f619bab92ad24981f54ff7e24173a093f45f801e0342af     *
// ********************************************************************************************




int main ()
{
  /* 4 bytes items */
  uint32_t version, time, bits, nonce;
  version = 1;
  time = 1231006505; 
  bits = 486604799;
  nonce = 2083236893;


  /* 32 bytes items */
  std::string pHash = "0000000000000000000000000000000000000000000000000000000000000000";
  std::string merkleRoot = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";

  /* hex to bin and byteswap */
  std::vector<uint8_t> pHashBytes;
  pHashBytes = ParseHex(pHash);
  std::vector<uint8_t> merkleRootBytes;
  merkleRootBytes = ParseHex(merkleRoot);
  std::reverse(merkleRootBytes.begin(), merkleRootBytes.end());
  

  /* this implementation of sha256 takes either uint8_t or uint32_t arrays. We go wiht the latter. 
   * FIPS 180-3: paragraph 5.Preprocessing: prepare the message in multiple of 512 bits. As block 
   * header is 80 bytes (640 bits) we need two blocks of 512 bits each.  
   */ 
  uint32_t block1[BLOCK_LEN] {};
  uint32_t block2[BLOCK_LEN] {};

  /* fill in the blocks with the block header data (the message to be processed by the hash function)*/
  block1[0] = bswap_32(version);

  for (int i=0, j=0; i<STATE_LEN; i++, j+=4) {
    block1[i+1] = ReadBE32(&pHashBytes.front() + j);
  }

  for (int i=0, j=0; i<STATE_LEN-1; i++, j+=4) {    // block1 is already full
    block1[i+9] = ReadBE32(&merkleRootBytes.front() + j);
  }  
  
  block2[0] = ReadBE32(&merkleRootBytes.front() + 28);
  block2[1] = bswap_32(time);
  block2[2] = bswap_32(bits);
  block2[3] = bswap_32(nonce);

  /* FIPS 180-3: paragraph 5.1.1: padding for 80 bytes message*/
  block2[4] = 0b10000000 << 24;
  block2[15] = 0b0000001010000000;

  // print blocks
  uint8_t blocks[4*16]{};
  for (int i=0, j=0; i<16; i++, j+=4){
    WriteBE32(&blocks[j], block1[i]);
  }
  std::vector<uint8_t> block1Bytes(blocks, blocks + sizeof(blocks)/sizeof(blocks[0]));
  std::cout << "Block1: " << HexStr(block1Bytes)  << std::endl;

  for (int i=0, j=0; i<16; i++, j+=4){
    WriteBE32(&blocks[j], block2[i]);
  }  
  std::vector<uint8_t> block2Bytes(blocks, blocks + sizeof(blocks)/sizeof(blocks[0]));
  std::cout << "Block2: " << HexStr(block2Bytes)  << std::endl;

  
  /* first sha256 hash: we aply the compression function as many times as blocks we have in sequence, using 
   * the previous output as input for the next round
   */
  uint32_t hash[STATE_LEN];
  SHA256::sha256Init(hash);
  SHA256::sha256StCompress(hash, block1);   // in this step the variable hash contains we have the so called "midstate".
  SHA256::sha256StCompress(hash, block2);


  /* re-initialize block1 for second hash. Block 2 will not be used, as now the message is a hash 32 bytes */
  memset(block1, 0, sizeof(block1));
  memcpy(block1, hash, sizeof(hash));


  /* padding for 32 bytes */
  block1[8] = 0b10000000 << 24;
  block1[15] = 0b0000000100000000;


  /* double hash */
  SHA256::sha256Init(hash);
  SHA256::sha256StCompress(hash, block1);


  /* print double hash result to cout */
  std::vector<unsigned char> hashBytes;
  unsigned char tmp[UINT32_SIZE];
  for (int i=0; i<STATE_LEN; i++){
    WriteBE32(tmp, hash[i]);
    for (int i=0; i<UINT32_SIZE; i++){
      hashBytes.push_back(tmp[i]);
    }
  }
  std::reverse(hashBytes.begin(), hashBytes.end());
  std::string obtainedHash = HexStr(hashBytes);
  std::cout << "Genesis block double Sha256 hash: " << obtainedHash  << std::endl;

  
  /* check results */
  std::string expectedHash = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

  std::string::iterator ite, ito;
  ito = obtainedHash.begin();
  for (std::string::iterator ite = expectedHash.begin(); ite < expectedHash.end(); ite++, ito++) {
    if (*ite != *ito) {
      std::cout << "Test failed on position: " << *ite <<  std::endl;
      return 1;
    }
  }
  std::cout << "Test succeeded!"  << std::endl;

  
  return 0;
}

