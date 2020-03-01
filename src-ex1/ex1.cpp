

#include <iostream>
#include <crypto/common.h>
#include <hash.h>
#include <util/strencodings.h>
#include <serialize.h>
#include <streams.h>

/*
/  Calculate the hash of the genesis block.
/  Block Header (80 bytes) = version (4 bytes) + prev. hash (32 bytes) + merkle root (32 bytes) + time (4 bytes) + difficulty (4 bytes) + nonce (4 bytes)
/
/  version = 1;
/  previous hash = 0000000000000000000000000000000000000000000000000000000000000000;
/  merkle root = 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b;
/  time = 1231006505;
/  bits = 486604799;
/  nonce = 2083236893;
/
/  Expected double hash: 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
/  Expected intermediate hash: 6dd6c5716cc8e24313f619bab92ad24981f54ff7e24173a093f45f801e0342af
/
*/

#define HASH_SIZE 32     // sizes in bytes
#define UINT32_SIZE 4 
#define BLOCK_SIZE 80

int main()
{
  // 4 bytes items
  uint32_t version, time, bits, nonce;
  version = 1;
  time = 1231006505; 
  bits = 486604799;
  nonce = 2083236893;

  // uint32_t to uint8_t little endian conversions
  uint8_t tmp[UINT32_SIZE];

  WriteLE32(tmp, version);
  std::vector<uint8_t> versionBytes(tmp, tmp + UINT32_SIZE);
  
  WriteLE32(tmp, time);
  std::vector<uint8_t> timeBytes(tmp, tmp + UINT32_SIZE);

  WriteLE32(tmp, bits);
  std::vector<uint8_t> bitsBytes(tmp, tmp + UINT32_SIZE);

  WriteLE32(tmp, nonce);
  std::vector<uint8_t> nonceBytes(tmp, tmp + UINT32_SIZE);

  // 32 bytes items
  std::string pHash = "0000000000000000000000000000000000000000000000000000000000000000";
  std::string merkleRoot = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";

  std::vector<uint8_t> pHashBytes;
  std::vector<uint8_t> merkleRootBytes;

  // hex to bin conversion. Note that both are byte-reversed (prev hash is all 0 so doesn't require reverse)
  if (IsHex(pHash)){
    pHashBytes = ParseHex(pHash);
  }

  if (IsHex(merkleRoot)){
    merkleRootBytes = ParseHex(merkleRoot);
  }
  std::reverse(merkleRootBytes.begin(), merkleRootBytes.end());

  // TODO: Try to use some implemented class like CDataStream or CVectorWriter instead.  
  std::vector<unsigned char> bhBytes(versionBytes.begin(), versionBytes.end());
  bhBytes.insert(bhBytes.end(), pHashBytes.begin(), pHashBytes.end());
  bhBytes.insert(bhBytes.end(), merkleRootBytes.begin(), merkleRootBytes.end());
  bhBytes.insert(bhBytes.end(), timeBytes.begin(), timeBytes.end());
  bhBytes.insert(bhBytes.end(), bitsBytes.begin(), bitsBytes.end());
  bhBytes.insert(bhBytes.end(), nonceBytes.begin(), nonceBytes.end());

  // calculate double sha256
  CHash256 dHasher;
  dHasher.Write(&bhBytes.front(), BLOCK_SIZE);
  unsigned char hash[HASH_SIZE];
  dHasher.Finalize(hash);

  // print results to cout
  std::vector<unsigned char> hashBytes(hash, hash + HASH_SIZE);
  std::reverse(hashBytes.begin(), hashBytes.end());
  std::string obtainedHash = HexStr(hashBytes);
  std::cout << obtainedHash  << std::endl;

  // check results
  std::string expectedHash = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

  std::string::iterator ite, ito;
  ito = obtainedHash.begin();
  for (std::string::iterator ite = expectedHash.begin(); ite < expectedHash.end(); ite++, ito++) {
    if (*ite != *ito) {
      std::cout << "Test failed on position: " << *ite <<  std::endl;
      return 1;
    }
  }
  std::cout << "Test succeed!"  << std::endl;
  
  return 0;
}
