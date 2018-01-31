#ifndef _CNHASHMAP_H_
#define _CNHASHMAP_H_

#include <uint256.h>

bool getHash(const uint256 &hashSha256, uint256 &hashCn);
void writeHash(const uint256 &hashSha256, const uint256 &hashCn);

#endif