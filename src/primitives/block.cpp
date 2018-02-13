// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <hash.h>
#include <tinyformat.h>
#include <utilstrencodings.h>
#include <crypto/common.h>

#include <btv_const.h>
#include <crypto/cryptonight.h>

#include <sync.h>
#include <fs.h>
#include <util.h>
#include <fstream>
#include <map>

std::map<uint256, uint256> hashMap;
std::map<uint256, uint256> tempMap;
CCriticalSection cs_hash;
bool loaded = false;

std::string getFilename()
{
    return GetDataDir().string() + "/cnhashmap.dat";
}

void loadCnHashMap()
{
    ENTER_CRITICAL_SECTION(cs_hash);
    std::ifstream in;
    try
    {
        if (loaded)
        {
            LEAVE_CRITICAL_SECTION(cs_hash);
            return;
        }

        loaded = true;
        in.open(getFilename(), std::ios::in | std::ios::binary);
        if (!in.is_open())
        {
            LEAVE_CRITICAL_SECTION(cs_hash);
            return;
        }

        in.seekg(0, std::ios::end);
        int hashCount = in.tellg() / 64;
        in.seekg(0, std::ios::beg);

        for (int i = 0 ; i < hashCount; ++i)
        {
            uint256 hash1;
            hash1.Unserialize(in);

            uint256 hash2;
            hash2.Unserialize(in);

            hashMap[hash1] = hash2;
        }
    }
    catch (...)
    {
        loaded = false;
    }

    if (in.is_open()) in.close();
    LEAVE_CRITICAL_SECTION(cs_hash);
}

bool getHash(const uint256 &hashSha256, uint256 &hashCn)
{
    loadCnHashMap();

    ENTER_CRITICAL_SECTION(cs_hash);
    try
    {
        std::map<uint256, uint256>::iterator it = hashMap.find(hashSha256);
        if (it == hashMap.end())
        {
			it = tempMap.find(hashSha256);
			if (it == tempMap.end())
			{
                LEAVE_CRITICAL_SECTION(cs_hash);
                return false;
			}
        }

        hashCn = it->second;
        LEAVE_CRITICAL_SECTION(cs_hash);
        return true;
    }
    catch (...) { }

    LEAVE_CRITICAL_SECTION(cs_hash);
    return false;
}

void writeHash(const uint256 &hashSha256, const uint256 &hashCn)
{
    ENTER_CRITICAL_SECTION(cs_hash);
    std::ofstream out;
    try
    {
        std::map<uint256, uint256>::iterator it = hashMap.find(hashSha256);
        if (it != hashMap.end())
        {
            LEAVE_CRITICAL_SECTION(cs_hash);
            return;
        }

        hashMap[hashSha256] = hashCn;
        out.open(getFilename(), std::ios::in | std::ios::out | std::ios::ate | std::ios::binary);
        if (!out.is_open()) out.open(getFilename(), std::ios::app | std::ios::binary);

        if (!out.is_open())
        {
            LEAVE_CRITICAL_SECTION(cs_hash);
            return;
        }

        out.seekp(0, std::ios::end);
        int count = out.tellp() / 64;
        out.seekp(count * 64, std::ios::beg);
        hashSha256.Serialize(out);
        hashCn.Serialize(out);
    }
    catch (...) { }

    if (out.is_open()) out.close();
    LEAVE_CRITICAL_SECTION(cs_hash);
}

void addTempMap(uint256 sha256, uint256 cnhash)
{
	ENTER_CRITICAL_SECTION(cs_hash);
	if (tempMap.size() == 1000000) tempMap.clear();
	tempMap[sha256] = cnhash;
	LEAVE_CRITICAL_SECTION(cs_hash);
}

uint256 CBlockHeader::GetHash() const
{
    uint256 ret = SerializeHash(*this);
    if (!IsBtvBranched()) // before branch
    {
        return ret;
    }
    else
    {
        uint256 result;
        if (getHash(ret, result))
		{
			return result;
		}

        char data[32];
        memset(data, 0, 32);
        cryptonight_hash(data, (const void*)this, 80);

        std::vector<unsigned char> vch;
        for (int i = 0; i < 32; ++i)
        {
            vch.push_back((unsigned char) data[i]);
        }

		uint256 hashCn(vch);
		addTempMap(GetHashSha256(), hashCn);
		return hashCn;
    }
}

uint256 CBlockHeader::GetHashSha256() const
{
    return SerializeHash(*this);
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
