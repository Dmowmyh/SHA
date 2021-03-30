#include "SHA1Hash.h"
#include <algorithm>
#include <boost/dynamic_bitset.hpp>
#include <cmath>
#include <cstring>
#include <iostream>
#include <vector>

//Function to perform the cyclic left rotation of blocks of data
inline unsigned int rotl32(unsigned int data, unsigned int shift_bits)
{
    return (data << shift_bits) | (data >> (32 - shift_bits));
}

// Save a 32-bit unsigned integer to memory, in big-endian order
inline void make_big_endian_uint32(unsigned char* byte, unsigned int num)
{
    byte[0] = (unsigned char)(num >> 24);
    byte[1] = (unsigned char)(num >> 16);
    byte[2] = (unsigned char)(num >> 8);
    byte[3] = (unsigned char)num;
}

inline void make_big_endian_uint64(unsigned char* byte, uint64_t num)
{
    byte[0] = (unsigned char)(num >> 56);
    byte[1] = (unsigned char)(num >> 48);
    byte[2] = (unsigned char)(num >> 40);
    byte[3] = (unsigned char)(num >> 32);
    byte[4] = (unsigned char)(num >> 24);
    byte[5] = (unsigned char)(num >> 16);
    byte[6] = (unsigned char)(num >> 8);
    byte[7] = (unsigned char)num;
}

void SHA1Hash::PrintHValues()
{
    std::cout << "H0: " << H0 << "\nH1: " << H1 << "\nH2: " << H2 << "\nH3: " << H3
              << "\nH4: " << H4 << std::endl;
}

std::string SHA1Hash::GenerateSHA1Hash(const std::string& input)
{
    Process(input);
    Finish(input);
    std::string result(std::begin(signature), std::end(signature));
    return result;
}

void SHA1Hash::Finish(const std::string& input)
{
    int padding = BLOCKSIZE-8-storage_used;
    if (padding <= 0)
        padding += BLOCKSIZE;
    if (padding > 0)
    {
        storage[storage_used] = 0x80;
        if (padding > 1)
            memset(storage + storage_used + 1, 0, padding-1);
        storage_used += padding;
    }
    make_big_endian_uint64(storage+storage_used, input.size()*8);
    ProcessBlock(storage);

    make_big_endian_uint32(signature,      H0);
    make_big_endian_uint32(signature + 4,  H1);
    make_big_endian_uint32(signature + 8,  H2);
    make_big_endian_uint32(signature + 12, H3);
    make_big_endian_uint32(signature + 16, H4);

    for (size_t i = 0; i < SHA1SIZE; i++)
    {
        std::cout << std::hex << (uint32_t) signature[i];
    }
}

void SHA1Hash::AppendMsgLength(unsigned char* block, size_t msgLength)
{
    uint64_t length = msgLength;
    make_big_endian_uint64(block, length);
}

void SHA1Hash::Process(const std::string& input)
{
    uint32_t processed = 0;
    while (processed + BLOCKSIZE <= input.size())
    {
        ProcessBlock((unsigned char*)input.data() + processed);
        processed += BLOCKSIZE;
    }
    if (processed < input.size())
    {
        memcpy(storage, (unsigned char*)input.data() + processed,
               input.size() - processed);
        storage_used = input.size()-processed;
    }
}

void SHA1Hash::ProcessBlock(const unsigned char* block)
{
    uint32_t f, k, temp, w[80];
    uint32_t a = H0;
    uint32_t b = H1;
    uint32_t c = H2;
    uint32_t d = H3;
    uint32_t e = H4;
    for (size_t i = 0; i < 16; i++)
    {
        w[i] = (block[i * 4] << 24) + (block[i * 4 + 1] << 16) + (block[i * 4 + 2] << 8) +
               block[i * 4 + 3];
    }
    for (size_t j = 16; j < 80; j++)
    {
        w[j] = rotl32(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
    }
    for (size_t j = 0; j < 80; j++)
    {
        if (j < 20)
        {
            f = (b & c) | ((~b) & d);
            k = 0x5a827999;
        }
        else if (j < 40)
        {
            f = b ^ c ^ d;
            k = 0x6ed9eba1;
        }
        else if (j < 60)
        {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdc;
        }
        else
        {
            f = b ^ c ^ d;
            k = 0xca62c1d6;
        }

        temp = rotl32(a, 5) + f + e + w[j] + k;
        e = d;
        d = c;
        c = rotl32(b, 30);
        b = a;
        a = temp;
    }

    H0 += a;
    H1 += b;
    H2 += c;
    H3 += d;
    H4 += e;
}
