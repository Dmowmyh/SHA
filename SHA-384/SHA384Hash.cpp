#include "SHA384Hash.h"
#include <algorithm>
#include <boost/dynamic_bitset.hpp>
#include <cctype>
#include <cmath>
#include <cstring>
#include <iostream>
#include <vector>
#include <iomanip>
#include <sstream>

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

uint64_t SHA384Hash::k[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

//Function to perform the cyclic left rotation of blocks of data
template<typename T> T rotl(T data, size_t shift_bits)
{
    return (data << shift_bits) | (data >> ((sizeof(T)*8) - shift_bits));
}

template<typename T> T rotr(T data, size_t shift_bits)
{
    return (data >> shift_bits) | (data << ((sizeof(T)*8) - shift_bits));
}

template <typename T>
inline void make_big_endian(unsigned char* byte, T num)
{
    size_t numOfBytes = sizeof(T);
    for (size_t i = 0; i < numOfBytes; i++)
    {
        byte[i] = (uint8_t) (num >> ((sizeof(T)*8-8)-(i*8)));
    }
}

std::string SHA384Hash::GenerateSHA384Hash(const std::string& input)
{
    Reset();
    Process(input);
    Finish(input);
    std::string result(std::begin(signature), std::end(signature));

    return ConvertSignatureToStr();
}

std::string SHA384Hash::ConvertSignatureToStr()
{
    std::stringstream result;
    for (size_t i = 0; i < SHA384SIZE; i++)
    {
        result << std::setfill('0') << std::setw(2) << std::right << std::hex
               << (uint64_t)signature[i];
    }
    return result.str();
}

void SHA384Hash::Finish(const std::string& input)
{
    int padding = BLOCKSIZE-16-storage_used;
    if (padding <= 0)
        padding += BLOCKSIZE;
    if (padding > 0)
    {
        storage[storage_used] = 0x80;
        if (padding > 1)
            memset(storage + storage_used + 1, 0, padding-1);
        storage_used += padding;
    }
    make_big_endian<uint128_t>(storage+storage_used, input.size()*8);
    ProcessBlock(storage);

    make_big_endian<uint64_t>(signature,      H[0]);
    make_big_endian<uint64_t>(signature + 8,  H[1]);
    make_big_endian<uint64_t>(signature + 16, H[2]);
    make_big_endian<uint64_t>(signature + 24, H[3]);
    make_big_endian<uint64_t>(signature + 32, H[4]);
    make_big_endian<uint64_t>(signature + 40, H[5]);

}

void SHA384Hash::Process(const std::string& input)
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

void SHA384Hash::ProcessBlock(const unsigned char* block)
{
    uint64_t w[80], s0, s1, S0, S1, ch, temp1, temp2, maj;
    uint64_t a = H[0];
    uint64_t b = H[1];
    uint64_t c = H[2];
    uint64_t d = H[3];
    uint64_t e = H[4];
    uint64_t f = H[5];
    uint64_t g = H[6];
    uint64_t h = H[7];
    for (size_t i = 0; i < 16; i++)
    {
        w[i] = ((uint64_t)block[i * 8] << 56) + ((uint64_t)block[i * 8 + 1] << 48) +
               ((uint64_t)block[i * 8 + 2] << 40) + ((uint64_t)block[i * 8 + 3] << 32) +
               ((uint64_t)block[i * 8 + 4] << 24) + ((uint64_t)block[i * 8 + 5] << 16) +
               ((uint64_t)block[i * 8 + 6] << 8) + (block[i * 8 + 7]);
    }
    for (size_t j = 16; j < 80; j++)
    {
        s0 = rotr<uint64_t>(w[j - 15], 1) ^ rotr<uint64_t>(w[j - 15], 8) ^
             (w[j - 15] >> 7);
        s1 =
            rotr<uint64_t>(w[j - 2], 19) ^ rotr<uint64_t>(w[j - 2], 61) ^ (w[j - 2] >> 6);
        w[j] = w[j - 16] + s0 + w[j - 7] + s1;
    }
    for (size_t i = 0; i < 80; i++)
    {
        S1 = rotr<uint64_t>(e, 14) ^ rotr<uint64_t>(e, 18) ^ rotr<uint64_t>(e, 41);
        ch = (e & f) ^ ((~e) & g);
        temp1 = h + S1 + ch + k[i] + w[i];
        S0 = rotr<uint64_t>(a, 28) ^ rotr<uint64_t>(a, 34) ^ rotr<uint64_t>(a, 39);
        maj = (a & b) ^ (a & c) ^ (b & c);
        temp2 = S0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;
}

void SHA384Hash::Reset()
{
    H[0] = 0xcbbb9d5dc1059ed8;
    H[1] = 0x629a292a367cd507;
    H[2] = 0x9159015a3070dd17;
    H[3] = 0x152fecd8f70e5939;
    H[4] = 0x67332667ffc00b31;
    H[5] = 0x8eb44a8768581511;
    H[6] = 0xdb0c2e0d64f98fa7;
    H[7] = 0x47b5481dbefa4fa4;
    storage_used = 0;
}
