#pragma once
#include <string>
#include <vector>

#define BYTES4 4
#define BYTES6 6

constexpr size_t BLOCKSIZE = 64;
constexpr size_t SHA1SIZE = 20;

//32 bit words
using WORD = unsigned int;

class SHA1Hash
{
public:
    SHA1Hash() {}
    std::string GenerateSHA1Hash(const std::string& input);

private:

    uint32_t H0 = 0x6a09e667;
    uint32_t H1 = 0xbb67ae85;
    uint32_t H2 = 0x3c6ef372;
    uint32_t H3 = 0xa54ff53a;
    uint32_t H4 = 0x510e527f;
    uint32_t H5 = 0x9b05688c;
    uint32_t H6 = 0x1f83d9ab;
    uint32_t H7 = 0x5be0cd19;

    void Process(const std::string& input);
    void Finish(const std::string& input);
    void ProcessBlock(const unsigned char* block);
    void AppendMsgLength(unsigned char* block, size_t msgLength);

    /**
     * @brief BLOCKSIZE*bytes = 64*8 = 512
     */
    unsigned char storage[BLOCKSIZE];
    unsigned char signature[SHA1SIZE];
    unsigned char big_indian_signature[SHA1SIZE];
    uint32_t storage_used = 0;

    void PrintHValues();
};
