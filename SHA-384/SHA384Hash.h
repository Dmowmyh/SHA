#pragma once
#include <string>
#include <vector>

constexpr size_t BLOCKSIZE = 128;
constexpr size_t SHA384SIZE = 48;

//32 bit words
using WORD = unsigned int;

class SHA384Hash
{
public:
    std::string GenerateSHA384Hash(const std::string& input);

private:
    uint64_t H[8] = {0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17,
                     0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511,
                     0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4};

    void Process(const std::string& input);
    void Finish(const std::string& input);
    void ProcessBlock(const unsigned char* block);
    void Reset();
    std::string ConvertSignatureToStr();

    /**
     * @brief BLOCKSIZE*bytes = 128*8 = 1024
     */
    unsigned char storage[BLOCKSIZE];
    unsigned char signature[SHA384SIZE];
    uint32_t storage_used = 0;
    static uint64_t k[80];
};
