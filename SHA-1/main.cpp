#include "SHA1Hash.h"
#include <iostream>

int main()
{
    std::string aTest = "AbcdefgoAbcdefgoAbcdefgoAbcdefgoAbcdefgoAbcdefgoAbcdef";
    std::string fox = "The quick brown fox jumps over the lazy cog";

    SHA1Hash sha1;
    auto res = sha1.GenerateSHA1Hash(fox);
    //for (size_t i = 0; i < res.size(); i++)
    //{
        //std::cout << std::hex << (uint32_t) res[i] << std::endl;
    //}

}
