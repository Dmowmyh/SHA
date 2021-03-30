#pragma once
#include "SHA384Hash.h"
#include <fstream>
#include <sstream>

class FkstHashString
{
    public:
        std::string GenerateHashFromString(const std::string& string)
        {
            SHA384Hash sha;
            return sha.GenerateSHA384Hash(string);
        }
};

class FkstHashConsole
{
    public:
        std::string GenerateHashFromConsole(const std::string& string)
        {
            SHA384Hash sha;
            return sha.GenerateSHA384Hash(string);
        }
};

class FkstHashFile
{
    public:
        std::string GenerateHashFromFile(const std::string& path)
        {
            std::ostringstream buf;
            std::ifstream file;
            file.open(path.c_str());
            if (file)
            {
                buf << file.rdbuf();
                std::string withoutEOF = buf.str();
                withoutEOF.erase(withoutEOF.size()-1);
                SHA384Hash sha;
                return sha.GenerateSHA384Hash(withoutEOF);
            }
        }
};
