#define CATCH_CONFIG_RUNNER

#include <catch.hpp>
#include "../SHA384Hash.h"
#include "../FkstHash.h"
#include <iostream>

std::string str128BytesLong = "This string should be exactly 128 bytes. Adding "
                              "information do reach 128 bytes. A little bit more. We "
                              "need 30 bytes mores. Ok ..";
std::string strLessThan128Bytes = "String less than 128 bytes";
std::string strBiggerThan128Bytes = "This string should be bigger than 128 bytes. The "
                                    "SHA algorithms are used in cryptography. For "
                                    "example they are used for storing passwords.";


std::string consoleInput;

int main(int argc, char* argv[])
{
    Catch::Session session;

    std::string input;
    using namespace Catch::clara;
    auto cli = session.cli() | Opt(input, "input")["-in"]["--input"]("Hash input");

    session.cli(cli);

    int returnCode =
        session.applyCommandLine(argc, argv);
    if (returnCode != 0) // Indicates a command line error
        return returnCode;

    // if set on the command line then 'height' is now set at this point
    if (input.size())
        consoleInput = input;

    return session.run();
}

TEST_CASE("TC01", "[module-test]")
{
    REQUIRE(str128BytesLong.size() == 128);
}

TEST_CASE("TC02", "[module-test]")
{
    REQUIRE(strBiggerThan128Bytes.size() > 128);
}

TEST_CASE("TC03", "[module-test]")
{
    REQUIRE(strLessThan128Bytes.size() < 128);
}

TEST_CASE("TC04", "[module-test]")
{
    SHA384Hash sha384;
    REQUIRE(sha384.GenerateSHA384Hash(str128BytesLong) ==
            "5158312de2ae4abf3e2d94b3cd6fcbedf3899f5cd5a823fe62d7c707bcd5ea20df5abcfd2a68"
            "044d39c75cd14a60a9b6");
}

TEST_CASE("TC05", "[module-test]")
{
    SHA384Hash sha384;
    REQUIRE(sha384.GenerateSHA384Hash(strBiggerThan128Bytes) ==
            "bb065750b811349a559842135f46f1678a79aea65c74843f2e475c66cd4557404d87435dd650"
            "f6cc2b9d5b98d9f9a3bd");
}

TEST_CASE("TC06", "[module-test]")
{
    SHA384Hash sha384;
    REQUIRE(sha384.GenerateSHA384Hash(strLessThan128Bytes) ==
            "d4c3cc402d7947fcd732c9ed6f356bab648df4c1f50e882ba2315e3a6fe710af4c0f5e74912c"
            "29dcf4b9ea1f95fb944a");
}

TEST_CASE("TC07", "[module-test]")
{
    SHA384Hash sha384;
    REQUIRE(sha384.GenerateSHA384Hash("") ==
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c"
            "0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
}

TEST_CASE("TC08", "[functional-test]")
{
    FkstHashFile hashFromFile;
    std::string hash = hashFromFile.GenerateHashFromFile(
        "/home/default/workspace/SHA-384/tests/testfile.txt");
    REQUIRE(hash == "addc6bb6663c4ea9f60c1874419a1108154d21208f922175dacfb5efb8be1edd7be2"
                    "f22fd2f664c8a3dfe1f29001e8c5");
}

TEST_CASE("TC09", "[functional-test]")
{
    FkstHashConsole hashFromConsole;
    std::string hash = hashFromConsole.GenerateHashFromConsole(consoleInput);
    REQUIRE(hash == "e862e2d17c990a8096bae2799bfb48313e3439b649a91a22a9a2271b1e8a51505057"
                    "c3aed8aa16f0a39612e81120809e");
}

TEST_CASE("TC10", "[functional-test]")
{
    FkstHashString hashFromString;
    std::string hash = hashFromString.GenerateHashFromString("Test string input");
    REQUIRE(hash == "387e120967357f7bbda8a68fead5ef7065189f475fc0161d246b2a9e2ab5979b6082"
                    "f121beea98c23e65cc0d5b31eccd");
}
