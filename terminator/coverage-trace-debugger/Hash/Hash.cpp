
#define UNICODE
#include <string>
#include <iostream>
#include <sstream>

int wmain(int argc, wchar_t* argv[])
{
    if (argc != 2) {
        std::wcout << "Expecting 1 argument but got " << argc << std::endl;
        return 1;
    }

    std::wstring path(argv[1]);
    auto hash = std::hash<std::wstring>{}(path);

    std::wcout
        << "I computed the hash of the path string (NOT the hash of the file contents at that path!):" << std::endl
        << "Input path:       " << path << std::endl
        << "Hash of path:     " << std::dec << hash << std::endl
        << "Hex hash of hash: " << std::hex << hash << std::endl
        << "BB file name:     " << std::hex << hash << "_bb.bin" << std::endl;

    return 0;
}
