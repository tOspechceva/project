#include "PcapReader.hpp"

#include <cstddef>
#include <exception>
#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    const std::string path = argc > 1 ? argv[1] : "FIRST-2015-merged.pcap";

    try {
        PcapReader reader;
        const std::size_t total = reader.read(path, std::cout);
        std::cout << "Total packets: " << total << '\n';
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }

    return 0;
}