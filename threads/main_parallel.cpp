#include "ParallelPcapReader.hpp"
#include <charconv>
#include <iostream>
#include <string_view>

int main(int argc, char** argv) {
    unsigned threads = 8;
    if (argc > 3) {
        std::cerr << "Usage: ./main_parallel [file.pcap] [threads]\n";
        return 1;
    }
    if (argc == 3) {
        std::string_view arg = argv[2];
        auto end = arg.data() + arg.size();
        auto result = std::from_chars(arg.data(), end, threads);
        if (result.ec != std::errc{} || result.ptr != end || threads == 0) {
            std::cerr << "Thread count must be a positive integer\n";
            return 1;
        }
    }
    try {
        traffic::ParallelPcapReader reader(argc > 1 ? argv[1] : "FIRST-2015-merged.pcap");
        reader.read(threads, std::cout);
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
