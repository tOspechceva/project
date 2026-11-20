#pragma once
#include "PacketParser.hpp"
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <atomic>
#include <cstdint>
#include <fstream>
#include <future>
#include <iomanip>
#include <map>
#include <memory>
#include <sstream>
#include <vector>

namespace traffic {

// Linux отображает файл в адресное пространство. Потоки читают свои диапазоны
// напрямую, без общей позиции чтения. Страницы подгружаются по необходимости.
class MappedFile {
public:
    const unsigned char* data;
    std::size_t size;
    explicit MappedFile(const char* path) {
        int fd = open(path, O_RDONLY);
        if (fd < 0) throw std::runtime_error(std::string("Cannot open ") + path);
        struct stat info{};
        if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size < 24) {
            close(fd);
            throw std::runtime_error("Expected a regular PCAP file with a full header");
        }
        size = info.st_size;
        void* mapping = mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);
        if (mapping == MAP_FAILED) throw std::runtime_error("Cannot map capture file");
        data = static_cast<const unsigned char*>(mapping);
    }
    ~MappedFile() { munmap(const_cast<unsigned char*>(data), size); }
    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;
};

struct Counters {
    std::atomic<std::uint64_t> total{0}, ipv4{0}, raw{0}, ipv6{0}, arp{0};
    std::atomic<std::uint64_t> control{0}, otherMac{0}, noPair{0};

    void count(const Packet& packet) {
        ++total;
        switch (packet.kind) {
            case Kind::RawIPv4: ++raw; ++ipv4; break;
            case Kind::IPv4: ++ipv4; break;
            case Kind::IPv6: ++ipv6; break;
            case Kind::ARP: ++arp; break;
            case Kind::Control: ++control; break;
            case Kind::Other:
                if (packet.source.empty()) ++noPair;
                else ++otherMac;
                break;
        }
    }
};

struct Range {
    std::size_t begin, end;
    std::uint64_t firstPacket;
};

// Каждый поток пишет только в собственный временный файл.
// Главный поток объединяет их в порядке расположения диапазонов.
struct WorkerOutput {
    std::unique_ptr<FILE, int (*)(FILE*)> rows{std::tmpfile(), &std::fclose};
    std::ostringstream preview;
    std::map<std::string,std::uint64_t> reasons;
};

class ParallelPcapReader {
    MappedFile file;
    bool littleEndian = false;
    bool nanoseconds = false;

    std::uint32_t number(const unsigned char* p, int bytes) const {
        std::uint32_t value = 0;
        for (int i = 0; i < bytes; ++i)
            value = (value << 8) | p[littleEndian ? bytes-1-i : i];
        return value;
    }

    // Заголовок записи занимает 16 байт. Поле по смещению 8 задаёт
    // длину сохранённых данных. Делить файл можно только между записями.
    std::vector<Range> ranges(unsigned threads) const {
        std::vector<Range> result;
        std::size_t begin = 24;
        std::uint64_t first = 1, next = 1;
        const std::size_t target = (file.size - 24) / threads;
        for (std::size_t pos = 24; pos < file.size;) {
            if (file.size - pos < 16) throw std::runtime_error("Incomplete record header");
            const auto captured = number(file.data + pos + 8, 4);
            if (captured > file.size - pos - 16)
                throw std::runtime_error("Incomplete packet data");
            pos += 16ULL + captured;
            ++next;
            if (pos - begin >= target && result.size() + 1 < threads && pos < file.size) {
                result.push_back({begin,pos,first});
                begin = pos;
                first = next;
            }
        }
        if (begin < file.size) result.push_back({begin,file.size,first});
        return result;
    }

    WorkerOutput readRange(Range range, Counters& stats) const {
        WorkerOutput out;
        if (!out.rows) throw std::runtime_error("Cannot create temporary report");
        auto frameNumber = range.firstPacket;
        for (auto pos = range.begin; pos < range.end; ++frameNumber) {
            const auto* record = file.data + pos;
            const auto captured = number(record+8, 4);
            const auto original = number(record+12, 4);
            const Packet packet = parse(record+16, captured, original);
            stats.count(packet);

            if (packet.kind == Kind::Other) ++out.reasons[packet.reason];
            if (packet.kind == Kind::Control || packet.kind == Kind::Other) {
                if (std::fprintf(out.rows.get(), "%llu,%s,%s,%u,%u,%s\n",
                        static_cast<unsigned long long>(frameNumber), packet.source.c_str(),
                        packet.destination.c_str(), captured, original, packet.reason.c_str()) < 0)
                    throw std::runtime_error("Cannot write temporary report");
            }
            if (frameNumber <= 5) {
                const char* labels[] = {"IPv4","IPv4 (raw)","IPv6","ARP sender/target","MAC Control","MAC"};
                auto micros = number(record+4, 4);
                if (nanoseconds) micros /= 1000;
                out.preview << "Packet " << frameNumber << " | time: " << number(record,4)
                            << '.' << std::setfill('0') << std::setw(6) << micros
                            << " | captured: " << captured << " bytes | original: " << original << " bytes";
                if (!packet.source.empty())
                    out.preview << " | " << labels[static_cast<int>(packet.kind)] << ": "
                                << packet.source << " -> " << packet.destination;
                out.preview << '\n';
            }
            pos += 16ULL + captured;
        }
        return out;
    }

public:
    explicit ParallelPcapReader(const char* path) : file(path) {
        const auto magic = number(file.data, 4);
        littleEndian = magic == 0xd4c3b2a1 || magic == 0x4d3cb2a1;
        nanoseconds = magic == 0xa1b23c4d || magic == 0x4d3cb2a1;
        if ((!littleEndian && !nanoseconds && magic != 0xa1b2c3d4) ||
            number(file.data+4,2) != 2 || number(file.data+6,2) != 4 ||
            (number(file.data+20,4) & 0xffff) != 1)
            throw std::runtime_error("Expected classic PCAP 2.4 with Ethernet link type");
    }

    void read(unsigned threads, std::ostream& output) const {
        if (threads == 0) throw std::invalid_argument("Thread count must be positive");
        Counters stats;
        std::vector<std::future<WorkerOutput>> workers;
        for (Range range : ranges(threads)) {
            workers.push_back(std::async(std::launch::async, [this, range, &stats] {
                return readRange(range, stats);
            }));
        }

        // get() ждёт результат соответствующего потока и передаёт его ошибки.
        std::vector<WorkerOutput> completed;
        for (auto& worker : workers) completed.push_back(worker.get());

        std::ofstream report("unparsed_frames.csv");
        report.exceptions(std::ios::failbit | std::ios::badbit);
        report << "frame,source_mac,destination_mac,captured,original,reason\n";
        std::map<std::string,std::uint64_t> reasons;
        for (auto& part : completed) {
            output << part.preview.str();
            for (const auto& [reason,count] : part.reasons) reasons[reason] += count;
            FILE* input = part.rows.get();
            if (std::fseek(input, 0, SEEK_SET) != 0) throw std::runtime_error("Cannot rewind report");
            char buffer[8192];
            while (auto n = std::fread(buffer,1,sizeof(buffer),input)) report.write(buffer,n);
            if (std::ferror(input)) throw std::runtime_error("Cannot read temporary report");
        }
        report.close();
        output << "IPv4 packets: " << stats.ipv4 << "\n  Included raw IPv4: " << stats.raw
               << "\nIPv6 packets: " << stats.ipv6 << "\nARP packets with IPv4 sender/target: " << stats.arp
               << "\nEthernet MAC Control: " << stats.control << "\nOther frames with MAC pair only: " << stats.otherMac
               << "\nFrames without any parsed pair: " << stats.noPair << '\n';
        for (const auto& [reason,count] : reasons) output << "  " << reason << ": " << count << '\n';
        output << "Total packets: " << stats.total << '\n';
    }
};
}
