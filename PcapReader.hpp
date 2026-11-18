#pragma once

#include <arpa/inet.h>
#include <pcap/pcap.h>

#include <cstddef>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <map>
#include <memory>
#include <ostream>
#include <stdexcept>
#include <string>

class PcapReader {
private:
    enum class Kind { IPv4, RawIPv4, IPv6, ARP, MacControl, Other };

    struct Result {
        Kind kind = Kind::Other;
        std::string source;
        std::string destination;
        std::string reason;
    };

    static unsigned read16(const unsigned char* p) {
        return (static_cast<unsigned>(p[0]) << 8) | p[1];
    }

    static std::string formatMac(const unsigned char* p) {
        char text[18];
        std::snprintf(text, sizeof(text), "%02x:%02x:%02x:%02x:%02x:%02x",
                      unsigned(p[0]), unsigned(p[1]), unsigned(p[2]),
                      unsigned(p[3]), unsigned(p[4]), unsigned(p[5]));
        return text;
    }

    static Result ipPair(Kind kind, int family,
                         const unsigned char* source,
                         const unsigned char* destination) {
        char src[INET6_ADDRSTRLEN]{};
        char dst[INET6_ADDRSTRLEN]{};

        if (!inet_ntop(family, source, src, sizeof(src)) ||
            !inet_ntop(family, destination, dst, sizeof(dst))) {
            return {Kind::Other, {}, {}, "Address conversion failed"};
        }
        return {kind, src, dst, {}};
    }

    static bool hasIPv4Header(const unsigned char* p, std::size_t size) {
        if (size < 20 || (p[0] >> 4) != 4) {
            return false;
        }

        const std::size_t headerSize = (p[0] & 0x0f) * 4;
        return headerSize >= 20 && headerSize <= size &&
               read16(p + 2) >= headerSize;
    }

    // Проверка для записей этого дампа, в которых IPv4 начинается с байта 0.
    static bool confirmedRawIPv4(const unsigned char* p,
                                 std::size_t captured,
                                 std::size_t original) {
        if (!hasIPv4Header(p, captured) || read16(p + 2) != original) {
            return false;
        }

        const std::size_t headerSize = (p[0] & 0x0f) * 4;
        unsigned sum = 0;
        for (std::size_t i = 0; i < headerSize; i += 2) {
            sum += read16(p + i);
        }
        while (sum > 0xffff) {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        return sum == 0xffff;
    }

    static Result parse(const unsigned char* data, const pcap_pkthdr& header,
                        bool isEthernet) {
        const std::size_t size = header.caplen;
        if (!isEthernet) {
            return {Kind::Other, {}, {}, "Non-Ethernet capture"};
        }
        if (size < 14) {
            return {Kind::Other, {}, {}, "Incomplete Ethernet header"};
        }

        unsigned type = read16(data + 12);
        std::size_t offset = 14;

        while (type == 0x8100 || type == 0x88a8) {
            if (size - offset < 4) {
                return {Kind::Other, {}, {}, "Incomplete VLAN header"};
            }
            type = read16(data + offset + 2);
            offset += 4;
        }

        const unsigned char* p = data + offset;
        const std::size_t remaining = size - offset;

        if (type == 0x0800) {
            if (!hasIPv4Header(p, remaining)) {
                return {Kind::Other, {}, {}, "Invalid or incomplete IPv4 header"};
            }
            return ipPair(Kind::IPv4, AF_INET, p + 12, p + 16);
        }

        if (type == 0x86dd) {
            if (remaining < 40 || (p[0] >> 4) != 6) {
                return {Kind::Other, {}, {}, "Invalid or incomplete IPv6 header"};
            }
            return ipPair(Kind::IPv6, AF_INET6, p + 8, p + 24);
        }

        if (type == 0x0806) {
            if (remaining < 28 || read16(p) != 1 || read16(p + 2) != 0x0800 ||
                p[4] != 6 || p[5] != 4) {
                return {Kind::Other, {}, {}, "Unsupported or incomplete ARP"};
            }
            return ipPair(Kind::ARP, AF_INET, p + 14, p + 24);
        }

        if (type == 0x8808) {
            return {Kind::MacControl, formatMac(data + 6), formatMac(data),
                    "Ethernet MAC Control"};
        }

        if (confirmedRawIPv4(data, size, header.len)) {
            return ipPair(Kind::RawIPv4, AF_INET, data + 12, data + 16);
        }

        char reason[40];
        std::snprintf(reason, sizeof(reason), "Unparsed Ethernet field 0x%04x", type);
        return {Kind::Other, {}, {}, reason};
    }

public:
    std::size_t read(const std::string& path, std::ostream& output) const {
        char error[PCAP_ERRBUF_SIZE]{};
        std::unique_ptr<pcap_t, decltype(&pcap_close)> capture(
            pcap_open_offline(path.c_str(), error), &pcap_close
        );
        if (!capture) {
            throw std::runtime_error("Cannot open " + path + ": " + error);
        }

        // Сюда попадают кадры, у которых программа не извлекла IP-пару.
        std::ofstream report("unparsed_frames.csv");
        if (!report) {
            throw std::runtime_error("Cannot create unparsed_frames.csv");
        }
        report << "frame,source_mac,destination_mac,captured,original,reason\n";

        const bool isEthernet = pcap_datalink(capture.get()) == DLT_EN10MB;
        std::size_t total = 0;
        std::size_t ipv4 = 0;
        std::size_t rawIPv4 = 0;
        std::size_t ipv6 = 0;
        std::size_t arp = 0;
        std::size_t macControl = 0;
        std::size_t otherMac = 0;
        std::size_t noPair = 0;
        std::map<std::string, std::size_t> otherReasons;

        pcap_pkthdr* header = nullptr;
        const unsigned char* data = nullptr;
        int status;

        while ((status = pcap_next_ex(capture.get(), &header, &data)) == 1) {
            ++total;
            Result result = parse(data, *header, isEthernet);
            const char* label = "";

            switch (result.kind) {
                case Kind::IPv4:
                    ++ipv4;
                    label = "IPv4";
                    break;
                case Kind::RawIPv4:
                    ++ipv4;
                    ++rawIPv4;
                    label = "IPv4 (raw)";
                    break;
                case Kind::IPv6:
                    ++ipv6;
                    label = "IPv6";
                    break;
                case Kind::ARP:
                    ++arp;
                    label = "ARP sender/target";
                    break;
                case Kind::MacControl:
                    ++macControl;
                    label = "MAC Control";
                    break;
                case Kind::Other:
                    ++otherReasons[result.reason];
                    if (isEthernet && header->caplen >= 12) {
                        result.source = formatMac(data + 6);
                        result.destination = formatMac(data);
                        ++otherMac;
                        label = "MAC";
                    } else {
                        ++noPair;
                    }
                    break;
            }

            if (result.kind == Kind::MacControl || result.kind == Kind::Other) {
                report << total << ',' << result.source << ',' << result.destination
                       << ',' << header->caplen << ',' << header->len
                       << ',' << result.reason << '\n';
            }

            if (total <= 5) {
                output << "Packet " << total
                       << " | time: " << header->ts.tv_sec << '.'
                       << std::setfill('0') << std::setw(6)
                       << header->ts.tv_usec << std::setfill(' ')
                       << " | captured: " << header->caplen << " bytes"
                       << " | original: " << header->len << " bytes";
                if (!result.source.empty()) {
                    output << " | " << label << ": "
                           << result.source << " -> " << result.destination;
                }
                output << '\n';
            }
        }

        if (status != PCAP_ERROR_BREAK) {
            throw std::runtime_error(pcap_geterr(capture.get()));
        }
        report.close();
        if (!report) {
            throw std::runtime_error("Error writing unparsed_frames.csv");
        }

        output << "IPv4 packets: " << ipv4 << '\n'
               << "  Included raw IPv4: " << rawIPv4 << '\n'
               << "IPv6 packets: " << ipv6 << '\n'
               << "ARP packets with IPv4 sender/target: " << arp << '\n'
               << "Ethernet MAC Control: " << macControl << '\n'
               << "Other frames with MAC pair only: " << otherMac << '\n'
               << "Frames without any parsed pair: " << noPair << '\n';

        for (const auto& entry : otherReasons) {
            output << "  " << entry.first << ": " << entry.second << '\n';
        }
        return total;
    }
};