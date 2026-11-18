#pragma once

#include <arpa/inet.h>
#include <pcap/pcap.h>

#include <cstddef>
#include <iomanip>
#include <memory>
#include <ostream>
#include <stdexcept>
#include <string>

class PcapReader {
private:
    // Двухбайтовое поле в сетевом порядке: сначала старший байт.
    static unsigned read16(const u_char* p) {
        return (static_cast<unsigned>(p[0]) << 8) | p[1];
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

        const bool isEthernet = pcap_datalink(capture.get()) == DLT_EN10MB;

        std::size_t count = 0;
        std::size_t ipv4Count = 0;
        std::size_t ipv6Count = 0;
        std::size_t arpCount = 0;

        pcap_pkthdr* header = nullptr;
        const u_char* data = nullptr;
        int status;

        while ((status = pcap_next_ex(capture.get(), &header, &data)) == 1) {
            ++count;

            // Адрес IPv6 в текстовом виде длиннее IPv4.
            char source[INET6_ADDRSTRLEN]{};
            char destination[INET6_ADDRSTRLEN]{};
            const char* addressLabel = nullptr;

            const std::size_t size = header->caplen;

            if (isEthernet && size >= 14) {
                unsigned etherType = read16(data + 12);
                std::size_t offset = 14;

                // Каждый VLAN-тег занимает 4 байта.
                while ((etherType == 0x8100 || etherType == 0x88A8) &&
                       size - offset >= 4) {
                    etherType = read16(data + offset + 2);
                    offset += 4;
                }

                const u_char* payload = data + offset;
                const std::size_t remaining = size - offset;

                if (etherType == 0x0800 && remaining >= 20 &&
                    (payload[0] >> 4) == 4) {
                    const std::size_t headerSize = (payload[0] & 0x0F) * 4;

                    if (headerSize >= 20 && remaining >= headerSize &&
                        inet_ntop(AF_INET, payload + 12, source, sizeof(source)) &&
                        inet_ntop(AF_INET, payload + 16, destination, sizeof(destination))) {
                        addressLabel = "IPv4";
                        ++ipv4Count;
                    }
                } else if (etherType == 0x86DD && remaining >= 40 &&
                           (payload[0] >> 4) == 6) {
                    if (inet_ntop(AF_INET6, payload + 8, source, sizeof(source)) &&
                        inet_ntop(AF_INET6, payload + 24, destination, sizeof(destination))) {
                        addressLabel = "IPv6";
                        ++ipv6Count;
                    }
                } else if (etherType == 0x0806 && remaining >= 28 &&
                           read16(payload) == 1 && read16(payload + 2) == 0x0800 &&
                           payload[4] == 6 && payload[5] == 4) {
                    // ARP поверх Ethernet: IPv4 отправителя и целевого узла.
                    if (inet_ntop(AF_INET, payload + 14, source, sizeof(source)) &&
                        inet_ntop(AF_INET, payload + 24, destination, sizeof(destination))) {
                        addressLabel = "ARP sender/target";
                        ++arpCount;
                    }
                }
            }

            if (count <= 5) {
                output << "Packet " << count
                       << " | time: " << header->ts.tv_sec << '.'
                       << std::setfill('0') << std::setw(6)
                       << header->ts.tv_usec << std::setfill(' ')
                       << " | captured: " << header->caplen << " bytes"
                       << " | original: " << header->len << " bytes";

                if (addressLabel != nullptr) {
                    output << " | " << addressLabel << ": "
                           << source << " -> " << destination;
                }

                output << '\n';
            }
        }

        if (status != PCAP_ERROR_BREAK) {
            throw std::runtime_error(pcap_geterr(capture.get()));
        }

        const std::size_t withoutPair = count - ipv4Count - ipv6Count - arpCount;

        output << "IPv4 packets: " << ipv4Count << '\n'
               << "IPv6 packets: " << ipv6Count << '\n'
               << "ARP packets with IPv4 sender/target: " << arpCount << '\n'
               << "Packets without a parsed address pair: " << withoutPair << '\n';

        return count;
    }
};