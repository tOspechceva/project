#pragma once

#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <cstddef>
#include <iomanip>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

class PcapReader {
public:
    std::size_t read(const std::string& path, std::ostream& output) const {
        char error[PCAP_ERRBUF_SIZE]{};

        // pcap_close вызовется автоматически при выходе из метода.
        std::unique_ptr<pcap_t, decltype(&pcap_close)> capture(
            pcap_open_offline(path.c_str(), error), &pcap_close
        );

        if (!capture) {
            throw std::runtime_error(
                "Cannot open " + path + ": " + error
            );
        }

        pcap_pkthdr* header = nullptr;
        const u_char* data = nullptr;
        std::size_t count = 0;
std::size_t ipv4Count = 0;
int status;

const bool isEthernet = pcap_datalink(capture.get()) == DLT_EN10MB;
constexpr std::size_t ethernetSize = 14;
constexpr std::size_t minIpv4Size = 20;

while ((status = pcap_next_ex(capture.get(), &header, &data)) == 1) {
    ++count;
    

    char source[INET_ADDRSTRLEN]{};
    char destination[INET_ADDRSTRLEN]{};
    bool hasIpv4Addresses = false;

    // Разбираем каждый пакет. EtherType 0x0800 означает IPv4.
    if (isEthernet &&
        header->caplen >= ethernetSize + minIpv4Size &&
        data[12] == 0x08 && data[13] == 0x00) {
        const u_char* ip = data + ethernetSize;
        const std::size_t ipHeaderSize = (ip[0] & 0x0F) * 4;

        if ((ip[0] >> 4) == 4 &&
            ipHeaderSize >= minIpv4Size &&
            header->caplen >= ethernetSize + ipHeaderSize) {
            hasIpv4Addresses =
                inet_ntop(AF_INET, ip + 12, source, sizeof(source)) != nullptr &&
                inet_ntop(AF_INET, ip + 16, destination, sizeof(destination)) != nullptr;

            if (hasIpv4Addresses) {
                ++ipv4Count;
            }
        }
    }

    // Ограничиваем только вывод в терминал.
    if (count <= 5) {
        output << "Packet " << count
               << " | time: " << header->ts.tv_sec << '.'
               << std::setfill('0') << std::setw(6)
               << header->ts.tv_usec << std::setfill(' ')
               << " | captured: " << header->caplen << " bytes"
               << " | original: " << header->len << " bytes";

        if (hasIpv4Addresses) {
            output << " | IP: " << source << " -> " << destination;
        }

        output << '\n';
    }
}
if (status != PCAP_ERROR_BREAK) {
        throw std::runtime_error(pcap_geterr(capture.get()));
    }
    output << "IPv4 packets with parsed addresses: " << ipv4Count << '\n';
        return count;
    }
};