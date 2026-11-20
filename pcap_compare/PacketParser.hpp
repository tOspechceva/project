#pragma once
#include <arpa/inet.h>
#include <cstddef>
#include <cstdio>
#include <stdexcept>
#include <string>

namespace traffic {
enum class Kind { IPv4, RawIPv4, IPv6, ARP, Control, Other };
struct Packet {
    Kind kind;
    std::string source, destination, reason;
};

inline unsigned network16(const unsigned char* p) {
    return unsigned(p[0]) * 256 + p[1];
}

inline std::string mac(const unsigned char* p) {
    char text[18];
    std::snprintf(text, sizeof(text), "%02x:%02x:%02x:%02x:%02x:%02x",
                  unsigned(p[0]), unsigned(p[1]), unsigned(p[2]),
                  unsigned(p[3]), unsigned(p[4]), unsigned(p[5]));
    return text;
}

inline std::string ip(int family, const unsigned char* p) {
    char text[INET6_ADDRSTRLEN];
    if (!inet_ntop(family, p, text, sizeof(text)))
        throw std::runtime_error("Cannot format IP");
    return text;
}

inline bool ipv4Header(const unsigned char* p, std::size_t n) {
    if (n < 20 || (p[0] >> 4) != 4) return false;
    unsigned length = (p[0] & 15) * 4;
    return length >= 20 && length <= n && network16(p + 2) >= length;
}

// Для записей без Ethernet проверяем также длину и контрольную сумму.
inline bool rawIPv4(const unsigned char* p, std::size_t n, unsigned original) {
    if (!ipv4Header(p, n) || network16(p + 2) != original) return false;
    unsigned sum = 0;
    for (unsigned i = 0; i < (p[0] & 15u) * 4; i += 2)
        sum += network16(p + i);
    while (sum > 65535) sum = (sum & 65535) + (sum >> 16);
    return sum == 65535;
}

inline Packet parse(const unsigned char* frame, std::size_t n, unsigned original) {
    auto other = [&](std::string reason) -> Packet {
        if (n < 12) return {Kind::Other, "", "", reason};
        return {Kind::Other, mac(frame + 6), mac(frame), reason};
    };
    if (n < 14) return other("Incomplete Ethernet header");
    unsigned type = network16(frame + 12);
    std::size_t offset = 14;
    while (type == 0x8100 || type == 0x88a8) {
        if (n - offset < 4) return other("Incomplete VLAN header");
        type = network16(frame + offset + 2);
        offset += 4;
    }
    const auto* p = frame + offset;
    const auto size = n - offset;
    switch (type) {
        case 0x0800:
            if (!ipv4Header(p, size)) return other("Invalid IPv4 header");
            return {Kind::IPv4, ip(AF_INET,p+12), ip(AF_INET,p+16), ""};
        case 0x86dd:
            if (size < 40 || (p[0] >> 4) != 6) return other("Invalid IPv6 header");
            return {Kind::IPv6, ip(AF_INET6,p+8), ip(AF_INET6,p+24), ""};
        case 0x0806:
            if (size < 28 || network16(p) != 1 || network16(p+2) != 0x0800 ||
                p[4] != 6 || p[5] != 4) return other("Unsupported or incomplete ARP");
            return {Kind::ARP, ip(AF_INET,p+14), ip(AF_INET,p+24), ""};
        case 0x8808:
            return {Kind::Control, mac(frame+6), mac(frame), "Ethernet MAC Control"};
    }
    if (rawIPv4(frame,n,original))
        return {Kind::RawIPv4, ip(AF_INET,frame+12), ip(AF_INET,frame+16), ""};
    char reason[40];
    std::snprintf(reason,sizeof(reason),"Unparsed Ethernet field 0x%04x",type);
    return other(reason);
}
}
