#pragma once  // Подключаем этот заголовочный файл один раз при компиляции.

#include <arpa/inet.h>  // inet_ntop: переводит IP-адрес из байтов в текст.
#include <pcap/pcap.h>  // libpcap: открывает файл захвата и читает пакеты.

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
    // По типу записи определяем, какие адреса нашли и какой счётчик увеличить.
    enum class PacketType {
        IPv4,
        RawIPv4,     // IPv4-заголовок начинается с самого первого байта записи.
        IPv6,
        ARP,
        MacControl,  // Управляющий кадр Ethernet с парой MAC-адресов.
        Other
    };

    // Результат разбора ОДНОЙ записи из файла.
    struct PacketInfo {
        PacketType type;
        std::string source;       // Адрес источника.
        std::string destination;  // Адрес назначения, для ARP — целевой адрес.
        std::string note;         // Пояснение для диагностического отчёта.
    };

    // Общий результат для ВСЕГО файла.
    struct Statistics {
        std::size_t total = 0;
        std::size_t ipv4 = 0;
        std::size_t rawIPv4 = 0;   // Эти записи уже входят в ipv4.
        std::size_t ipv6 = 0;
        std::size_t arp = 0;
        std::size_t macControl = 0;
        std::size_t otherMac = 0;  // Протокол неизвестен, но пара MAC прочитана.
        std::size_t withoutPair = 0;

        // Ключ — причина, значение — сколько раз она встретилась.
        std::map<std::string, std::size_t> otherReasons;
    };

    // Некоторые поля заголовка занимают два байта.
    // В сети сначала записан старший байт, затем младший.
    // Например, байты 0x08 и 0x00 вместе дают число 0x0800.
    static unsigned readTwoBytes(const unsigned char* bytes) {
        return static_cast<unsigned>(bytes[0]) * 256 + bytes[1];
    }

    // MAC-адрес занимает 6 байт. Для вывода превращаем их в строку.
    // %02x печатает байт двумя шестнадцатеричными цифрами, например 0a.
    static std::string macToString(const unsigned char* bytes) {
        char text[18];  // 17 символов адреса и завершающий символ '\0'.

        std::snprintf(text, sizeof(text), "%02x:%02x:%02x:%02x:%02x:%02x",
                      unsigned(bytes[0]), unsigned(bytes[1]), unsigned(bytes[2]),
                      unsigned(bytes[3]), unsigned(bytes[4]), unsigned(bytes[5]));

        return text;
    }

    // family указывает формат: AF_INET для IPv4, AF_INET6 для IPv6.
    // Например, 4 байта IPv4 превращаются в строку "192.168.0.54".
    static std::string ipToString(int family, const unsigned char* bytes) {
        char text[INET6_ADDRSTRLEN]{};  // Буфера хватает для обоих форматов.

        if (inet_ntop(family, bytes, text, sizeof(text)) == nullptr) {
            throw std::runtime_error("Cannot convert IP address to text");
        }

        return text;
    }

    // Проверяем, достаточно ли сохранённых байтов для чтения IPv4-заголовка.
    static bool hasIPv4Header(const unsigned char* data, std::size_t size) {
        if (size < 20) {  // Минимальная длина IPv4-заголовка — 20 байт.
            return false;
        }

        // В одном байте находятся два поля:
        // старшие 4 бита — версия IP, младшие 4 — длина заголовка в словах.
        // Одно слово занимает 4 байта. Например, 0x45 означает IPv4 и 20 байт.
        const unsigned version = data[0] >> 4;
        const unsigned headerLength = (data[0] & 0x0F) * 4;

        // Начиная с байта 2 записана полная длина IP-пакета вместе с заголовком.
        const unsigned packetLength = readTwoBytes(data + 2);

        return version == 4 &&
               headerLength >= 20 &&
               headerLength <= size &&
               headerLength <= packetLength;
    }

    // Эту проверку используем для необычных записей нашего дампа:
    // в них IPv4 начинается с байта 0, где обычно ожидается Ethernet-заголовок.
    static bool isRawIPv4(const unsigned char* data,
                          std::size_t capturedSize,
                          std::size_t originalSize) {
        if (!hasIPv4Header(data, capturedSize)) {
            return false;
        }

        // Если вся запись — один IP-пакет, его длина должна совпасть
        // с исходной длиной записи, которую указал PCAP.
        if (readTwoBytes(data + 2) != originalSize) {
            return false;
        }

        const unsigned headerLength = (data[0] & 0x0F) * 4;
        unsigned sum = 0;

        // Складываем заголовок по два байта, включая поле контрольной суммы.
        for (unsigned i = 0; i < headerLength; i += 2) {
            sum += readTwoBytes(data + i);
        }

        // По правилам IPv4 перенос за пределы 16 бит прибавляется к младшим битам.
        while (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // Для корректного заголовка итоговая сумма содержит 16 единиц.
        return sum == 0xFFFF;
    }

    // ip указывает именно на НАЧАЛО IPv4-заголовка.
    // Поэтому смещения одинаковы для IPv4 внутри Ethernet и для RawIPv4.
    static PacketInfo readIPv4(const unsigned char* ip, PacketType type) {
        return {type,
                ipToString(AF_INET, ip + 12),  // Байты 12–15: источник.
                ipToString(AF_INET, ip + 16),  // Байты 16–19: назначение.
                ""};
    }

    // Разбираем одну запись. data указывает на её первый сохранённый байт.
    static PacketInfo parsePacket(const unsigned char* data,
                                  const pcap_pkthdr& header,
                                  bool isEthernet) {
        // caplen — сколько байтов реально есть в файле. Все проверки границ
        // делаем по caplen, потому что при захвате пакет могли обрезать.
        const std::size_t size = header.caplen;

        if (!isEthernet) {
            return {PacketType::Other, "", "", "Non-Ethernet capture"};
        }
        if (size < 14) {
            return {PacketType::Other, "", "", "Incomplete Ethernet header"};
        }

        // Ethernet: байты 0–5 — MAC назначения, 6–11 — MAC источника,
        // 12–13 — поле типа. После этих 14 байтов начинаются данные.
        unsigned etherType = readTwoBytes(data + 12);
        std::size_t offset = 14;

        // Между Ethernet и следующим протоколом могут находиться VLAN-теги.
        // Каждый тег добавляет 4 байта. Цикл учитывает и несколько тегов подряд.
        while (etherType == 0x8100 || etherType == 0x88A8) {
            if (size - offset < 4) {
                return {PacketType::Other, "", "", "Incomplete VLAN header"};
            }

            etherType = readTwoBytes(data + offset + 2);
            offset += 4;
        }

        // Теперь payload указывает на начало вложенного протокола.
        // Например, для обычного Ethernet с IPv4 это data + 14.
        const unsigned char* payload = data + offset;
        const std::size_t payloadSize = size - offset;

        switch (etherType) {
            case 0x0800:  // IPv4
                if (!hasIPv4Header(payload, payloadSize)) {
                    return {PacketType::Other, "", "", "Invalid IPv4 header"};
                }
                return readIPv4(payload, PacketType::IPv4);

            case 0x86DD:  // IPv6
                // Базовый заголовок IPv6 занимает 40 байт.
                // Адреса находятся в нём и занимают по 16 байт.
                if (payloadSize < 40 || (payload[0] >> 4) != 6) {
                    return {PacketType::Other, "", "", "Invalid IPv6 header"};
                }
                return {PacketType::IPv6,
                        ipToString(AF_INET6, payload + 8),   // Источник.
                        ipToString(AF_INET6, payload + 24),  // Назначение.
                        ""};

            case 0x0806:  // ARP
                // Проверяем формат, для которого справедливы смещения ниже:
                // Ethernet (1), IPv4 (0x0800), длина MAC 6 байт, длина IP 4 байта.
                if (payloadSize < 28 ||
                    readTwoBytes(payload) != 1 ||
                    readTwoBytes(payload + 2) != 0x0800 ||
                    payload[4] != 6 || payload[5] != 4) {
                    return {PacketType::Other, "", "", "Unsupported or incomplete ARP"};
                }

                // В ARP-запросе целевой IP принадлежит узлу, чей MAC ищут.
                return {PacketType::ARP,
                        ipToString(AF_INET, payload + 14),
                        ipToString(AF_INET, payload + 24),
                        ""};

            case 0x8808:  // Ethernet MAC Control
                // Управляющий кадр работает на уровне Ethernet.
                // Для него берём пару MAC из начала кадра.
                return {PacketType::MacControl,
                        macToString(data + 6),  // Источник.
                        macToString(data),      // Назначение.
                        "Ethernet MAC Control"};
        }

        // Сюда попадаем, если switch не распознал тип Ethernet.
        // Проверяем запись с самого начала. Так в нашем дампе нашлись 14 IPv4.
        if (isRawIPv4(data, size, header.len)) {
            return readIPv4(data, PacketType::RawIPv4);
        }

        // Сохраняем значение неизвестного типа, чтобы позже изучить кадр.
        char reason[40];
        std::snprintf(reason, sizeof(reason), "Unparsed Ethernet field 0x%04x",
                      etherType);
        return {PacketType::Other, "", "", reason};
    }

    // stats передаётся по ссылке: изменения сохраняются в общей статистике.
    static void countPacket(Statistics& stats, const PacketInfo& packet) {
        ++stats.total;  // Любая прочитанная запись учитывается ровно один раз.

        switch (packet.type) {
            case PacketType::IPv4:
                ++stats.ipv4;
                break;
            case PacketType::RawIPv4:
                ++stats.ipv4;     // Все IPv4, включая пакеты без Ethernet.
                ++stats.rawIPv4;  // Из них — сколько началось сразу с IPv4.
                break;
            case PacketType::IPv6:
                ++stats.ipv6;
                break;
            case PacketType::ARP:
                ++stats.arp;
                break;
            case PacketType::MacControl:
                ++stats.macControl;
                break;
            case PacketType::Other:
                ++stats.otherReasons[packet.note];
                if (packet.source.empty()) {
                    ++stats.withoutPair;
                } else {
                    ++stats.otherMac;
                }
                break;
        }
    }

    // Подпись перед парой адресов в терминале.
    static const char* addressLabel(PacketType type) {
        switch (type) {
            case PacketType::IPv4:       return "IPv4";
            case PacketType::RawIPv4:    return "IPv4 (raw)";
            case PacketType::IPv6:       return "IPv6";
            case PacketType::ARP:        return "ARP sender/target";
            case PacketType::MacControl: return "MAC Control";
            case PacketType::Other:      return "MAC";
        }
        return "";
    }

    static void printPacket(std::ostream& output, std::size_t number,
                            const pcap_pkthdr& header, const PacketInfo& packet) {
        // Время захвата состоит из секунд и микросекунд.
        // setw(6) и setfill('0') сохраняют ведущие нули в дробной части.
        output << "Packet " << number
               << " | time: " << header.ts.tv_sec << '.'
               << std::setfill('0') << std::setw(6) << header.ts.tv_usec
               << std::setfill(' ')
               << " | captured: " << header.caplen << " bytes"
               << " | original: " << header.len << " bytes";

        if (!packet.source.empty()) {
            output << " | " << addressLabel(packet.type) << ": "
                   << packet.source << " -> " << packet.destination;
        }
        output << '\n';
    }

    static void printStatistics(std::ostream& output, const Statistics& stats) {
        output << "IPv4 packets: " << stats.ipv4 << '\n'
               << "  Included raw IPv4: " << stats.rawIPv4 << '\n'
               << "IPv6 packets: " << stats.ipv6 << '\n'
               << "ARP packets with IPv4 sender/target: " << stats.arp << '\n'
               << "Ethernet MAC Control: " << stats.macControl << '\n'
               << "Other frames with MAC pair only: " << stats.otherMac << '\n'
               << "Frames without any parsed pair: " << stats.withoutPair << '\n';

        for (const auto& [reason, count] : stats.otherReasons) {
            output << "  " << reason << ": " << count << '\n';
        }
    }

public:
    // Основной метод класса. Возвращает число записей, прочитанных из файла.
    std::size_t read(const std::string& path, std::ostream& output) const {
        char error[PCAP_ERRBUF_SIZE]{};

        // pcap_open_offline открывает сохранённый дамп.
        // unique_ptr вызовет pcap_close и при обычном выходе, и при исключении.
        std::unique_ptr<pcap_t, decltype(&pcap_close)> capture(
            pcap_open_offline(path.c_str(), error), &pcap_close
        );
        if (!capture) {
            throw std::runtime_error("Cannot open " + path + ": " + error);
        }

        // Отчёт создаётся заново в папке запуска. В него попадут записи,
        // у которых не извлечена пара IP, в том числе кадры Ethernet MAC Control.
        std::ofstream report("unparsed_frames.csv");
        if (!report) {
            throw std::runtime_error("Cannot create unparsed_frames.csv");
        }
        report << "frame,source_mac,destination_mac,captured,original,reason\n";

        // Тип канального уровня читаем один раз перед обходом файла.
        const bool isEthernet = pcap_datalink(capture.get()) == DLT_EN10MB;
        Statistics stats;

        pcap_pkthdr* header = nullptr;       // Время захвата и размеры записи.
        const unsigned char* data = nullptr; // Байты текущей записи.
        int status;

        // pcap_next_ex возвращает 1, когда очередная запись успешно прочитана.
        // Обрабатываем её до следующего вызова: память для header и data
        // принадлежит libpcap и может быть использована для следующей записи.
        while ((status = pcap_next_ex(capture.get(), &header, &data)) == 1) {
            PacketInfo packet = parsePacket(data, *header, isEthernet);

            // Первых 12 байтов Ethernet достаточно для двух MAC-адресов,
            // даже если протокол внутри кадра распознать не удалось.
            if (packet.type == PacketType::Other && isEthernet && header->caplen >= 12) {
                packet.source = macToString(data + 6);
                packet.destination = macToString(data);
            }

            // Счётчики обновляем для каждого пакета. Ограничение в 5 записей
            // относится только к подробному выводу в терминал.
            countPacket(stats, packet);

            if (stats.total <= 5) {
                printPacket(output, stats.total, *header, packet);
            }

            if (packet.type == PacketType::MacControl || packet.type == PacketType::Other) {
                report << stats.total << ',' << packet.source << ','
                       << packet.destination << ',' << header->caplen << ','
                       << header->len << ',' << packet.note << '\n';
            }
        }

        // Для чтения из файла PCAP_ERROR_BREAK означает, что достигнут конец.
        // При ошибке сообщаем причину, чтобы не выдать частичный подсчёт за полный.
        if (status != PCAP_ERROR_BREAK) {
            throw std::runtime_error(pcap_geterr(capture.get()));
        }

        // При закрытии последние данные из буфера записываются в CSV.
        report.close();
        if (!report) {
            throw std::runtime_error("Error writing unparsed_frames.csv");
        }

        printStatistics(output, stats);
        return stats.total;
    }
};