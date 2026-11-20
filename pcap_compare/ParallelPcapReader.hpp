#pragma once
#include "PacketParser.hpp"
#include <pcap/pcap.h>
#include <unistd.h>
#include <cstdlib>
#include <array>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <fstream>
#include <future>
#include <iomanip>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <thread>
#include <vector>

namespace traffic {
using Count = std::uint64_t;
enum Field { Total, IPv4, Raw, IPv6, Arp, Control, OtherMac, NoPair, Fields };
using Counts = std::array<Count, Fields>;
using AtomicCounts = std::array<std::atomic<Count>, Fields>;

struct Record {
    pcap_pkthdr header;
    std::size_t offset;
};

// Партия владеет байтами пакетов: очередное чтение libpcap не затрёт их.
struct Batch {
    Count first = 0;
    std::vector<Record> records;
    std::vector<unsigned char> bytes;
};

struct Output {
    std::ostringstream preview, csv;
    std::map<std::string, Count> reasons;
};

inline Output processBatch(const Batch& batch, AtomicCounts& shared) {
    Output out;
    Counts local{};
    Count number = batch.first;
    for (const Record& record : batch.records) {
        const auto& h = record.header;
        const auto* data = h.caplen ? batch.bytes.data() + record.offset : nullptr;
        Packet packet = parse(data, h.caplen, h.len);
        ++local[Total];
        const char* label = "";
        switch (packet.kind) {
            case Kind::IPv4: ++local[IPv4]; label = "IPv4"; break;
            case Kind::RawIPv4: ++local[IPv4]; ++local[Raw]; label = "IPv4 (raw)"; break;
            case Kind::IPv6: ++local[IPv6]; label = "IPv6"; break;
            case Kind::ARP: ++local[Arp]; label = "ARP sender/target"; break;
            case Kind::Control: ++local[Control]; label = "MAC Control"; break;
            case Kind::Other:
                ++local[packet.source.empty() ? NoPair : OtherMac];
                ++out.reasons[packet.reason];
                label = "MAC";
                break;
        }
        if (packet.kind == Kind::Other || packet.kind == Kind::Control)
            out.csv << number << ',' << packet.source << ',' << packet.destination << ','
                    << h.caplen << ',' << h.len << ',' << packet.reason << '\n';
        if (number <= 5) {
            out.preview << "Packet " << number << " | time: " << h.ts.tv_sec << '.'
                        << std::setfill('0') << std::setw(6) << h.ts.tv_usec
                        << " | captured: " << h.caplen << " bytes | original: " << h.len << " bytes";
            if (!packet.source.empty())
                out.preview << " | " << label << ": " << packet.source << " -> " << packet.destination;
            out.preview << '\n';
        }
        ++number;
    }
    // Синхронизация нужна один раз на партию, а не на каждый пакет.
    for (std::size_t i = 0; i < Fields; ++i)
        if (local[i]) shared[i].fetch_add(local[i], std::memory_order_relaxed);
    return out;
}

class WorkerPool {
    using Job = std::packaged_task<Output()>;
    std::deque<Job> jobs;
    std::vector<std::thread> workers;
    std::mutex mutex;
    std::condition_variable ready;
    bool closing = false;

    void worker() {
        for (;;) {
            Job job;
            {
                std::unique_lock<std::mutex> lock(mutex);
                ready.wait(lock, [&] { return closing || !jobs.empty(); });
                if (jobs.empty()) return;
                job = std::move(jobs.front());
                jobs.pop_front();
            }
            job(); // Разбор идёт вне блокировки. Ошибки передаются через future.
        }
    }

    void finish() {
        {
            std::lock_guard<std::mutex> lock(mutex);
            closing = true;
        }
        ready.notify_all();
        for (auto& thread : workers) thread.join();
    }

public:
    explicit WorkerPool(unsigned n) {
        try {
            for (unsigned i = 0; i < n; ++i) workers.emplace_back([this] { worker(); });
        } catch (...) { finish(); throw; }
    }
    ~WorkerPool() { finish(); }

    std::future<Output> submit(Batch batch, AtomicCounts& totals) {
        Job job([batch = std::move(batch), &totals] { return processBatch(batch, totals); });
        auto result = job.get_future();
        {
            std::lock_guard<std::mutex> lock(mutex);
            jobs.push_back(std::move(job));
        }
        ready.notify_one();
        return result;
    }
};

inline Counts run(const std::string& path, unsigned n, std::ostream* display) {
    if (!n) throw std::runtime_error("Worker count must be positive");
    char error[PCAP_ERRBUF_SIZE]{};
    // Имя "-" означает PCAP из stdin. Источник читается ровно один раз за прогон.
    std::unique_ptr<pcap_t, void(*)(pcap_t*)> input(pcap_open_offline(path.c_str(), error), pcap_close);
    if (!input) throw std::runtime_error(error);
    if (pcap_datalink(input.get()) != DLT_EN10MB) throw std::runtime_error("Expected Ethernet capture");

    // Отчёт сначала собирается во временном файле. Готовый публикуем целиком.
    char name[] = "unparsed_frames.csv.XXXXXX";
    int fd = mkstemp(name);
    if (fd < 0) throw std::runtime_error("Cannot create report in current directory");
    close(fd);
    struct Cleanup { const char* name; ~Cleanup() { std::remove(name); } } cleanup{name};
    std::ofstream report(name);
    report.exceptions(std::ios::badbit | std::ios::failbit);
    report << "frame,source_mac,destination_mac,captured,original,reason\n";

    AtomicCounts totals;
    for (auto& counter : totals) counter.store(0);
    WorkerPool pool(n);
    std::deque<std::future<Output>> pending;
    std::map<std::string, Count> reasons;
    auto collect = [&] {
        Output part = pending.front().get();
        pending.pop_front();
        report << part.csv.str();
        if (display) *display << part.preview.str();
        for (const auto& [reason, count] : part.reasons) reasons[reason] += count;
    };

    Count next = 1;
    Batch batch;
    auto submit = [&] {
        pending.push_back(pool.submit(std::move(batch), totals));
        batch = Batch{};
        // Ограничиваем одновременно очередь, занятые партии и ожидающие результаты.
        if (pending.size() >= 2ULL * n) collect();
    };

    pcap_pkthdr* header = nullptr;
    const unsigned char* data = nullptr;
    int status;
    while ((status = pcap_next_ex(input.get(), &header, &data)) == 1) {
        if (batch.records.empty()) batch.first = next;
        batch.records.push_back({*header, batch.bytes.size()});
        if (header->caplen)
            batch.bytes.insert(batch.bytes.end(), data, data + header->caplen);
        ++next;
        if (batch.records.size() == 256 || batch.bytes.size() >= 256 * 1024) submit();
    }
    if (status != PCAP_ERROR_BREAK) throw std::runtime_error(pcap_geterr(input.get()));
    if (!batch.records.empty()) submit();
    while (!pending.empty()) collect();
    report.close();
    if (std::rename(name, "unparsed_frames.csv") != 0) throw std::runtime_error("Cannot publish report");

    Counts result{};
    for (std::size_t i = 0; i < Fields; ++i) result[i] = totals[i].load();
    if (display) {
        *display << "IPv4 packets: " << result[IPv4] << "\n  Included raw IPv4: " << result[Raw]
                 << "\nIPv6 packets: " << result[IPv6] << "\nARP packets with IPv4 sender/target: " << result[Arp]
                 << "\nEthernet MAC Control: " << result[Control] << "\nOther frames with MAC pair only: " << result[OtherMac]
                 << "\nFrames without any parsed pair: " << result[NoPair] << '\n';
        for (const auto& [reason,count] : reasons) *display << "  " << reason << ": " << count << '\n';
        *display << "Total packets: " << result[Total] << '\n';
    }
    return result;
}
}
