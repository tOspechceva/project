#include "ParallelPcapReader.hpp"
#include <algorithm>
#include <charconv>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <string_view>

using Clock = std::chrono::steady_clock;

unsigned positive(std::string_view arg) {
    unsigned value = 0;
    auto end = arg.data() + arg.size();
    auto result = std::from_chars(arg.data(), end, value);
    if (result.ec != std::errc{} || result.ptr != end || value == 0)
        throw std::runtime_error("Expected a positive integer");
    return value;
}

double median(std::vector<double> values) {
    std::sort(values.begin(), values.end());
    const auto middle = values.size() / 2;
    if (values.size() % 2) return values[middle];
    return (values[middle - 1] + values[middle]) / 2;
}

void benchmark(const std::string& path, unsigned maximum, unsigned repeats) {
    if (path == "-" || !std::filesystem::is_regular_file(path))
        throw std::runtime_error("Benchmark requires a repeatable PCAP file");
    if (repeats < 2) throw std::runtime_error("Use at least two measured runs");
    std::cout << "Прогрев: 1 рабочий поток" << std::endl;
    const auto expected = traffic::run(path, 1, nullptr);
    if (!expected[traffic::Total]) throw std::runtime_error("Empty capture");
    std::vector<std::vector<double>> times(maximum);
    std::cout << std::fixed << std::setprecision(3);
    for (std::size_t round = 0; round < repeats; ++round) {
        // Чередуем 1..N и N..1, чтобы один вариант не всегда шёл первым.
        for (std::size_t step = 0; step < maximum; ++step) {
            unsigned n = round % 2 ? maximum - step : step + 1;
            const auto start = Clock::now();
            const auto actual = traffic::run(path, n, nullptr);
            double seconds = std::chrono::duration<double>(Clock::now() - start).count();
            if (actual != expected) throw std::runtime_error("Packet counters differ between runs");
            times[n-1].push_back(seconds);
            std::cout << "Прогон " << round+1 << " | потоков " << n
                      << " | " << seconds << " с | " << expected[traffic::Total]/seconds
                      << " пак/с" << std::endl;
        }
    }

    double baseline = median(times.front());
    double fastestMedian = baseline;
    double peak = 0;
    std::size_t optimal = 1, peakWorkers = 1;
    std::cout << "\nОбработано пакетов за прогон: " << expected[traffic::Total]
              << "\nПотоки | мин с | медиана с | макс с | пак/с по медиане | пик пак/с | ускорение\n";
    for (std::size_t i = 0; i < times.size(); ++i) {
        const auto [lo,hi] = std::minmax_element(times[i].begin(), times[i].end());
        double typical = median(times[i]);
        double bestRate = expected[traffic::Total] / *lo;
        if (typical < fastestMedian) { fastestMedian = typical; optimal = i+1; }
        if (bestRate > peak) { peak = bestRate; peakWorkers = i+1; }
        std::cout << i+1 << " | " << *lo << " | " << typical << " | " << *hi
                  << " | " << expected[traffic::Total]/typical << " | " << bestRate
                  << " | " << baseline/typical << "x\n";
    }
    std::cout << "Оптимум по медиане: " << optimal << " раб. потоков, "
              << fastestMedian << " с, ускорение " << baseline/fastestMedian << "x\n"
              << "Максимальная скорость одного прогона: " << peak
              << " пак/с при " << peakWorkers << " раб. потоках\n";
}

int main(int argc, char** argv) {
    try {
        if (argc > 1 && std::string_view(argv[1]) == "--bench") {
            if (argc != 5) throw std::runtime_error("Usage: main_parallel --bench file.pcap max_workers runs");
            benchmark(argv[2], positive(argv[3]), positive(argv[4]));
        } else {
            if (argc > 3) throw std::runtime_error("Usage: main_parallel [file.pcap|-] [workers]");
            traffic::run(argc > 1 ? argv[1] : "FIRST-2015-merged.pcap",
                         argc > 2 ? positive(argv[2]) : 4, &std::cout);
        }
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
