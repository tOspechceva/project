#include "PcapReader.hpp"

#include <exception>
#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    // При запуске ./main программа ищет этот файл в текущей папке.
    std::string path = "FIRST-2015-merged.pcap";

    // При запуске ./main http.cap в argv[1] находится строка "http.cap".
    // argc учитывает и имя программы, поэтому проверяем argc > 1.
    if (argc > 1) {
        path = argv[1];
    }

    try {
        PcapReader reader;

        // Передаём путь к дампу и поток для вывода.
        // std::cout направляет вывод в терминал.
        const std::size_t total = reader.read(path, std::cout);
        std::cout << "Total packets: " << total << '\n';
    } catch (const std::exception& error) {
        // Сюда попадают, например, ошибки открытия дампа или записи CSV.
        // Код 1 сообщает оболочке, что программа завершилась с ошибкой.
        std::cerr << error.what() << '\n';
        return 1;
    }

    return 0;
}