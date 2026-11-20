#ifndef NUMBER_FILE_READER_HPP
#define NUMBER_FILE_READER_HPP

#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

class NumberFileReader {
public:
    std::vector<int> read(const std::string& path) const {
        std::ifstream file(path);
        if (!file) {
            throw std::runtime_error("Cannot open file: " + path);
        }

        std::vector<int> numbers;
        std::string token;

        while (file >> token) {
            std::istringstream input(token);
            int number;
            if (!(input >> number) || !input.eof()) {
                throw std::runtime_error("Invalid integer: " + token);
            }
            numbers.push_back(number);
        }

        if (file.bad() || !file.eof()) {
            throw std::runtime_error("Cannot read file: " + path);
        }

        return numbers;
    }
};

#endif
