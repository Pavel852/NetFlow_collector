#include "ini.h"
#include <fstream>
#include <sstream>
#include <iostream>

INIParser::INIParser(const std::string& filename) : filename(filename) {}

bool INIParser::parse() {
    std::ifstream file(filename);
    if (!file) {
        std::cerr << "Cannot open configuration file: " << filename << std::endl;
        return false;
    }

    std::string line, currentSection;
    while (std::getline(file, line)) {
        // Remove comments
        size_t commentPos = line.find_first_of(";#");
        if (commentPos != std::string::npos)
            line = line.substr(0, commentPos);

        // Trim whitespace
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);

        if (line.empty())
            continue;

        // Section
        if (line.front() == '[' && line.back() == ']') {
            currentSection = line.substr(1, line.length() - 2);
            continue;
        }

        // Key-value pair
        size_t equalPos = line.find('=');
        if (equalPos == std::string::npos)
            continue;

        std::string key = line.substr(0, equalPos);
        std::string value = line.substr(equalPos + 1);

        // Trim whitespace
        key.erase(0, key.find_first_not_of(" \t\r\n"));
        key.erase(key.find_last_not_of(" \t\r\n") + 1);
        value.erase(0, value.find_first_not_of(" \t\r\n"));
        value.erase(value.find_last_not_of(" \t\r\n") + 1);

        data[currentSection][key] = value;
    }

    return true;
}

std::string INIParser::get(const std::string& section, const std::string& key, const std::string& defaultValue) const {
    auto secIt = data.find(section);
    if (secIt != data.end()) {
        auto keyIt = secIt->second.find(key);
        if (keyIt != secIt->second.end())
            return keyIt->second;
    }
    return defaultValue;
}

int INIParser::getInteger(const std::string& section, const std::string& key, int defaultValue) const {
    std::string value = get(section, key);
    if (!value.empty()) {
        try {
            return std::stoi(value);
        } catch (...) {
            // Conversion failed
        }
    }
    return defaultValue;
}
