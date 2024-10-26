#ifndef INI_H
#define INI_H

#include <string>
#include <unordered_map>

class INIParser {
public:
    INIParser(const std::string& filename);
    bool parse();
    std::string get(const std::string& section, const std::string& key, const std::string& defaultValue = "") const;
    int getInteger(const std::string& section, const std::string& key, int defaultValue = 0) const;

private:
    std::string filename;
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> data;
};

#endif // INI_H
