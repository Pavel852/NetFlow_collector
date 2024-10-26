// netflow_collector.cpp

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <memory>
#include <cstring>
#include <fstream>
#include <iomanip>    // For hex output
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <syslog.h>   // For logging
#include <errno.h>    // For errno
#include <ctime>      // For time conversion

// Include headers for INI parser and SQLite3
#include "ini.h"
#include <sqlite3.h>

// For MySQL
#include <mysql/mysql.h>

// Version and author information
#define VERSION "2.1"
#define AUTHOR "PB"
#define EMAIL "pavel.bartos.pb@gmail.com"
#define YEAR "10/2024"

#pragma pack(push, 1) // Align structures to 1 byte

// Structures for NetFlow v9
struct NetFlowV9Header {
    uint16_t version;
    uint16_t count;
    uint32_t sys_uptime;
    uint32_t unix_secs;
    uint32_t sequence_number;
    uint32_t source_id;
};

// Template FlowSet Header
struct NetFlowV9FlowSetHeader {
    uint16_t flowset_id;
    uint16_t length;
};

// Template Record
struct NetFlowV9TemplateRecord {
    uint16_t template_id;
    uint16_t field_count;
    // Followed by a list of Field Specifiers
};

// Field Specifier
struct NetFlowV9FieldSpecifier {
    uint16_t type;
    uint16_t length;
};

#pragma pack(pop)

// Configuration structures
struct DatabaseConfig {
    std::string type;
    std::string sqlite_path;
    std::string csv_path;
    std::string mysql_host;
    int mysql_port;
    std::string mysql_user;
    std::string mysql_password;
    std::string mysql_database;
};

struct SondaConfig {
    std::string name;
    std::string version;
    std::string filter_address; // Used to filter incoming packets by source IP
    int port;
};

struct FlowData {
    std::string SourceIP;
    std::string DestinationIP;
    int SourcePort;
    int DestinationPort;
    uint8_t Protocol;
    uint32_t PacketCount;
    uint32_t ByteCount;
    std::string FlowStart;
    std::string FlowEnd;
    std::string SourceSond;
    // Add additional fields as needed
};

// Abstract class for database operations
class DatabaseHandler {
public:
    virtual bool connect() = 0;
    virtual bool insertFlowData(const FlowData& data) = 0;
    virtual void close() = 0;
    virtual bool initializeTable() = 0;
    virtual bool checkConnection() = 0; // Function to check connection
};

// Implementation for SQLite
class SQLiteHandler : public DatabaseHandler {
private:
    sqlite3* db;
    std::string dbPath;

public:
    SQLiteHandler(const std::string& dbPath) : db(nullptr), dbPath(dbPath) {}

    bool connect() override {
        if (sqlite3_open(dbPath.c_str(), &db) != SQLITE_OK) {
            std::cerr << "Cannot open SQLite database: " << sqlite3_errmsg(db) << std::endl;
            syslog(LOG_ERR, "Cannot open SQLite database: %s", sqlite3_errmsg(db));
            return false;
        }
        // Initialize table
        if (!initializeTable()) {
            return false;
        }
        syslog(LOG_INFO, "Connected to SQLite database: %s", dbPath.c_str());
        return true;
    }

    bool checkConnection() override {
        if (sqlite3_open(dbPath.c_str(), &db) != SQLITE_OK) {
            std::cerr << "Cannot open SQLite database: " << sqlite3_errmsg(db) << std::endl;
            syslog(LOG_ERR, "Cannot open SQLite database: %s", sqlite3_errmsg(db));
            return false;
        }
        std::cout << "Successfully connected to SQLite database." << std::endl;
        syslog(LOG_INFO, "Successfully connected to SQLite database.");
        sqlite3_close(db);
        db = nullptr;
        return true;
    }

    bool initializeTable() override {
        // Check if table exists
        const char* sqlCheck = "SELECT name FROM sqlite_master WHERE type='table' AND name='NetFlowData';";
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, sqlCheck, -1, &stmt, nullptr) != SQLITE_OK) {
            std::cerr << "Error checking table existence: " << sqlite3_errmsg(db) << std::endl;
            syslog(LOG_ERR, "Error checking table existence: %s", sqlite3_errmsg(db));
            return false;
        }
        int rc = sqlite3_step(stmt);
        if (rc != SQLITE_ROW) {
            // Table does not exist, create it using sqlite.sql
            std::ifstream sqlFile("sqlite.sql");
            if (!sqlFile.is_open()) {
                std::cerr << "Cannot open sqlite.sql file for table creation." << std::endl;
                syslog(LOG_ERR, "Cannot open sqlite.sql file for table creation.");
                sqlite3_finalize(stmt);
                return false;
            }
            std::string sqlCreate((std::istreambuf_iterator<char>(sqlFile)), std::istreambuf_iterator<char>());
            sqlFile.close();

            char* errMsg = nullptr;
            if (sqlite3_exec(db, sqlCreate.c_str(), nullptr, nullptr, &errMsg) != SQLITE_OK) {
                std::cerr << "Error creating table: " << errMsg << std::endl;
                syslog(LOG_ERR, "Error creating table: %s", errMsg);
                sqlite3_free(errMsg);
                sqlite3_finalize(stmt);
                return false;
            }
            std::cout << "Table NetFlowData created in SQLite database." << std::endl;
            syslog(LOG_INFO, "Table NetFlowData created in SQLite database.");
        } else {
            std::cout << "Table NetFlowData already exists in SQLite database." << std::endl;
            syslog(LOG_INFO, "Table NetFlowData already exists in SQLite database.");
        }
        sqlite3_finalize(stmt);
        return true;
    }

    bool insertFlowData(const FlowData& data) override {
        // Implement data insertion into SQLite database
        std::string sqlInsert = "INSERT INTO NetFlowData (SourceIP, DestinationIP, SourcePort, DestinationPort, Protocol, PacketCount, ByteCount, FlowStart, FlowEnd, SourceSond) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, sqlInsert.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            std::cerr << "Error preparing insert statement: " << sqlite3_errmsg(db) << std::endl;
            syslog(LOG_ERR, "Error preparing insert statement: %s", sqlite3_errmsg(db));
            return false;
        }

        sqlite3_bind_text(stmt, 1, data.SourceIP.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, data.DestinationIP.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 3, data.SourcePort);
        sqlite3_bind_int(stmt, 4, data.DestinationPort);
        sqlite3_bind_int(stmt, 5, data.Protocol);
        sqlite3_bind_int(stmt, 6, data.PacketCount);
        sqlite3_bind_int(stmt, 7, data.ByteCount);
        sqlite3_bind_text(stmt, 8, data.FlowStart.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 9, data.FlowEnd.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 10, data.SourceSond.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            std::cerr << "Error inserting data: " << sqlite3_errmsg(db) << std::endl;
            syslog(LOG_ERR, "Error inserting data: %s", sqlite3_errmsg(db));
            sqlite3_finalize(stmt);
            return false;
        }

        sqlite3_finalize(stmt);
        return true;
    }

    void close() override {
        if (db) {
            sqlite3_close(db);
            db = nullptr;
        }
    }
};

// Implementation for MySQL
class MySQLHandler : public DatabaseHandler {
private:
    MYSQL* conn;
    DatabaseConfig dbConfig;

public:
    MySQLHandler(const DatabaseConfig& config) : conn(nullptr), dbConfig(config) {}

    bool connect() override {
        conn = mysql_init(nullptr);
        if (conn == nullptr) {
            std::cerr << "mysql_init() failed." << std::endl;
            syslog(LOG_ERR, "mysql_init() failed.");
            return false;
        }

        if (mysql_real_connect(conn, dbConfig.mysql_host.c_str(), dbConfig.mysql_user.c_str(),
                               dbConfig.mysql_password.c_str(), dbConfig.mysql_database.c_str(),
                               dbConfig.mysql_port, nullptr, 0) == nullptr) {
            std::cerr << "mysql_real_connect() failed: " << mysql_error(conn) << std::endl;
            syslog(LOG_ERR, "mysql_real_connect() failed: %s", mysql_error(conn));
            mysql_close(conn);
            return false;
        }

        // Initialize table
        if (!initializeTable()) {
            return false;
        }

        syslog(LOG_INFO, "Connected to MySQL database: %s", dbConfig.mysql_database.c_str());
        return true;
    }

    bool checkConnection() override {
        conn = mysql_init(nullptr);
        if (conn == nullptr) {
            std::cerr << "mysql_init() failed." << std::endl;
            syslog(LOG_ERR, "mysql_init() failed.");
            return false;
        }

        if (mysql_real_connect(conn, dbConfig.mysql_host.c_str(), dbConfig.mysql_user.c_str(),
                               dbConfig.mysql_password.c_str(), dbConfig.mysql_database.c_str(),
                               dbConfig.mysql_port, nullptr, 0) == nullptr) {
            std::cerr << "mysql_real_connect() failed: " << mysql_error(conn) << std::endl;
            syslog(LOG_ERR, "mysql_real_connect() failed: %s", mysql_error(conn));
            mysql_close(conn);
            return false;
        }

        std::cout << "Successfully connected to MySQL database." << std::endl;
        syslog(LOG_INFO, "Successfully connected to MySQL database.");
        mysql_close(conn);
        conn = nullptr;
        return true;
    }

    bool initializeTable() override {
        // Check if table exists
        std::string sqlCheck = "SHOW TABLES LIKE 'NetFlowData';";
        if (mysql_query(conn, sqlCheck.c_str())) {
            std::cerr << "Error checking table existence: " << mysql_error(conn) << std::endl;
            syslog(LOG_ERR, "Error checking table existence: %s", mysql_error(conn));
            return false;
        }
        MYSQL_RES* result = mysql_store_result(conn);
        if (result == nullptr) {
            std::cerr << "Error storing result: " << mysql_error(conn) << std::endl;
            syslog(LOG_ERR, "Error storing result: %s", mysql_error(conn));
            return false;
        }
        if (mysql_num_rows(result) == 0) {
            // Table does not exist, create it using mysql.sql
            std::ifstream sqlFile("mysql.sql");
            if (!sqlFile.is_open()) {
                std::cerr << "Cannot open mysql.sql file for table creation." << std::endl;
                syslog(LOG_ERR, "Cannot open mysql.sql file for table creation.");
                mysql_free_result(result);
                return false;
            }
            std::string sqlCreate((std::istreambuf_iterator<char>(sqlFile)), std::istreambuf_iterator<char>());
            sqlFile.close();

            if (mysql_query(conn, sqlCreate.c_str())) {
                std::cerr << "Error creating table: " << mysql_error(conn) << std::endl;
                syslog(LOG_ERR, "Error creating table: %s", mysql_error(conn));
                mysql_free_result(result);
                return false;
            }
            std::cout << "Table NetFlowData created in MySQL database." << std::endl;
            syslog(LOG_INFO, "Table NetFlowData created in MySQL database.");
        } else {
            std::cout << "Table NetFlowData already exists in MySQL database." << std::endl;
            syslog(LOG_INFO, "Table NetFlowData already exists in MySQL database.");
        }
        mysql_free_result(result);
        return true;
    }

    bool insertFlowData(const FlowData& data) override {
        // Implement data insertion into MySQL database
        std::string sqlInsert = "INSERT INTO NetFlowData (SourceIP, DestinationIP, SourcePort, DestinationPort, Protocol, PacketCount, ByteCount, FlowStart, FlowEnd, SourceSond) VALUES ('" +
                                data.SourceIP + "', '" + data.DestinationIP + "', " + std::to_string(data.SourcePort) + ", " + std::to_string(data.DestinationPort) + ", " +
                                std::to_string(data.Protocol) + ", " + std::to_string(data.PacketCount) + ", " + std::to_string(data.ByteCount) + ", '" + data.FlowStart + "', '" +
                                data.FlowEnd + "', '" + data.SourceSond + "');";
        if (mysql_query(conn, sqlInsert.c_str())) {
            std::cerr << "Error inserting data: " << mysql_error(conn) << std::endl;
            syslog(LOG_ERR, "Error inserting data: %s", mysql_error(conn));
            return false;
        }
        return true;
    }

    void close() override {
        if (conn) {
            mysql_close(conn);
            conn = nullptr;
        }
    }
};

// Implementation for CSV
class CSVHandler : public DatabaseHandler {
private:
    std::string csvPath;

public:
    CSVHandler(const std::string& csvPath) : csvPath(csvPath) {}

    bool connect() override {
        // Check if file exists
        std::ifstream file(csvPath);
        if (!file.good()) {
            // File does not exist, create it with header
            std::ofstream outFile(csvPath);
            if (!outFile.is_open()) {
                std::cerr << "Cannot create CSV file: " << csvPath << std::endl;
                syslog(LOG_ERR, "Cannot create CSV file: %s", csvPath.c_str());
                return false;
            }
            // Write header
            outFile << "SourceIP,DestinationIP,SourcePort,DestinationPort,Protocol,PacketCount,ByteCount,FlowStart,FlowEnd,SourceSond\n";
            outFile.close();
            std::cout << "CSV file created: " << csvPath << std::endl;
            syslog(LOG_INFO, "CSV file created: %s", csvPath.c_str());
        } else {
            // CSV file exists, proceed to use it
            std::cout << "CSV file is ready: " << csvPath << std::endl;
            syslog(LOG_INFO, "CSV file is ready: %s", csvPath.c_str());
        }
        return true;
    }

    bool checkConnection() override {
        std::ofstream outFile(csvPath, std::ios::app);
        if (!outFile.is_open()) {
            std::cerr << "Cannot open CSV file: " << csvPath << std::endl;
            syslog(LOG_ERR, "Cannot open CSV file: %s", csvPath.c_str());
            return false;
        }
        std::cout << "CSV file is accessible: " << csvPath << std::endl;
        syslog(LOG_INFO, "CSV file is accessible: %s", csvPath.c_str());
        outFile.close();
        return true;
    }

    bool initializeTable() override {
        // No additional initialization needed for CSV
        return true;
    }

    bool insertFlowData(const FlowData& data) override {
        // Implement data insertion into CSV
        std::ofstream outFile(csvPath, std::ios::app);
        if (!outFile.is_open()) {
            std::cerr << "Cannot open CSV file for appending: " << csvPath << std::endl;
            syslog(LOG_ERR, "Cannot open CSV file for appending: %s", csvPath.c_str());
            return false;
        }
        // Write data in CSV format
        outFile << data.SourceIP << ','
                << data.DestinationIP << ','
                << data.SourcePort << ','
                << data.DestinationPort << ','
                << static_cast<int>(data.Protocol) << ','
                << data.PacketCount << ','
                << data.ByteCount << ','
                << data.FlowStart << ','
                << data.FlowEnd << ','
                << data.SourceSond << '\n';
        outFile.close();
        return true;
    }

    void close() override {
        // No action needed for CSV on close
    }
};

// Global configuration variables
DatabaseConfig dbConfig;
std::vector<SondaConfig> sondaConfigs;
bool displayPackets = false; // For -d or --display option
bool enableLogging = false;   // Controlled by 'log' option in .ini file
std::string diagFilePath;     // For --diag=PATH option
std::mutex diagFileMutex;     // Mutex for thread-safe writing to diag file

// Function to load configuration
bool loadConfig(const std::string& filename) {
    INIParser parser(filename);
    if (!parser.parse()) {
        std::cerr << "Failed to parse configuration file." << std::endl;
        syslog(LOG_ERR, "Failed to parse configuration file: %s", filename.c_str());
        return false;
    }

    // Load database configuration
    dbConfig.type = parser.get("Database", "type", "");
    dbConfig.sqlite_path = parser.get("Database", "sqlite_path", "");
    dbConfig.csv_path = parser.get("Database", "csv_path", "");
    dbConfig.mysql_host = parser.get("Database", "mysql_host", "localhost");
    dbConfig.mysql_port = parser.getInteger("Database", "mysql_port", 3306);
    dbConfig.mysql_user = parser.get("Database", "mysql_user", "");
    dbConfig.mysql_password = parser.get("Database", "mysql_password", "");
    dbConfig.mysql_database = parser.get("Database", "mysql_database", "");

    // Load general configuration
    enableLogging = parser.getInteger("General", "log", 0) == 1;

    // Load probe configurations
    int sondaCount = parser.getInteger("SondeCount", "count", 0);
    for (int i = 1; i <= sondaCount; ++i) {
        std::string section = "Sonda" + std::to_string(i);
        SondaConfig sonda;
        sonda.name = parser.get(section, "name", "");
        sonda.version = parser.get(section, "version", "");
        sonda.filter_address = parser.get(section, "listen_address", ""); // Use 'listen_address' as 'filter_address'
        sonda.port = parser.getInteger(section, "port", 0);

        if (sonda.name.empty() || sonda.port == 0) {
            std::cerr << "Missing data in configuration for " << section << std::endl;
            syslog(LOG_ERR, "Missing data in configuration for %s", section.c_str());
            return false;
        }

        sondaConfigs.push_back(sonda);
    }

    return true;
}

// Function to create a socket
int createSocket(int port) {
    int sockfd;
    struct sockaddr_in servaddr;

    // Create socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Error creating socket");
        syslog(LOG_ERR, "Error creating socket: %s", strerror(errno));
        return -1;
    }

    // Set address and port
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY); // Bind to all interfaces
    servaddr.sin_port = htons(port);

    // Bind socket to address and port
    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("Error binding socket");
        syslog(LOG_ERR, "Error binding socket on port %d: %s", port, strerror(errno));
        close(sockfd);
        return -1;
    }

    return sockfd;
}

struct SondaRuntime {
    SondaConfig config;
    int socket_fd;
    std::unique_ptr<DatabaseHandler> dbHandler;
    std::map<uint16_t, std::vector<NetFlowV9FieldSpecifier>> templates;
};

std::vector<SondaRuntime> sondaRuntimes;

// Function to set up sockets
bool setupSockets() {
    for (auto& sondaConfig : sondaConfigs) {
        int sockfd = createSocket(sondaConfig.port);
        if (sockfd < 0) {
            std::cerr << "Cannot create socket for probe " << sondaConfig.name << std::endl;
            syslog(LOG_ERR, "Cannot create socket for probe %s", sondaConfig.name.c_str());
            return false;
        }

        SondaRuntime runtime;
        runtime.config = sondaConfig;
        runtime.socket_fd = sockfd;

        // Create database handler for each probe
        if (dbConfig.type == "sqlite") {
            runtime.dbHandler = std::make_unique<SQLiteHandler>(dbConfig.sqlite_path);
        } else if (dbConfig.type == "mysql") {
            runtime.dbHandler = std::make_unique<MySQLHandler>(dbConfig);
        } else if (dbConfig.type == "csv") {
            runtime.dbHandler = std::make_unique<CSVHandler>(dbConfig.csv_path);
        } else {
            std::cerr << "Database type not implemented: " << dbConfig.type << std::endl;
            syslog(LOG_ERR, "Database type not implemented: %s", dbConfig.type.c_str());
            return false;
        }

        if (!runtime.dbHandler->connect()) {
            std::cerr << "Cannot connect to database for probe " << sondaConfig.name << std::endl;
            syslog(LOG_ERR, "Cannot connect to database for probe %s", sondaConfig.name.c_str());
            return false;
        }

        sondaRuntimes.push_back(std::move(runtime));
    }
    return true;
}

// Function to check database connection (--checkdb parameter)
bool checkDatabase() {
    // Create database handler based on type
    std::unique_ptr<DatabaseHandler> dbHandler;
    if (dbConfig.type == "sqlite") {
        dbHandler = std::make_unique<SQLiteHandler>(dbConfig.sqlite_path);
    } else if (dbConfig.type == "mysql") {
        dbHandler = std::make_unique<MySQLHandler>(dbConfig);
    } else if (dbConfig.type == "csv") {
        dbHandler = std::make_unique<CSVHandler>(dbConfig.csv_path);
    } else {
        std::cerr << "Database type not implemented: " << dbConfig.type << std::endl;
        syslog(LOG_ERR, "Database type not implemented: %s", dbConfig.type.c_str());
        return false;
    }

    // Check connection
    if (!dbHandler->checkConnection()) {
        std::cerr << "Database connection failed." << std::endl;
        syslog(LOG_ERR, "Database connection failed.");
        return false;
    }

    // Initialize table or file
    if (!dbHandler->connect()) {
        std::cerr << "Failed to initialize database." << std::endl;
        syslog(LOG_ERR, "Failed to initialize database.");
        return false;
    }

    dbHandler->close();
    return true;
}

// Function to process NetFlow v9 data
void processNetFlowV9Data(char* buffer, ssize_t length, SondaRuntime& sonda) {
    char* ptr = buffer;
    NetFlowV9Header* header = reinterpret_cast<NetFlowV9Header*>(ptr);

    ptr += sizeof(NetFlowV9Header);
    length -= sizeof(NetFlowV9Header);

    uint16_t count = ntohs(header->count);

    while (length > 0) {
        if (length < 4) {
            std::cerr << "Incomplete FlowSet header." << std::endl;
            syslog(LOG_ERR, "Incomplete FlowSet header.");
            break;
        }

        NetFlowV9FlowSetHeader* flowsetHeader = reinterpret_cast<NetFlowV9FlowSetHeader*>(ptr);
        uint16_t flowsetID = ntohs(flowsetHeader->flowset_id);
        uint16_t flowsetLength = ntohs(flowsetHeader->length);

        ptr += sizeof(NetFlowV9FlowSetHeader);
        length -= sizeof(NetFlowV9FlowSetHeader);

        if (flowsetLength > length + sizeof(NetFlowV9FlowSetHeader)) {
            std::cerr << "FlowSet length exceeds remaining packet length." << std::endl;
            syslog(LOG_ERR, "FlowSet length exceeds remaining packet length.");
            break;
        }

        size_t flowsetDataLength = flowsetLength - sizeof(NetFlowV9FlowSetHeader);

        if (flowsetID == 0) {
            // Template FlowSet
            char* templatePtr = ptr;
            while (templatePtr < ptr + flowsetDataLength) {
                NetFlowV9TemplateRecord* templateRecord = reinterpret_cast<NetFlowV9TemplateRecord*>(templatePtr);
                uint16_t templateID = ntohs(templateRecord->template_id);
                uint16_t fieldCount = ntohs(templateRecord->field_count);

                templatePtr += sizeof(NetFlowV9TemplateRecord);

                std::vector<NetFlowV9FieldSpecifier> fields;

                for (int i = 0; i < fieldCount; ++i) {
                    NetFlowV9FieldSpecifier* fieldSpecifier = reinterpret_cast<NetFlowV9FieldSpecifier*>(templatePtr);
                    NetFlowV9FieldSpecifier field;
                    field.type = ntohs(fieldSpecifier->type);
                    field.length = ntohs(fieldSpecifier->length);
                    fields.push_back(field);

                    templatePtr += sizeof(NetFlowV9FieldSpecifier);
                }

                sonda.templates[templateID] = fields;
            }
        } else if (flowsetID > 255) {
            // Data FlowSet
            uint16_t templateID = flowsetID;
            if (sonda.templates.find(templateID) == sonda.templates.end()) {
                std::cerr << "Unknown template ID: " << templateID << std::endl;
                syslog(LOG_ERR, "Unknown template ID: %d", templateID);
                ptr += flowsetDataLength;
                length -= flowsetDataLength;
                continue;
            }

            std::vector<NetFlowV9FieldSpecifier>& fields = sonda.templates[templateID];
            char* recordPtr = ptr;
            size_t recordLength = 0;
            for (auto& field : fields) {
                recordLength += field.length;
            }

            while (recordPtr + recordLength <= ptr + flowsetDataLength) {
                FlowData flowData;
                size_t offset = 0;

                for (auto& field : fields) {
                    switch (field.type) {
                        case 8: // Source IP
                            flowData.SourceIP = inet_ntoa(*(struct in_addr*)(recordPtr + offset));
                            break;
                        case 12: // Destination IP
                            flowData.DestinationIP = inet_ntoa(*(struct in_addr*)(recordPtr + offset));
                            break;
                        case 7: // Source Port
                            flowData.SourcePort = ntohs(*(uint16_t*)(recordPtr + offset));
                            break;
                        case 11: // Destination Port
                            flowData.DestinationPort = ntohs(*(uint16_t*)(recordPtr + offset));
                            break;
                        case 4: // Protocol
                            flowData.Protocol = *(uint8_t*)(recordPtr + offset);
                            break;
                        case 2: // Packet Count
                            flowData.PacketCount = ntohl(*(uint32_t*)(recordPtr + offset));
                            break;
                        case 1: // Byte Count
                            flowData.ByteCount = ntohl(*(uint32_t*)(recordPtr + offset));
                            break;
                        case 21: // Flow Start SysUpTime
                            // Implement time calculation if needed
                            break;
                        case 22: // Flow End SysUpTime
                            // Implement time calculation if needed
                            break;
                        default:
                            // Ignore other fields
                            break;
                    }
                    offset += field.length;
                }

                flowData.SourceSond = sonda.config.name;

                // Insert the flow data into the database
                if (!sonda.dbHandler->insertFlowData(flowData)) {
                    std::cerr << "Failed to insert flow data into database." << std::endl;
                    syslog(LOG_ERR, "Failed to insert flow data into database.");
                }

                recordPtr += recordLength;
            }
        } else {
            // Ignore other FlowSet IDs
        }

        ptr += flowsetDataLength;
        length -= flowsetDataLength;
    }
}

// Function to process IPFIX data (placeholder)
void processIPFIXData(char* buffer, ssize_t length, SondaRuntime& sonda) {
    // Implement IPFIX data processing
    // Placeholder implementation
}

// Function to receive and process data
void receiveData(SondaRuntime& sonda) {
    char buffer[65536];
    struct sockaddr_in cliaddr;
    socklen_t len = sizeof(cliaddr);
    while (true) {
        ssize_t n = recvfrom(sonda.socket_fd, buffer, sizeof(buffer), 0, (struct sockaddr*)&cliaddr, &len);
        if (n < 0) {
            perror("Error receiving data");
            syslog(LOG_ERR, "Error receiving data: %s", strerror(errno));
            continue;
        }

        char source_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(cliaddr.sin_addr), source_ip, INET_ADDRSTRLEN);

        // Check if the source IP matches the filter address
        bool accepted = true;
        if (!sonda.config.filter_address.empty() && sonda.config.filter_address != source_ip) {
            // Ignore packet from other source
            accepted = false;
        }

        // Display packet information if displayPackets is true
        if (displayPackets) {
            std::cout << "Received packet from " << source_ip << " on port " << sonda.config.port;
            if (accepted) {
                std::cout << " [ACCEPTED]" << std::endl;
            } else {
                std::cout << " [REJECTED] (Expected source IP: " << sonda.config.filter_address << ")" << std::endl;
            }
        }

        // Write raw data to diagnostic file if diagFilePath is set
        if (!diagFilePath.empty()) {
            std::lock_guard<std::mutex> lock(diagFileMutex); // Ensure thread safety
            std::ofstream diagFile(diagFilePath, std::ios::app | std::ios::binary);
            if (diagFile.is_open()) {
                diagFile << "Probe: " << sonda.config.name << std::endl;
                diagFile << "Data: ";
                // Write data in hexadecimal format
                for (ssize_t i = 0; i < n; ++i) {
                    diagFile << std::hex << std::setw(2) << std::setfill('0') << (static_cast<unsigned int>(buffer[i]) & 0xFF) << ' ';
                }
                diagFile << std::dec << std::endl << std::endl; // Reset to decimal
                diagFile.close();
            } else {
                std::cerr << "Cannot open diagnostic file: " << diagFilePath << std::endl;
                syslog(LOG_ERR, "Cannot open diagnostic file: %s", diagFilePath.c_str());
            }
        }

        if (!accepted) {
            continue;
        }

        // Process the data
        uint16_t version = ntohs(*(uint16_t*)buffer);
        if (version == 9) {
            processNetFlowV9Data(buffer, n, sonda);
        } else if (version == 10) {
            processIPFIXData(buffer, n, sonda);
        } else {
            std::cerr << "Unknown NetFlow version: " << version << std::endl;
            syslog(LOG_ERR, "Unknown NetFlow version: %d", version);
        }
    }
}

// Function to display version and author information
void displayVersion() {
    std::cout << "NetFlow Collector Version " << VERSION << std::endl;
    std::cout << "Author: " << AUTHOR << std::endl;
    std::cout << "Email: " << EMAIL << std::endl;
    std::cout << "Year: " << YEAR << std::endl;
}

// Function to display help
void displayHelp() {
    std::cout << "Usage: ./netflow_collector [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -h, --help            Show this help message" << std::endl;
    std::cout << "  -v, --version         Show version and author information" << std::endl;
    std::cout << "  -d, --display         Display incoming packets and their acceptance status" << std::endl;
    std::cout << "  --config=PATH         Specify path to configuration file (default: nf_sond.ini)" << std::endl;
    std::cout << "  --checkdb             Check database connection and initialize table if necessary" << std::endl;
    std::cout << "  --diag=PATH           Enable diagnostic logging to the specified file" << std::endl;
    std::cout << std::endl;
    std::cout << "The application uses a configuration file to set up database connections and probes." << std::endl;
    std::cout << "Please refer to the documentation for the format of the .ini file." << std::endl;
}

// Main program function
int main(int argc, char* argv[]) {
    std::string configFile = "nf_sond.ini"; // Default configuration file
    bool checkDbOnly = false;

    // Parse command-line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-v" || arg == "--version") {
            displayVersion();
            return 0;
        } else if (arg == "-h" || arg == "--help") {
            displayHelp();
            return 0;
        } else if (arg == "-d" || arg == "--display") {
            displayPackets = true;
        } else if (arg.find("--config=") == 0) {
            configFile = arg.substr(9);
        } else if (arg == "--checkdb") {
            checkDbOnly = true;
        } else if (arg.find("--diag=") == 0) {
            diagFilePath = arg.substr(7);
        } else {
            std::cerr << "Unknown argument: " << arg << std::endl;
            displayHelp();
            return 1;
        }
    }

    // Load configuration
    if (!loadConfig(configFile)) {
        if (enableLogging) {
            openlog("netflow_collector", LOG_PID | LOG_CONS, LOG_USER);
            syslog(LOG_ERR, "Failed to load configuration file: %s", configFile.c_str());
            closelog();
        }
        return 1;
    }

    // Open syslog if logging is enabled
    if (enableLogging) {
        openlog("netflow_collector", LOG_PID | LOG_CONS, LOG_USER);
        syslog(LOG_INFO, "NetFlow Collector started.");
    }

    // If --diag is set, check if the file can be opened
    if (!diagFilePath.empty()) {
        std::ofstream diagFile(diagFilePath, std::ios::app);
        if (!diagFile.is_open()) {
            std::cerr << "Cannot open diagnostic file: " << diagFilePath << std::endl;
            syslog(LOG_ERR, "Cannot open diagnostic file: %s", diagFilePath.c_str());
            if (enableLogging) {
                syslog(LOG_ERR, "Cannot open diagnostic file: %s", diagFilePath.c_str());
                closelog();
            }
            return 1;
        }
        diagFile.close();
        std::cout << "Diagnostic logging enabled. Writing to: " << diagFilePath << std::endl;
        syslog(LOG_INFO, "Diagnostic logging enabled. Writing to: %s", diagFilePath.c_str());
    }

    // If --checkdb is specified, verify database connection and exit
    if (checkDbOnly) {
        if (checkDatabase()) {
            std::cout << "Database check completed successfully." << std::endl;
            if (enableLogging) {
                syslog(LOG_INFO, "Database check completed successfully.");
                closelog();
            }
            return 0;
        } else {
            std::cerr << "Database check failed." << std::endl;
            if (enableLogging) {
                syslog(LOG_ERR, "Database check failed.");
                closelog();
            }
            return 1;
        }
    }

    // Set up sockets
    if (!setupSockets()) {
        if (enableLogging) {
            syslog(LOG_ERR, "Failed to set up sockets.");
            closelog();
        }
        return 1;
    }

    // Start receiving data for each probe
    std::vector<std::thread> threads;

    for (auto& sonda : sondaRuntimes) {
        threads.emplace_back(receiveData, std::ref(sonda));
    }

    // Wait for threads to finish
    for (auto& t : threads) {
        t.join();
    }

    // Close databases
    for (auto& sonda : sondaRuntimes) {
        sonda.dbHandler->close();
    }

    if (enableLogging) {
        syslog(LOG_INFO, "NetFlow Collector stopped.");
        closelog();
    }

    return 0;
}

