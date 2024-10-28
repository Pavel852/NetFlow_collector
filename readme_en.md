
# NetFlow Collector

NetFlow Collector is a C++ application designed for receiving, processing, and storing NetFlow v9 and IPFIX data from various network probes. The application supports multiple storage options (SQLite, MySQL, and CSV) and is configurable via an `.ini` file.

## Table of Contents
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Compilation](#compilation)
- [Extending the Application](#extending-the-application)
- [Author and Contact](#author-and-contact)
- [License](#license)

## Features
- Supports NetFlow v9 and IPFIX protocols.
- Configurable via `.ini` file.
- Stores data in SQLite, MySQL, or CSV formats.
- Automatically initializes database tables if they do not exist.
- Command-line options for database checks, debugging, and version info.

## Requirements
- **Operating System**: Ubuntu (or other Unix-based systems)
- **Compiler**: GCC with C++11 support
- **Libraries**:
  - `libsqlite3-dev` (for SQLite support)
  - `libmysqlclient-dev` (for MySQL support)
  - `libpthread` (thread support)
- **INIReader Library** for `.ini` file parsing
- **MySQL Server** (if using MySQL as backend)

## Installation

### Clone the Repository
Clone the project repository or download the source code files:
```bash
git clone https://github.com/Pavel852/netflow_collector.git
```

### Install Dependencies
Install the required libraries:
```bash
sudo apt-get update
sudo apt-get install build-essential libsqlite3-dev libmysqlclient-dev
```

## Configuration

The application uses an `.ini` file for configuration. By default, it looks for `nf_sond.ini` in the current directory, but you can specify a different path with the `--config` command-line option.

### Example `nf_sond.ini`
```ini
[Database]
type = sqlite
sqlite_path = /path/to/netflow_data.db
csv_path = /path/to/netflow_data.csv
mysql_host = localhost
mysql_port = 3306
mysql_user = user
mysql_password = password
mysql_database = netflow_db

[SondeCount]
count = 2

[Sonda1]
name = Sonda1
version = IPFIX
listen_address = 192.168.1.10
port = 2055

[Sonda2]
name = Sonda2
version = NetFlow_v9
listen_address = 192.168.1.11
port = 2056
```

### Configuration Parameters
- **[Database]**
  - `type`: Database type (`sqlite`, `csv`, or `mysql`).
  - `sqlite_path`: Path to the SQLite database.
  - `csv_path`: Path to the CSV file.
  - `mysql_host`, `mysql_port`, `mysql_user`, `mysql_password`, `mysql_database`: MySQL connection details.

- **[SondeCount]**
  - `count`: Number of probes to monitor.

- **[SondaX]**
  - `name`: Unique name for the probe.
  - `version`: Protocol version (`IPFIX` or `NetFlow_v9`).
  - `listen_address`: IP address to listen on.
  - `port`: Port number to listen on.

## Usage

Run the application from the command line:
```bash
./netflow_collector [options]
```

### Command-Line Options
- `-h`, `--help`: Show help message.
- `-v`, `--version`: Show version and author information.
- `-d`, `--display`: Display incoming packets and their status.
- `--config=PATH`: Specify path to the configuration file (default: `nf_sond.ini`).
- `--checkdb`: Check database connection and initialize the table if necessary.
- `--diag=PATH`: Enable debugging logs to the specified file.

### Examples

- **Run with default configuration**:
  ```bash
  ./netflow_collector
  ```

- **Run with a specific configuration file**:
  ```bash
  ./netflow_collector --config=/path/to/myconfig.ini
  ```

- **Check database connection**:
  ```bash
  ./netflow_collector --checkdb
  ```

## Compilation

Compile the application with the following command:
```bash
g++ -std=c++11 -o netflow_collector netflow_collector.cpp INIReader.cpp -lsqlite3 -lmysqlclient -lpthread
```

## Extending the Application
- **Implement Full Parsing**: Extend `processNetFlowV9Data` and `processIPFIXData` functions for full record processing.
- **Support Additional Databases**: Add support for other database systems as needed.
- **Logging**: Implement logging for monitoring errors and performance.

## Author and Contact
- **Author**: PB
- **Email**: pavel.bartos.pb@gmail.com
- **Version**: 2.1
- **Year**: 10/2024

## License
This project is open-source and available under the MIT License.
