
# NetFlow Collector

NetFlow Collector je C++ aplikace navržená k přijímání, zpracování a ukládání dat NetFlow v9 a IPFIX z různých síťových sond. Aplikace podporuje několik typů úložišť (SQLite, MySQL a CSV) a je nakonfigurovatelná prostřednictvím `.ini` souboru.

## Obsah
- [Funkce](#funkce)
- [Požadavky](#požadavky)
- [Instalace](#instalace)
- [Konfigurace](#konfigurace)
- [Použití](#použití)
- [Kompilace](#kompilace)
- [Rozšíření aplikace](#rozšíření-aplikace)
- [Autor a kontakt](#autor-a-kontakt)
- [Licence](#licence)

## Funkce
- Podpora protokolů NetFlow v9 a IPFIX.
- Možnost konfigurace pomocí `.ini` souboru.
- Ukládání dat do SQLite, MySQL nebo CSV.
- Automatická inicializace databázové tabulky, pokud ještě neexistuje.
- Parametry příkazové řádky pro kontrolu databáze, ladění a verzi.

## Požadavky
- **Operační systém**: Ubuntu (nebo jiný Unixový systém)
- **Kompilátor**: GCC s podporou C++11
- **Knihovny**:
  - `libsqlite3-dev` (pro SQLite podporu)
  - `libmysqlclient-dev` (pro MySQL podporu)
  - `libpthread` (podpora pro vlákna)
- **Knihovna INIReader** pro načítání `.ini` souboru
- **MySQL Server** (pokud používáte MySQL backend)

## Instalace

### Klonování Repozitáře
Klonujte projektový repozitář nebo stáhněte zdrojové kódy:
```bash
git clone https://github.com/Pavel852/netflow_collector.git
```

### Instalace Závislostí
Nainstalujte potřebné knihovny:
```bash
sudo apt-get update
sudo apt-get install build-essential libsqlite3-dev libmysqlclient-dev
```

## Konfigurace

Aplikace používá `.ini` soubor pro konfiguraci. Výchozí cesta je `nf_sond.ini`, ale můžete ji změnit pomocí parametru `--config` v příkazové řádce.

### Příklad `nf_sond.ini`
```ini
[Database]
type = sqlite
sqlite_path = /path/to/netflow_data.db
csv_path = /path/to/netflow_data.csv
mysql_host = localhost
mysql_port = 3306
mysql_user = uzivatel
mysql_password = heslo
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

### Parametry Konfigurace
- **[Database]**
  - `type`: Typ databáze (`sqlite`, `csv`, nebo `mysql`).
  - `sqlite_path`: Cesta k SQLite databázi.
  - `csv_path`: Cesta k CSV souboru.
  - `mysql_host`, `mysql_port`, `mysql_user`, `mysql_password`, `mysql_database`: MySQL připojení.

- **[SondeCount]**
  - `count`: Počet sledovaných sond.

- **[SondaX]**
  - `name`: Unikátní název sondy.
  - `version`: Verze protokolu (`IPFIX` nebo `NetFlow_v9`).
  - `listen_address`: IP adresa pro naslouchání.
  - `port`: Číslo portu pro naslouchání.

## Použití

Spusťte aplikaci z příkazové řádky:
```bash
./netflow_collector [možnosti]
```

### Parametry Příkazové Řádky
- `-h`, `--help`: Zobrazí nápovědu.
- `-v`, `--version`: Zobrazí verzi a informace o autorovi.
- `-d`, `--display`: Zobrazí příchozí pakety a jejich stav.
- `--config=CESTA`: Zadejte cestu k souboru s konfigurací (výchozí: `nf_sond.ini`).
- `--checkdb`: Zkontroluje připojení k databázi a inicializuje tabulku, pokud je to nutné.
- `--diag=CESTA`: Umožní ladění logů do určeného souboru.

### Příklady

- **Spuštění s výchozím nastavením**:
  ```bash
  ./netflow_collector
  ```

- **Spuštění s konkrétním konfiguračním souborem**:
  ```bash
  ./netflow_collector --config=/path/to/myconfig.ini
  ```

- **Kontrola databáze**:
  ```bash
  ./netflow_collector --checkdb
  ```

## Kompilace

Kompilujte aplikaci následujícím příkazem:
```bash
g++ -std=c++11 -o netflow_collector netflow_collector.cpp INIReader.cpp -lsqlite3 -lmysqlclient -lpthread
```

## Rozšíření Aplikace
- **Implementace úplného parsování**: Rozšiřte funkce `processNetFlowV9Data` a `processIPFIXData` pro kompletní zpracování záznamů.
- **Podpora dalších databází**: Přidejte podporu pro jiné databázové systémy dle potřeby.
- **Logování**: Implementujte logování událostí aplikace pro sledování chyb a výkonu.

## Autor a Kontakt
- **Autor**: PB
- **Email**: pavel.bartos.pb@gmail.com
- **Verze**: 2.1
- **Rok**: 10/2024

## Licence
Tento projekt je open-source a je dostupný pod licencí MIT.
