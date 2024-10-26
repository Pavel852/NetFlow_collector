sudo apt-get install libsqlite3-dev
sudo apt-get install libmysqlclient-dev

g++ -std=c++14 -o netflow_collector netflow_collector.cpp ini.cpp -lsqlite3 -lmysqlclient -lpthread

