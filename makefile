# Makefile for netflow_collector project

# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++14 -Wall

# Libraries
LIBS = -lsqlite3 -lmysqlclient -lpthread

# Sources and executable
SRCS = netflow_collector.cpp ini.cpp
OBJS = $(SRCS:.cpp=.o)
EXEC = netflow_collector

# Targets
all: $(EXEC)

$(EXEC): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(EXEC) $(OBJS) $(LIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(EXEC)

.PHONY: all clean

