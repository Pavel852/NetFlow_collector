CREATE TABLE NetFlowData (
    FlowID INTEGER PRIMARY KEY AUTOINCREMENT,
    SourceIP TEXT NOT NULL,
    DestinationIP TEXT NOT NULL,
    SourcePort INTEGER NOT NULL,
    DestinationPort INTEGER NOT NULL,
    Protocol INTEGER NOT NULL,
    PacketCount INTEGER NOT NULL,
    ByteCount INTEGER NOT NULL,
    FlowStart TEXT NOT NULL,
    FlowEnd TEXT NOT NULL,
    SourceSond TEXT NOT NULL
);
