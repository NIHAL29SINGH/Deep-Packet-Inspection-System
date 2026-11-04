package com.deeppacket.pcap;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class PcapReaderTest {
    @Test
    void rejectsInvalidMagicAndTruncatedHeader() throws Exception {
        Path bad = Files.createTempFile("bad", ".pcap");
        Files.write(bad, new byte[] {0, 1, 2});
        assertThrows(Exception.class, () -> {
            try (PcapReader reader = new PcapReader()) {
                reader.open(bad.toString());
            }
        });
        Files.deleteIfExists(bad);
    }
}
