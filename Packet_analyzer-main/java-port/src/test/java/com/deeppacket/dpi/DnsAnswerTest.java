package com.deeppacket.dpi;

import com.deeppacket.testutil.PacketBuilder;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class DnsAnswerTest {
    private static final int IP1 = 0xcb007101; // 203.0.113.1
    private static final int IP2 = 0xcb007102;

    @Test
    void parsesTheNameAndEveryARecord() {
        byte[] response = PacketBuilder.dnsResponse("www.example.com", null, IP1, IP2);
        var answer = DNSExtractor.extractAnswer(response, response.length).orElseThrow();
        assertEquals("www.example.com", answer.name());
        assertEquals(java.util.List.of(IP1, IP2), answer.addresses());
    }

    @Test
    void attributesAddressesBehindACnameToTheNameThatWasAsked() {
        byte[] response = PacketBuilder.dnsResponse("www.shop.example", "edge.cdn.example.net", IP1);
        var answer = DNSExtractor.extractAnswer(response, response.length).orElseThrow();
        assertEquals("www.shop.example", answer.name());
        assertEquals(java.util.List.of(IP1), answer.addresses());
    }

    @Test
    void ignoresQueriesErrorsAndResponsesWithoutAddresses() {
        byte[] query = PacketBuilder.dnsQuery("www.example.com");
        assertTrue(DNSExtractor.extractAnswer(query, query.length).isEmpty());

        byte[] nxdomain = PacketBuilder.dnsResponse("www.example.com", null, IP1);
        nxdomain[3] = (byte) 0x83; // RCODE 3
        assertTrue(DNSExtractor.extractAnswer(nxdomain, nxdomain.length).isEmpty());

        byte[] empty = PacketBuilder.dnsResponse("www.example.com", null);
        assertTrue(DNSExtractor.extractAnswer(empty, empty.length).isEmpty());
    }

    @Test
    void neverThrowsOnTruncatedOrCorruptResponses() {
        byte[] response = PacketBuilder.dnsResponse("www.example.com", "edge.cdn.example.net", IP1, IP2);
        for (int cut = 0; cut <= response.length; cut++) {
            byte[] part = Arrays.copyOf(response, cut);
            DNSExtractor.extractAnswer(part, part.length); // must simply return, whatever it finds
        }
        // A compression pointer that points at itself must not loop forever.
        byte[] loop = response.clone();
        loop[12] = (byte) 0xC0;
        loop[13] = 0x0C;
        assertTrue(DNSExtractor.extractAnswer(loop, loop.length).isEmpty());
        assertTrue(DNSExtractor.extractAnswer(null, 0).isEmpty());
    }
}
