package com.deeppacket.dpi;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class HostnameValidatorTest {
    @Test
    void acceptsOrdinaryHostnames() {
        assertTrue(HostnameValidator.isPlausibleHostname("www.example.com"));
        assertTrue(HostnameValidator.isPlausibleHostname("a-b_c.example.org"));
        assertTrue(HostnameValidator.isPlausibleHostname("*.example.com"));
        assertTrue(HostnameValidator.isPlausibleHostname("example.com."));
        assertTrue(HostnameValidator.isPlausibleHostname("10.0.0.1"));
    }

    @Test
    void rejectsHostileOrMalformedNames() {
        assertFalse(HostnameValidator.isPlausibleHostname(""));
        assertFalse(HostnameValidator.isPlausibleHostname(null));
        assertFalse(HostnameValidator.isPlausibleHostname(".example.com"));
        assertFalse(HostnameValidator.isPlausibleHostname("a..b.com"));
        assertFalse(HostnameValidator.isPlausibleHostname("evil\"><script>.com"));
        assertFalse(HostnameValidator.isPlausibleHostname("=cmd|calc.example"));
        assertFalse(HostnameValidator.isPlausibleHostname("a\r\nb.com"));
        assertFalse(HostnameValidator.isPlausibleHostname("a".repeat(64) + ".com"));
        assertFalse(HostnameValidator.isPlausibleHostname(("a.".repeat(130)) + "com"));
    }

    @Test
    void sniExtractorRejectsNonHostnameValues() {
        byte[] hello = com.deeppacket.testutil.PacketBuilder.clientHello("good.example.com");
        assertEquals("good.example.com", SNIExtractor.extract(hello, hello.length).orElseThrow());
        byte[] bad = com.deeppacket.testutil.PacketBuilder.clientHello("bad<host>.com");
        assertTrue(SNIExtractor.extract(bad, bad.length).isEmpty());
    }

    @Test
    void httpHostMustStartAHeaderLine() {
        byte[] ok = "GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
        assertEquals("example.com", HTTPHostExtractor.extract(ok, ok.length).orElseThrow());

        // "host:" inside the URL must not be treated as the Host header.
        byte[] inUrl = "GET /?q=host:evil.example HTTP/1.1\r\nAccept: */*\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
        assertTrue(HTTPHostExtractor.extract(inUrl, inUrl.length).isEmpty());

        byte[] literalBackslashes = "GET / HTTP/1.1\\r\\nHost: example.com\\r\\n".getBytes(StandardCharsets.US_ASCII);
        assertTrue(HTTPHostExtractor.extract(literalBackslashes, literalBackslashes.length).isEmpty());
    }
}
