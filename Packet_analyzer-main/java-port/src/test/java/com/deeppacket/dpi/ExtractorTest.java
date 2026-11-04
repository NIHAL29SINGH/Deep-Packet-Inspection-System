package com.deeppacket.dpi;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class ExtractorTest {
    @Test
    void extractsHttpHostCaseInsensitively() {
        byte[] payload = "GET / HTTP/1.1\r\nhOsT: example.test:8080\r\n\r\n"
            .getBytes(StandardCharsets.US_ASCII);
        assertTrue(HTTPHostExtractor.isHttpRequest(payload, payload.length));
        assertEquals("example.test", HTTPHostExtractor.extract(payload, payload.length).orElseThrow());
    }

    @Test
    void extractsDnsQuery() {
        byte[] payload = new byte[] {
            0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
            3, 'w', 'w', 'w', 6, 'g', 'i', 't', 'h', 'u', 'b', 3, 'c', 'o', 'm', 0,
            0, 1, 0, 1
        };
        assertTrue(DNSExtractor.isDnsQuery(payload, payload.length));
        assertEquals("www.github.com", DNSExtractor.extractQuery(payload, payload.length).orElseThrow());
    }

    @Test
    void rejectsMalformedDnsAndTls() {
        assertTrue(DNSExtractor.extractQuery(new byte[] {1, 2, 3}, 3).isEmpty());
        assertTrue(SNIExtractor.extract(new byte[] {0x16, 3, 3, 0, 1, 1}, 6).isEmpty());
    }

    @Test
    void extractsSniFromClientHelloAndRejectsTruncation() {
        byte[] hello = clientHello("www.example.test");
        assertTrue(SNIExtractor.isTlsClientHello(hello, hello.length));
        assertEquals("www.example.test", SNIExtractor.extract(hello, hello.length).orElseThrow());
        // A ClientHello split across TCP segments is not reassembled, so SNI is not found.
        assertTrue(SNIExtractor.extract(hello, hello.length - 10).isEmpty());
    }

    private static byte[] clientHello(String host) {
        byte[] name = host.getBytes(StandardCharsets.US_ASCII);
        int sniExtLen = 2 + 1 + 2 + name.length;
        int extensionsLen = 4 + sniExtLen;
        int helloBody = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extensionsLen;
        byte[] b = new byte[5 + 4 + helloBody];
        int o = 0;
        b[o++] = 0x16; b[o++] = 3; b[o++] = 1;
        b[o++] = (byte) ((4 + helloBody) >> 8); b[o++] = (byte) (4 + helloBody);
        b[o++] = 0x01; b[o++] = 0; b[o++] = (byte) (helloBody >> 8); b[o++] = (byte) helloBody;
        b[o++] = 3; b[o++] = 3;
        o += 32;
        b[o++] = 0;
        b[o++] = 0; b[o++] = 2; b[o++] = 0x13; b[o++] = 0x01;
        b[o++] = 1; b[o++] = 0;
        b[o++] = (byte) (extensionsLen >> 8); b[o++] = (byte) extensionsLen;
        b[o++] = 0; b[o++] = 0;
        b[o++] = (byte) (sniExtLen >> 8); b[o++] = (byte) sniExtLen;
        b[o++] = (byte) ((sniExtLen - 2) >> 8); b[o++] = (byte) (sniExtLen - 2);
        b[o++] = 0;
        b[o++] = (byte) (name.length >> 8); b[o++] = (byte) name.length;
        System.arraycopy(name, 0, b, o, name.length);
        return b;
    }
}
