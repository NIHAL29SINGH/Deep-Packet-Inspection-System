package com.deeppacket.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AppTypeTest {
    @Test
    void classifiesKnownServices() {
        assertEquals(AppType.YOUTUBE, AppType.fromSni("www.youtube.com"));
        assertEquals(AppType.YOUTUBE, AppType.fromSni("r3---sn-abc.googlevideo.com"));
        assertEquals(AppType.GOOGLE, AppType.fromSni("www.google.com"));
        assertEquals(AppType.GOOGLE, AppType.fromSni("www.google.co.in"));
        assertEquals(AppType.NETFLIX, AppType.fromSni("www.netflix.com"));
        assertEquals(AppType.MICROSOFT, AppType.fromSni("www.microsoft.com"));
        assertEquals(AppType.TWITTER, AppType.fromSni("x.com"));
        assertEquals(AppType.TWITTER, AppType.fromSni("api.twitter.com"));
        assertEquals(AppType.GITHUB, AppType.fromSni("raw.githubusercontent.com"));
    }

    @Test
    void doesNotMatchOnSubstrings() {
        // Regression: "x.com" is a substring of netflix.com and "t.co" of microsoft.com,
        // which used to label Netflix and Microsoft traffic as Twitter.
        assertNotEquals(AppType.TWITTER, AppType.fromSni("www.netflix.com"));
        assertNotEquals(AppType.TWITTER, AppType.fromSni("www.microsoft.com"));
        assertNotEquals(AppType.TWITTER, AppType.fromSni("www.dropbox.com"));
        assertNotEquals(AppType.AMAZON, AppType.fromSni("paws.example.org"));
        assertNotEquals(AppType.ZOOM, AppType.fromSni("zoomable.example.org"));
        assertEquals(AppType.HTTPS, AppType.fromSni("www.dropbox.com"));
    }

    @Test
    void handlesEmptyAndTrailingDotInput() {
        assertEquals(AppType.UNKNOWN, AppType.fromSni(null));
        assertEquals(AppType.UNKNOWN, AppType.fromSni(""));
        assertEquals(AppType.YOUTUBE, AppType.fromSni("WWW.YouTube.COM."));
    }

    @Test
    void parsesDisplayNames() {
        assertEquals(AppType.TWITTER, AppType.fromDisplayName("x"));
        assertEquals(AppType.YOUTUBE, AppType.fromDisplayName("youtube"));
        assertThrows(IllegalArgumentException.class, () -> AppType.fromDisplayName("nope"));
    }
}
