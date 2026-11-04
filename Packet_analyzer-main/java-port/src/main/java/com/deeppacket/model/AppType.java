package com.deeppacket.model;

import java.util.Locale;

public enum AppType {
    UNKNOWN("Unknown"),
    HTTP("HTTP"),
    HTTPS("HTTPS"),
    DNS("DNS"),
    TLS("TLS"),
    QUIC("QUIC"),
    YOUTUBE("YouTube", "youtube.com", "youtu.be", "ytimg.com", "googlevideo.com", "yt3.ggpht.com", "youtube-nocookie.com"),
    GOOGLE("Google", "google.com", "gstatic.com", "googleapis.com", "ggpht.com", "gvt1.com", "googleusercontent.com", "googleadservices.com"),
    FACEBOOK("Facebook", "facebook.com", "fbcdn.net", "fb.com", "fbsbx.com", "meta.com", "facebook.net"),
    TWITTER("Twitter/X", "twitter.com", "twimg.com", "x.com", "t.co"),
    INSTAGRAM("Instagram", "instagram.com", "cdninstagram.com"),
    NETFLIX("Netflix", "netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com", "nflxso.net"),
    AMAZON("Amazon", "amazon.com", "amazonaws.com", "cloudfront.net", "amazon.co.uk", "amazon.in"),
    MICROSOFT("Microsoft", "microsoft.com", "msn.com", "office.com", "office365.com", "azure.com", "live.com", "outlook.com", "bing.com", "microsoftonline.com", "windows.net"),
    APPLE("Apple", "apple.com", "icloud.com", "mzstatic.com", "itunes.com"),
    WHATSAPP("WhatsApp", "whatsapp.com", "whatsapp.net", "wa.me"),
    TELEGRAM("Telegram", "telegram.org", "telegram.me", "t.me"),
    TIKTOK("TikTok", "tiktok.com", "tiktokcdn.com", "musical.ly", "bytedance.com", "byteoversea.com"),
    SPOTIFY("Spotify", "spotify.com", "scdn.co"),
    ZOOM("Zoom", "zoom.us", "zoom.com"),
    DISCORD("Discord", "discord.com", "discordapp.com", "discord.gg"),
    GITHUB("GitHub", "github.com", "githubusercontent.com", "github.io"),
    CLOUDFLARE("Cloudflare", "cloudflare.com", "cloudflare-dns.com", "cloudflarestream.com");

    private final String displayName;
    private final String[] domains;

    AppType(String displayName, String... domains) {
        this.displayName = displayName;
        this.domains = domains;
    }

    public String displayName() {
        return displayName;
    }

    public static AppType fromDisplayName(String value) {
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        if (normalized.equals("twitter") || normalized.equals("x")) {
            return TWITTER;
        }
        for (AppType type : values()) {
            if (type.displayName.equalsIgnoreCase(value)) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown app: " + value);
    }

    /**
     * Classifies a visible hostname (TLS SNI, HTTP Host or DNS name).
     *
     * <p>Matching is done on DNS label boundaries: a host matches a domain when it equals it or is a
     * true subdomain of it. Substring matching is deliberately avoided because it mislabels traffic
     * ("www.netflix.com" contains "x.com", "www.microsoft.com" contains "t.co").
     */
    public static AppType fromSni(String sni) {
        if (sni == null || sni.isEmpty()) {
            return UNKNOWN;
        }
        String host = sni.toLowerCase(Locale.ROOT);
        if (host.endsWith(".")) host = host.substring(0, host.length() - 1);
        for (AppType type : values()) {
            if (type.domains.length > 0 && matchesAny(host, type.domains)) return type;
        }
        // Regional Google/Amazon domains such as google.co.in or amazon.de: match on a whole label.
        if (hasLabel(host, "google")) return GOOGLE;
        if (hasLabel(host, "amazon")) return AMAZON;
        return HTTPS;
    }

    static boolean matchesAny(String host, String[] domains) {
        for (String domain : domains) {
            if (host.equals(domain) || host.endsWith("." + domain)) return true;
        }
        return false;
    }

    private static boolean hasLabel(String host, String label) {
        for (String part : host.split("\\.")) {
            if (part.equals(label)) return true;
        }
        return false;
    }
}
