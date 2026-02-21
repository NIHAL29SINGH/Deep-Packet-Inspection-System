package com.deeppacket.model;

import java.util.Locale;

public enum AppType {
    UNKNOWN("Unknown"),
    HTTP("HTTP"),
    HTTPS("HTTPS"),
    DNS("DNS"),
    TLS("TLS"),
    QUIC("QUIC"),
    GOOGLE("Google"),
    FACEBOOK("Facebook"),
    YOUTUBE("YouTube"),
    TWITTER("Twitter/X"),
    INSTAGRAM("Instagram"),
    NETFLIX("Netflix"),
    AMAZON("Amazon"),
    MICROSOFT("Microsoft"),
    APPLE("Apple"),
    WHATSAPP("WhatsApp"),
    TELEGRAM("Telegram"),
    TIKTOK("TikTok"),
    SPOTIFY("Spotify"),
    ZOOM("Zoom"),
    DISCORD("Discord"),
    GITHUB("GitHub"),
    CLOUDFLARE("Cloudflare");

    private final String displayName;

    AppType(String displayName) {
        this.displayName = displayName;
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

    public static AppType fromSni(String sni) {
        if (sni == null || sni.isEmpty()) {
            return UNKNOWN;
        }
        String lower = sni.toLowerCase(Locale.ROOT);
        if (containsAny(lower, "youtube", "ytimg", "youtu.be", "yt3.ggpht")) return YOUTUBE;
        if (containsAny(lower, "google", "gstatic", "googleapis", "ggpht", "gvt1")) return GOOGLE;
        if (containsAny(lower, "facebook", "fbcdn", "fb.com", "fbsbx", "meta.com")) return FACEBOOK;
        if (containsAny(lower, "instagram", "cdninstagram")) return INSTAGRAM;
        if (containsAny(lower, "whatsapp", "wa.me")) return WHATSAPP;
        if (containsAny(lower, "twitter", "twimg", "x.com", "t.co")) return TWITTER;
        if (containsAny(lower, "netflix", "nflxvideo", "nflximg")) return NETFLIX;
        if (containsAny(lower, "amazon", "amazonaws", "cloudfront", "aws")) return AMAZON;
        if (containsAny(lower, "microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing")) return MICROSOFT;
        if (containsAny(lower, "apple", "icloud", "mzstatic", "itunes")) return APPLE;
        if (containsAny(lower, "telegram", "t.me")) return TELEGRAM;
        if (containsAny(lower, "tiktok", "tiktokcdn", "musical.ly", "bytedance")) return TIKTOK;
        if (containsAny(lower, "spotify", "scdn.co")) return SPOTIFY;
        if (containsAny(lower, "zoom")) return ZOOM;
        if (containsAny(lower, "discord", "discordapp")) return DISCORD;
        if (containsAny(lower, "github", "githubusercontent")) return GITHUB;
        if (containsAny(lower, "cloudflare", "cf-")) return CLOUDFLARE;
        return HTTPS;
    }

    private static boolean containsAny(String source, String... needles) {
        for (String needle : needles) {
            if (source.contains(needle)) return true;
        }
        return false;
    }
}
