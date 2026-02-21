package com.deeppacket.engine;

import com.deeppacket.model.AppType;
import com.deeppacket.model.NetUtil;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class RuleManager {
    public enum BlockType { IP, APP, DOMAIN, PORT }

    public static class BlockReason {
        public final BlockType type;
        public final String detail;
        public BlockReason(BlockType type, String detail) {
            this.type = type;
            this.detail = detail;
        }
    }

    private final Set<Integer> blockedIps = new HashSet<>();
    private final EnumSet<AppType> blockedApps = EnumSet.noneOf(AppType.class);
    private final Set<String> blockedDomains = new HashSet<>();
    private final List<String> domainPatterns = new ArrayList<>();
    private final Set<Integer> blockedPorts = new HashSet<>();
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    public void blockIP(String ip) { blockIP(NetUtil.parseIpv4ToInt(ip)); }
    public void blockIP(int ip) {
        lock.writeLock().lock();
        try {
            blockedIps.add(ip);
            System.out.println("[Rules] Blocked IP: " + NetUtil.intToIpv4(ip));
        } finally { lock.writeLock().unlock(); }
    }

    public boolean isIPBlocked(int ip) {
        lock.readLock().lock();
        try { return blockedIps.contains(ip); } finally { lock.readLock().unlock(); }
    }

    public void blockApp(AppType app) {
        lock.writeLock().lock();
        try {
            blockedApps.add(app);
            System.out.println("[Rules] Blocked app: " + app.displayName());
        } finally { lock.writeLock().unlock(); }
    }

    public boolean isAppBlocked(AppType app) {
        lock.readLock().lock();
        try { return blockedApps.contains(app); } finally { lock.readLock().unlock(); }
    }

    public void blockDomain(String domain) {
        lock.writeLock().lock();
        try {
            if (domain.contains("*")) domainPatterns.add(domain.toLowerCase(Locale.ROOT));
            else blockedDomains.add(domain.toLowerCase(Locale.ROOT));
            System.out.println("[Rules] Blocked domain: " + domain);
        } finally { lock.writeLock().unlock(); }
    }

    public boolean isDomainBlocked(String domain) {
        if (domain == null || domain.isEmpty()) return false;
        String lower = domain.toLowerCase(Locale.ROOT);
        lock.readLock().lock();
        try {
            if (blockedDomains.contains(lower)) return true;
            for (String blocked : blockedDomains) {
                if (lower.contains(blocked)) return true;
            }
            for (String pattern : domainPatterns) {
                if (domainMatchesPattern(lower, pattern)) return true;
            }
            return false;
        } finally { lock.readLock().unlock(); }
    }

    public void blockPort(int port) {
        lock.writeLock().lock();
        try { blockedPorts.add(port & 0xFFFF); } finally { lock.writeLock().unlock(); }
    }

    public boolean isPortBlocked(int port) {
        lock.readLock().lock();
        try { return blockedPorts.contains(port & 0xFFFF); } finally { lock.readLock().unlock(); }
    }

    public Optional<BlockReason> shouldBlock(int srcIp, int dstPort, AppType app, String domain) {
        if (isIPBlocked(srcIp)) return Optional.of(new BlockReason(BlockType.IP, NetUtil.intToIpv4(srcIp)));
        if (isPortBlocked(dstPort)) return Optional.of(new BlockReason(BlockType.PORT, String.valueOf(dstPort)));
        if (isAppBlocked(app)) return Optional.of(new BlockReason(BlockType.APP, app.displayName()));
        if (isDomainBlocked(domain)) return Optional.of(new BlockReason(BlockType.DOMAIN, domain));
        return Optional.empty();
    }

    public boolean saveRules(String file) {
        lock.readLock().lock();
        try (BufferedWriter out = Files.newBufferedWriter(Path.of(file))) {
            out.write("[BLOCKED_IPS]\n");
            for (int ip : blockedIps) out.write(NetUtil.intToIpv4(ip) + "\n");
            out.write("\n[BLOCKED_APPS]\n");
            for (AppType app : blockedApps) out.write(app.displayName() + "\n");
            out.write("\n[BLOCKED_DOMAINS]\n");
            for (String d : blockedDomains) out.write(d + "\n");
            for (String p : domainPatterns) out.write(p + "\n");
            out.write("\n[BLOCKED_PORTS]\n");
            for (int p : blockedPorts) out.write(p + "\n");
            return true;
        } catch (IOException e) {
            return false;
        } finally {
            lock.readLock().unlock();
        }
    }

    public boolean loadRules(String file) {
        String section = "";
        try (BufferedReader in = Files.newBufferedReader(Path.of(file))) {
            String line;
            while ((line = in.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                if (line.startsWith("[") && line.endsWith("]")) {
                    section = line;
                    continue;
                }
                switch (section) {
                    case "[BLOCKED_IPS]" -> blockIP(line);
                    case "[BLOCKED_APPS]" -> blockApp(AppType.fromDisplayName(line));
                    case "[BLOCKED_DOMAINS]" -> blockDomain(line);
                    case "[BLOCKED_PORTS]" -> blockPort(Integer.parseInt(line));
                    default -> {}
                }
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean domainMatchesPattern(String domain, String pattern) {
        if (pattern.startsWith("*.")) {
            String suffix = pattern.substring(1);
            return domain.endsWith(suffix) || domain.equals(pattern.substring(2));
        }
        return false;
    }
}
