package com.deeppacket.engine;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class ThreadSafeQueue<T> {
    private final ArrayBlockingQueue<T> queue;
    private final AtomicBoolean shutdown = new AtomicBoolean(false);

    public ThreadSafeQueue(int maxSize) {
        this.queue = new ArrayBlockingQueue<>(maxSize);
    }

    public void push(T item) {
        if (shutdown.get()) return;
        try {
            queue.put(item);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public T popWithTimeout(long timeoutMs) {
        try {
            return queue.poll(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
    }

    public boolean empty() {
        return queue.isEmpty();
    }

    public int size() {
        return queue.size();
    }

    public void shutdown() {
        shutdown.set(true);
    }

    public boolean isShutdown() {
        return shutdown.get();
    }
}
