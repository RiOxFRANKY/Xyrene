
package com.mitm.ids.capture;

import com.mitm.ids.model.PacketData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Abstract base for all packet capture engines.
 * Manages background thread lifecycle, listener notification, and error propagation.
 */
public abstract class AbstractPacketCapture implements IPacketCapture {
    protected final Logger logger = LoggerFactory.getLogger(getClass());
    private final List<IPacketListener> listeners = new CopyOnWriteArrayList<>();
    private Thread captureThread;
    private volatile boolean running = false;
    private volatile String activeInterface;

    @Override
    public void addListener(IPacketListener listener) {
        listeners.add(listener);
    }

    @Override
    public final synchronized void start(String interfaceName) {
        if (running) {
            logger.warn("Capture already running on {}", activeInterface);
            return;
        }
        activeInterface = interfaceName;
        running = true;
        captureThread = new Thread(() -> {
            try {
                runCaptureLoop(interfaceName);
            } catch (Exception e) {
                logger.error("Capture loop crashed on {}: {}", interfaceName, e.getMessage(), e);
                notifyError("Capture loop crashed: " + e.getMessage(), e);
            } finally {
                running = false;
            }
        }, "PacketCapture-" + interfaceName);
        captureThread.setDaemon(true);
        captureThread.start();
        logger.info("Packet capture started on [{}]", interfaceName);
    }

    @Override
    public final synchronized void stop() {
        if (!running) return;
        running = false;
        if (captureThread != null) {
            captureThread.interrupt();
        }
        onStop();
        logger.info("Packet capture stopped on [{}]", activeInterface);
    }

    @Override
    public boolean isRunning() {
        return running;
    }

    public String getActiveInterface() {
        return activeInterface;
    }

    protected void notifyListeners(PacketData data) {
        if (data == null) return;
        for (IPacketListener listener : listeners) {
            try {
                listener.onPacket(data);
            } catch (Exception e) {
                logger.error("Listener {} error: {}", listener.getClass().getSimpleName(), e.getMessage());
            }
        }
    }

    protected void notifyError(String message, Throwable cause) {
        for (IPacketListener listener : listeners) {
            try {
                listener.onCaptureError(message, cause);
            } catch (Exception ignored) {}
        }
    }

    /**
     * Main capture loop — implemented by concrete subclasses.
     */
    protected abstract void runCaptureLoop(String interfaceName);

    /**
     * Optional cleanup hook.
     */
    protected void onStop() {}
}
