#pragma once

#include <windows.h>
#include <string>
#include <memory>
#include <atomic>
#include <thread>
#include <mutex>
#include <queue>
#include <chrono>
#include <flutter/event_channel.h>
#include <flutter/encodable_value.h>

namespace wireguard_flutter {

class WireGuardTunnelManager {
private:
    // Tunnel thread (WireGuard tunnel runs in a dedicated thread)
    std::thread tunnelThread;
    std::atomic<bool> tunnelRunning{false};
    std::atomic<bool> shouldStopTunnel{false};
    
    // Connection state
    std::atomic<bool> isConnected{false};
    std::atomic<bool> isConnecting{false};
    std::string currentStatus = "disconnected";
    std::wstring currentConfigPath;
    
    // Status monitoring
    std::thread statusMonitorThread;
    std::atomic<bool> shouldMonitor{true};
    
    // Event sink for status updates
    flutter::EventSink<flutter::EncodableValue>* eventSink = nullptr;
    
    // Thread safety
    std::mutex statusMutex;
    std::queue<std::string> pendingStatusUpdates;
    
    // Connection tracking
    std::chrono::system_clock::time_point connectionStartTime;
    
    // tunnel.dll handle and function
    HMODULE tunnelDll = nullptr;
    typedef unsigned char (*WireGuardTunnelServiceFunc)(unsigned short* confFile16);
    WireGuardTunnelServiceFunc pWireGuardTunnelService = nullptr;

public:
    WireGuardTunnelManager();
    ~WireGuardTunnelManager();
    
    void setEventSink(flutter::EventSink<flutter::EncodableValue>* sink);
    bool startTunnel(const std::string& config);
    void stopTunnel();
    std::string getStatus();
    
    // Process pending status updates (call from main thread)
    void processPendingStatusUpdates();
    
private:
    bool loadTunnelDll();
    void unloadTunnelDll();
    void runTunnelService();
    void monitorConnection();
    void updateStatus(const std::string& status);
    void updateStatusThreadSafe(const std::string& status);
    bool createConfigFile(const std::string& config);
    void cleanupTempFiles();
    bool checkConnectionStatus();
    std::wstring getAppDirectory();
};

} // namespace wireguard_flutter
