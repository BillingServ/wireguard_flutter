#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <netioapi.h>

#include "wireguard_tunnel_manager.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace wireguard_flutter {

WireGuardTunnelManager::WireGuardTunnelManager() {
    std::cout << "WireGuardTunnelManager: Initializing..." << std::endl;
    if (!loadTunnelDll()) {
        std::cerr << "WireGuardTunnelManager: Failed to load tunnel.dll" << std::endl;
    }
}

WireGuardTunnelManager::~WireGuardTunnelManager() {
    std::cout << "WireGuardTunnelManager: Cleaning up..." << std::endl;
    stopTunnel();
    unloadTunnelDll();
}

void WireGuardTunnelManager::setEventSink(flutter::EventSink<flutter::EncodableValue>* sink) {
    eventSink = sink;
}

bool WireGuardTunnelManager::loadTunnelDll() {
    std::cout << "WireGuardTunnelManager: Loading tunnel.dll..." << std::endl;
    
    // Get the application directory
    std::wstring dllPath = getAppDirectory() + L"\\tunnel.dll";
    tunnelDll = LoadLibraryW(dllPath.c_str());
    
    if (!tunnelDll) {
        DWORD error = GetLastError();
        std::cerr << "WireGuardTunnelManager: Failed to load tunnel.dll from "
                  << std::string(dllPath.begin(), dllPath.end()) << std::endl;
        std::cerr << "Error code: " << error << std::endl;
        return false;
    }
    
    // Load WireGuardTunnelService function
    pWireGuardTunnelService = (WireGuardTunnelServiceFunc)GetProcAddress(tunnelDll, "WireGuardTunnelService");
    
    if (!pWireGuardTunnelService) {
        std::cerr << "WireGuardTunnelManager: Failed to load WireGuardTunnelService function" << std::endl;
        unloadTunnelDll();
        return false;
    }
    
    std::cout << "WireGuardTunnelManager: Successfully loaded tunnel.dll" << std::endl;
    return true;
}

void WireGuardTunnelManager::unloadTunnelDll() {
    if (tunnelDll) {
        FreeLibrary(tunnelDll);
        tunnelDll = nullptr;
        pWireGuardTunnelService = nullptr;
    }
}

std::wstring WireGuardTunnelManager::getAppDirectory() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring path(exePath);
    return path.substr(0, path.find_last_of(L"\\/"));
}

bool WireGuardTunnelManager::createConfigFile(const std::string& config) {
    std::wcout << L"WireGuardTunnelManager: Creating config file..." << std::endl;
    
    try {
        // Create a temporary file path
        wchar_t tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        
        // Generate a unique filename based on timestamp
        auto now = std::chrono::system_clock::now();
        auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
        
        std::wostringstream pathStream;
        pathStream << tempPath << L"wg_flutter_" << timestamp << L".conf";
        currentConfigPath = pathStream.str();
        
        // Write config to file
        std::ofstream configFile(currentConfigPath);
        if (!configFile.is_open()) {
            std::cerr << "Failed to create config file" << std::endl;
            return false;
        }
        
        configFile << config;
        configFile.close();
        
        std::wcout << L"Config file created: " << currentConfigPath << std::endl;
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Exception creating config file: " << e.what() << std::endl;
        return false;
    }
}

void WireGuardTunnelManager::cleanupTempFiles() {
    if (!currentConfigPath.empty()) {
        std::wcout << L"WireGuardTunnelManager: Cleaning up config file: " << currentConfigPath << std::endl;
        DeleteFileW(currentConfigPath.c_str());
        currentConfigPath.clear();
    }
}

void WireGuardTunnelManager::runTunnelService() {
    std::wcout << L"WireGuardTunnelManager: Starting tunnel service thread..." << std::endl;
    
    if (!pWireGuardTunnelService) {
        std::cerr << "WireGuardTunnelService function not loaded" << std::endl;
        updateStatusThreadSafe("error");
        return;
    }
    
    tunnelRunning = true;
    
    // Call WireGuardTunnelService with the config file path
    // This function blocks until the tunnel stops
    try {
        std::wcout << L"Calling WireGuardTunnelService with config: " << currentConfigPath << std::endl;
        
        // Convert wstring to unsigned short array for the Go function
        std::vector<unsigned short> configPathUtf16(currentConfigPath.begin(), currentConfigPath.end());
        configPathUtf16.push_back(0); // Null terminator
        
        unsigned char result = pWireGuardTunnelService(configPathUtf16.data());
        
        std::cout << "WireGuardTunnelService returned: " << (int)result << std::endl;
        
        if (result == 0) {
            std::cout << "Tunnel service completed successfully" << std::endl;
        } else {
            std::cerr << "Tunnel service returned error code: " << (int)result << std::endl;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Exception in tunnel service: " << e.what() << std::endl;
    }
    
    tunnelRunning = false;
    
    if (!shouldStopTunnel) {
        // Tunnel stopped unexpectedly
        std::cout << "Tunnel stopped unexpectedly" << std::endl;
        updateStatusThreadSafe("disconnected");
    }
}

bool WireGuardTunnelManager::checkConnectionStatus() {
    // Check if WireGuard adapter exists and is up
    // We can check this by looking for network interfaces with "WireGuard" in the name
    
    ULONG bufferSize = 15000;
    PIP_ADAPTER_ADDRESSES addresses = (IP_ADAPTER_ADDRESSES*)malloc(bufferSize);
    
    if (!addresses) {
        return false;
    }
    
    ULONG result = GetAdaptersAddresses(
        AF_UNSPEC,
        GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS,
        NULL,
        addresses,
        &bufferSize
    );
    
    bool connected = false;
    
    if (result == NO_ERROR) {
        PIP_ADAPTER_ADDRESSES currentAddress = addresses;
        
        while (currentAddress) {
            std::wstring description(currentAddress->Description);
            std::wstring friendlyName(currentAddress->FriendlyName);
            
            // Check if this is a WireGuard adapter
            if (description.find(L"WireGuard") != std::wstring::npos ||
                friendlyName.find(L"WireGuard") != std::wstring::npos) {
                
                // Check if adapter is up
                if (currentAddress->OperStatus == IfOperStatusUp) {
                    std::wcout << L"Found active WireGuard adapter: " << friendlyName << std::endl;
                    connected = true;
                    break;
                }
            }
            
            currentAddress = currentAddress->Next;
        }
    }
    
    free(addresses);
    return connected;
}

void WireGuardTunnelManager::monitorConnection() {
    std::cout << "WireGuardTunnelManager: Starting connection monitor..." << std::endl;
    
    int connectionCheckAttempts = 0;
    const int maxConnectionCheckAttempts = 30; // 30 seconds
    
    while (shouldMonitor && tunnelRunning) {
        // Check if the tunnel thread is still running
        if (!tunnelRunning) {
            std::cout << "Tunnel thread stopped" << std::endl;
            updateStatusThreadSafe("disconnected");
            break;
        }
        
        // Check for actual connection
        if (isConnecting && checkConnectionStatus()) {
            std::cout << "WireGuard connection established!" << std::endl;
            isConnecting = false;
            isConnected = true;
            updateStatusThreadSafe("connected");
        } else if (isConnecting) {
            connectionCheckAttempts++;
            if (connectionCheckAttempts >= maxConnectionCheckAttempts) {
                std::cerr << "Connection timeout - adapter not coming up" << std::endl;
                updateStatusThreadSafe("error");
                shouldStopTunnel = true;
                break;
            }
        }
        
        // Check if connected adapter went down
        if (isConnected && !checkConnectionStatus()) {
            std::cout << "WireGuard connection lost" << std::endl;
            isConnected = false;
            updateStatusThreadSafe("disconnected");
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    std::cout << "Connection monitor stopped" << std::endl;
}

bool WireGuardTunnelManager::startTunnel(const std::string& config) {
    std::lock_guard<std::mutex> lock(statusMutex);
    
    if (isConnected || isConnecting || tunnelRunning) {
        std::cerr << "WireGuardTunnelManager: Already connected or connecting" << std::endl;
        return false;
    }
    
    if (!tunnelDll) {
        std::cerr << "WireGuardTunnelManager: tunnel.dll not loaded" << std::endl;
        return false;
    }
    
    std::cout << "WireGuardTunnelManager: Starting tunnel..." << std::endl;
    
    // Create config file
    if (!createConfigFile(config)) {
        return false;
    }
    
    // Reset flags
    shouldStopTunnel = false;
    isConnecting = true;
    connectionStartTime = std::chrono::system_clock::now();
    
    updateStatus("connecting");
    
    // Start tunnel service in a separate thread
    tunnelThread = std::thread(&WireGuardTunnelManager::runTunnelService, this);
    
    // Give it a moment to start
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Start monitoring thread
    shouldMonitor = true;
    statusMonitorThread = std::thread(&WireGuardTunnelManager::monitorConnection, this);
    
    std::cout << "WireGuardTunnelManager: Tunnel start initiated" << std::endl;
    return true;
}

void WireGuardTunnelManager::stopTunnel() {
    std::cout << "WireGuardTunnelManager: Stopping tunnel..." << std::endl;
    
    // Signal tunnel to stop
    shouldStopTunnel = true;
    shouldMonitor = false;
    
    // Wait for monitoring thread
    if (statusMonitorThread.joinable()) {
        statusMonitorThread.join();
    }
    
    // The tunnel service is blocking, so we need to force it to stop
    // Unfortunately, the WireGuardTunnelService function doesn't provide
    // a clean way to stop it from another thread.
    // We'll need to wait for it or terminate ungracefully
    
    if (tunnelThread.joinable()) {
        // Give it a few seconds to stop gracefully
        auto stopWaitStart = std::chrono::steady_clock::now();
        while (tunnelRunning && 
               std::chrono::steady_clock::now() - stopWaitStart < std::chrono::seconds(5)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        if (tunnelRunning) {
            std::cerr << "Tunnel thread did not stop gracefully, detaching..." << std::endl;
            // We can't force-kill the Go runtime safely, so we'll detach
            tunnelThread.detach();
        } else {
            tunnelThread.join();
        }
    }
    
    isConnected = false;
    isConnecting = false;
    tunnelRunning = false;
    
    std::lock_guard<std::mutex> lock(statusMutex);
    updateStatus("disconnected");
    
    // Cleanup
    cleanupTempFiles();
    
    std::cout << "WireGuardTunnelManager: Tunnel stopped" << std::endl;
}

std::string WireGuardTunnelManager::getStatus() {
    std::lock_guard<std::mutex> lock(statusMutex);
    return currentStatus;
}

void WireGuardTunnelManager::updateStatus(const std::string& status) {
    currentStatus = status;
    if (eventSink) {
        eventSink->Success(flutter::EncodableValue(status));
    }
    std::cout << "WireGuardTunnelManager: Status updated to: " << status << std::endl;
}

void WireGuardTunnelManager::updateStatusThreadSafe(const std::string& status) {
    std::lock_guard<std::mutex> lock(statusMutex);
    pendingStatusUpdates.push(status);
}

void WireGuardTunnelManager::processPendingStatusUpdates() {
    std::lock_guard<std::mutex> lock(statusMutex);
    while (!pendingStatusUpdates.empty()) {
        updateStatus(pendingStatusUpdates.front());
        pendingStatusUpdates.pop();
    }
}

} // namespace wireguard_flutter
