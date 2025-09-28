#ifndef BLOCKLIST_MANAGER_H
#define BLOCKLIST_MANAGER_H

#include <unordered_map>
#include <string>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <sys/stat.h>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <unistd.h>
#include <android-base/logging.h>

class BlocklistManager {
private:
    struct BlockEntry {
        std::shared_ptr<std::string> targetAddress;
    };

    struct FileInfo {
        timespec modTime = {0, 0};
        off_t fileSize = 0;
    };

    // Main blocklist storage
    std::unordered_map<std::string, BlockEntry> blocklist;
    
    // For deduplicating common addresses like 0.0.0.0
    std::unordered_map<std::string, std::shared_ptr<std::string>> addressPool;
    
    // File tracking
    std::string blocklistPath;
    FileInfo lastFileInfo;
    
    // Thread safety
    mutable std::shared_mutex rwMutex;
    
    // Private constructor for singleton
    BlocklistManager(const std::string& path) : blocklistPath(path) {
        loadBlocklist();
    }
    
    // Get or create shared address
    std::shared_ptr<std::string> getOrCreateAddress(const std::string& addr) {
        auto it = addressPool.find(addr);
        if (it != addressPool.end()) {
            return it->second;
        }
        auto sharedAddr = std::make_shared<std::string>(addr);
        addressPool[addr] = sharedAddr;
        return sharedAddr;
    }
    
    // Check if file is stable (not being written to)
    bool isFileStable() const {
        struct stat stat1, stat2;
        
        // First stat
        if (stat(blocklistPath.c_str(), &stat1) != 0) {
            return false;
        }
        
        // Wait a tiny bit
        usleep(1000); // 1ms
        
        // Second stat
        if (stat(blocklistPath.c_str(), &stat2) != 0) {
            return false;
        }
        
        // If size or mtime changed, file is being written
        return (stat1.st_size == stat2.st_size &&
                stat1.st_mtim.tv_sec == stat2.st_mtim.tv_sec &&
                stat1.st_mtim.tv_nsec == stat2.st_mtim.tv_nsec);
    }
    
    // Check if we should reload the file
    bool shouldReload() const {
        struct stat fileStat;
        if (stat(blocklistPath.c_str(), &fileStat) != 0) {
            return false;
        }
        
        // Check if file changed
        bool changed = (fileStat.st_mtim.tv_sec != lastFileInfo.modTime.tv_sec ||
                       fileStat.st_mtim.tv_nsec != lastFileInfo.modTime.tv_nsec ||
                       fileStat.st_size != lastFileInfo.fileSize);
        
        if (!changed) {
            return false;  // No change, no need to reload
        }
        
        // File changed, check if it's stable (this is where we wait 1ms)
        if (!isFileStable()) {
            // File is being written, skip this update
            return false;
        }
        
        return true;
    }
    
    // Parse blocklist file
    void loadBlocklist() {
        struct stat fileStat;
        if (stat(blocklistPath.c_str(), &fileStat) != 0) {
            LOG(WARNING) << "Blocklist file not found: " << blocklistPath;
            return;
        }
        
        std::ifstream file(blocklistPath);
        if (!file.is_open()) {
            LOG(WARNING) << "Failed to open blocklist file: " << blocklistPath;
            return;
        }
        
        // Update file info
        lastFileInfo.modTime = fileStat.st_mtim;
        lastFileInfo.fileSize = fileStat.st_size;
        
        // Clear existing entries
        blocklist.clear();
        addressPool.clear();
        
        std::string line;
        int lineNum = 0;
        while (std::getline(file, line)) {
            lineNum++;
            
            // Skip empty lines and comments
            if (line.empty() || line[0] == '#') {
                continue;
            }
            
            // Remove trailing whitespace
            line.erase(line.find_last_not_of(" \t\r\n") + 1);
            
            std::istringstream iss(line);
            std::string address, domain;
            
            // Parse: <address> <domain>
            if (iss >> address >> domain) {
                // Normalize domain to lowercase
                std::transform(domain.begin(), domain.end(), domain.begin(), ::tolower);
                
                // Store with shared address
                blocklist[domain] = {getOrCreateAddress(address)};
                
                LOG(VERBOSE) << "Loaded blocklist entry: " << domain << " -> " << address;
            } else {
                LOG(WARNING) << "Invalid blocklist entry at line " << lineNum << ": " << line;
            }
        }
        
        LOG(INFO) << "Loaded " << blocklist.size() << " entries from blocklist, "
                  << addressPool.size() << " unique addresses";
    }
    
    // Internal lookup function (must be called with lock held)
    std::pair<bool, std::string> lookupDomain(const std::string& domain) const {
        // 1. Try exact match
        auto it = blocklist.find(domain);
        if (it != blocklist.end()) {
            return {true, *it->second.targetAddress};
        }
        
        // 2. Try wildcard matches by checking parent domains
        size_t pos = 0;
        while ((pos = domain.find('.', pos)) != std::string::npos) {
            // Create wildcard version: ".parent.domain"
            std::string wildcardDomain = domain.substr(pos);  // This includes the dot
            
            auto it = blocklist.find(wildcardDomain);
            if (it != blocklist.end()) {
                return {true, *it->second.targetAddress};
            }
            
            pos++;  // Move past the current dot
        }
        
        return {false, ""};
    }
    
public:
    // Singleton instance
    static BlocklistManager& getInstance(const std::string& path = "/data/etc/hosts") {
        static BlocklistManager instance(path);
        return instance;
    }
    
    // Delete copy constructor and assignment operator
    BlocklistManager(const BlocklistManager&) = delete;
    BlocklistManager& operator=(const BlocklistManager&) = delete;
    
    // Check if a domain is blocked and return the target address
    std::pair<bool, std::string> checkDomain(const std::string& domain) {
        // Normalize domain to lowercase
        std::string normalizedDomain = domain;
        std::transform(normalizedDomain.begin(), normalizedDomain.end(), 
                      normalizedDomain.begin(), ::tolower);
        
        // First, check with read lock
        {
            std::shared_lock<std::shared_mutex> readLock(rwMutex);
            if (!shouldReload()) {
                // No reload needed, do the lookup
                return lookupDomain(normalizedDomain);
            }
        }
        
        // Need to reload
        {
            std::unique_lock<std::shared_mutex> writeLock(rwMutex);
            // Double-check under write lock
            if (shouldReload()) {
                LOG(INFO) << "Reloading blocklist file: " << blocklistPath;
                loadBlocklist();
            }
            // Now do the lookup
            return lookupDomain(normalizedDomain);
        }
    }
    
    // Force reload (useful for testing or manual refresh)
    void forceReload() {
        std::unique_lock<std::shared_mutex> writeLock(rwMutex);
        LOG(INFO) << "Force reloading blocklist file: " << blocklistPath;
        loadBlocklist();
    }
    
    // Get statistics (useful for debugging)
    void getStats(size_t& domainCount, size_t& uniqueAddressCount) const {
        std::shared_lock<std::shared_mutex> readLock(rwMutex);
        domainCount = blocklist.size();
        uniqueAddressCount = addressPool.size();
    }
};

#endif // BLOCKLIST_MANAGER_H