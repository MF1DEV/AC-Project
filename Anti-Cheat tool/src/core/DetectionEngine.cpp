#include "DetectionEngine.h"
#include "Logger.h"

DetectionEngine::DetectionEngine()
    : isRunning(false) {
    processScanner = std::make_unique<ProcessScanner>();
    dllDetector = std::make_unique<DllInjectionDetector>();
    memoryScanner = std::make_unique<MemoryScanner>();

    LOG_INFO("DetectionEngine created");
}

DetectionEngine::~DetectionEngine() {
    stop();
    LOG_INFO("DetectionEngine destroyed");
}

bool DetectionEngine::initialize() {
    try {
        // Load memory signatures
        if (!memoryScanner->loadSignatures("signatures/known_cheats.db")) {
            LOG_WARNING("Failed to load custom signatures, using defaults");
        }

        LOG_INFO("DetectionEngine initialized successfully");
        return true;
    }
    catch (const std::exception& e) {
        LOG_ERROR("Failed to initialize DetectionEngine: " + std::string(e.what()));
        return false;
    }
}

void DetectionEngine::start() {
    if (isRunning.load()) {
        LOG_WARNING("DetectionEngine is already running");
        return;
    }

    isRunning.store(true);
    scanThread = std::thread(&DetectionEngine::scanLoop, this);

    LOG_INFO("DetectionEngine started");
}

void DetectionEngine::stop() {
    if (!isRunning.load()) {
        return;
    }

    isRunning.store(false);

    if (scanThread.joinable()) {
        scanThread.join();
    }

    LOG_INFO("DetectionEngine stopped");
}

void DetectionEngine::setDetectionCallback(std::function<void(const DetectionResult&)> callback) {
    detectionCallback = callback;
}

std::vector<DetectionResult> DetectionEngine::getRecentDetections() {
    std::lock_guard<std::mutex> lock(detectionMutex);
    return recentDetections;
}

void DetectionEngine::scanLoop() {
    LOG_INFO("Detection scan loop started");
    int scanCount = 0;

    while (isRunning.load()) {
        try {
            scanCount++;
            LOG_DEBUG("Starting scan cycle #" + std::to_string(scanCount));

            // Process scanning - limit frequency to avoid spam
            if (scanCount % 2 == 0) { // Every other scan
                auto processDetections = processScanner->detectSuspiciousProcesses();
                for (const auto& detection : processDetections) {
                    if (!isDuplicateDetection(detection)) {
                        processDetection(detection);
                    }
                }
                LOG_DEBUG("Process scan completed, found " + std::to_string(processDetections.size()) + " detections");
            }

            // DLL injection detection - less frequent
            if (scanCount % 3 == 0) { // Every third scan
                auto dllDetections = dllDetector->detectInjectedDlls();
                for (const auto& detection : dllDetections) {
                    if (!isDuplicateDetection(detection)) {
                        processDetection(detection);
                    }
                }
                LOG_DEBUG("DLL scan completed, found " + std::to_string(dllDetections.size()) + " detections");
            }

            // Memory scanning (limit to specific processes to avoid performance issues)
            if (scanCount % 5 == 0) { // Every fifth scan
                auto processes = processScanner->scanProcesses();
                int memoryScansPerformed = 0;

                for (const auto& process : processes) {
                    // Only scan game processes or suspicious processes (and limit total scans)
                    if (memoryScansPerformed >= 3) break; // Limit to 3 memory scans per cycle

                    if (process.processName.find("game") != std::string::npos ||
                        process.processName.find("client") != std::string::npos ||
                        process.processName.find("cheat") != std::string::npos) {

                        auto memoryDetections = memoryScanner->scanProcessMemory(process.processId);
                        for (const auto& detection : memoryDetections) {
                            if (!isDuplicateDetection(detection)) {
                                processDetection(detection);
                            }
                        }
                        memoryScansPerformed++;
                    }
                }
                LOG_DEBUG("Memory scan completed on " + std::to_string(memoryScansPerformed) + " processes");
            }

            // Clean up old detections every 20 scans
            if (scanCount % 20 == 0) {
                cleanupOldDetections();
            }

        }
        catch (const std::exception& e) {
            LOG_ERROR("Error in scan loop: " + std::string(e.what()));
        }

        LOG_DEBUG("Scan cycle #" + std::to_string(scanCount) + " completed, sleeping for " + std::to_string(SCAN_INTERVAL_MS) + "ms");

        // Wait before next scan
        std::this_thread::sleep_for(std::chrono::milliseconds(SCAN_INTERVAL_MS));
    }

    LOG_INFO("Detection scan loop ended after " + std::to_string(scanCount) + " cycles");
}

void DetectionEngine::processDetection(const DetectionResult& detection) {
    {
        std::lock_guard<std::mutex> lock(detectionMutex);

        // Add to recent detections (keep last 50 instead of 100 to reduce memory usage)
        recentDetections.push_back(detection);
        if (recentDetections.size() > 50) {
            recentDetections.erase(recentDetections.begin());
        }
    }

    // Call callback if set
    if (detectionCallback) {
        detectionCallback(detection);
    }

    // Log the detection
    std::string severityStr;
    switch (detection.severity) {
    case Severity::LOW: severityStr = "LOW"; break;
    case Severity::MEDIUM: severityStr = "MEDIUM"; break;
    case Severity::HIGH: severityStr = "HIGH"; break;
    case Severity::CRITICAL: severityStr = "CRITICAL"; break;
    }

    LOG_WARNING("DETECTION [" + severityStr + "]: " + detection.description +
        " (Process: " + detection.processName + ", PID: " + std::to_string(detection.processId) + ")");
}

bool DetectionEngine::isDuplicateDetection(const DetectionResult& newDetection) {
    std::lock_guard<std::mutex> lock(detectionMutex);

    auto now = std::chrono::system_clock::now();

    for (const auto& existing : recentDetections) {
        // Check if it's the same type of detection on the same process
        if (existing.type == newDetection.type &&
            existing.processId == newDetection.processId &&
            existing.processName == newDetection.processName) {

            // Check if it's recent (within last 5 minutes)
            auto timeDiff = std::chrono::duration_cast<std::chrono::minutes>(now - existing.timestamp);
            if (timeDiff.count() < 5) {
                return true; // It's a duplicate
            }
        }
    }

    return false; // Not a duplicate
}

void DetectionEngine::cleanupOldDetections() {
    std::lock_guard<std::mutex> lock(detectionMutex);

    auto now = std::chrono::system_clock::now();
    auto cutoffTime = now - std::chrono::hours(1); // Remove detections older than 1 hour

    auto newEnd = std::remove_if(recentDetections.begin(), recentDetections.end(),
        [cutoffTime](const DetectionResult& detection) {
            return detection.timestamp < cutoffTime;
        });

    size_t removedCount = std::distance(newEnd, recentDetections.end());
    recentDetections.erase(newEnd, recentDetections.end());

    if (removedCount > 0) {
        LOG_DEBUG("Cleaned up " + std::to_string(removedCount) + " old detections");
    }
}