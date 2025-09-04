#pragma once
#include "../../include/Common.h"
#include "ProcessScanner.h"
#include "DllInjectionDetector.h"
#include "MemoryScanner.h"

class DetectionEngine {
private:
    std::unique_ptr<ProcessScanner> processScanner;
    std::unique_ptr<DllInjectionDetector> dllDetector;
    std::unique_ptr<MemoryScanner> memoryScanner;

    std::thread scanThread;
    std::atomic<bool> isRunning;
    std::mutex detectionMutex;

    std::vector<DetectionResult> recentDetections;
    std::function<void(const DetectionResult&)> detectionCallback;

public:
    DetectionEngine();
    ~DetectionEngine();

    bool initialize();
    void start();
    void stop();
    void setDetectionCallback(std::function<void(const DetectionResult&)> callback);
    std::vector<DetectionResult> getRecentDetections();

private:
    void scanLoop();
    void processDetection(const DetectionResult& detection);
    bool isDuplicateDetection(const DetectionResult& newDetection);
    void cleanupOldDetections();
};