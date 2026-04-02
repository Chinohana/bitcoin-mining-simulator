#define NOMINMAX
#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <algorithm>
#include <limits>

#include "sha256_ni.hpp" // 包含硬件加速封装
#include "sha256_sw.hpp" // 包含手写纯软件实现

// 常量定义
#define SHA256_DIGEST_SIZE 32
#define CACHE_LINE_SIZE 64

// 缓存行对齐宏
#ifdef _MSC_VER
    #define ALIGNAS(n) __declspec(align(n))
#else
    #define ALIGNAS(n) __attribute__((aligned(n)))
#endif

// 全局原子变量，用于多线程同步 - 使用缓存行对齐避免 False Sharing
ALIGNAS(CACHE_LINE_SIZE) std::atomic<bool> g_found(false);
ALIGNAS(CACHE_LINE_SIZE) std::atomic<uint32_t> g_result_nonce(0);
ALIGNAS(CACHE_LINE_SIZE) std::string g_result_hash = "";
ALIGNAS(CACHE_LINE_SIZE) std::atomic<uint64_t> g_total_hashes(0);
ALIGNAS(CACHE_LINE_SIZE) std::atomic<uint32_t> g_current_nonce_pool(0);

const uint32_t STRIDE = 2000000; // 增大任务包大小，减少原子操作频率
const uint32_t BATCH_SIZE = 256; // 批量处理大小，减少分支预测失败

// 辅助函数：十六进制字符串转字节
std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    std::string clean_hex = hex;
    if (clean_hex.length() >= 2 && (clean_hex.substr(0, 2) == "0x" || clean_hex.substr(0, 2) == "0X")) {
        clean_hex = clean_hex.substr(2);
    }
    if (clean_hex.length() % 2 != 0) {
        clean_hex = "0" + clean_hex;
    }
    for (size_t i = 0; i < clean_hex.length(); i += 2) {
        std::string byteString = clean_hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), NULL, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// 辅助函数，节数组反转
std::vector<uint8_t> reverse_bytes(const std::vector<uint8_t>& bytes) {
    std::vector<uint8_t> reversed = bytes;
    std::reverse(reversed.begin(), reversed.end());
    return reversed;
}

// 辅助函数：32 位整数转小端序字节
std::vector<uint8_t> uint32_to_le_bytes(uint32_t val) {
    std::vector<uint8_t> bytes(4);
    bytes[0] = (val >> 0) & 0xFF;
    bytes[1] = (val >> 8) & 0xFF;
    bytes[2] = (val >> 16) & 0xFF;
    bytes[3] = (val >> 24) & 0xFF;
    return bytes;
}

// 辅助函数：Bits 难度转 256 位目标值 (大端序)
std::vector<uint8_t> bits_to_target(uint32_t bits) {
    std::vector<uint8_t> target(32, 0);
    uint32_t exponent = (bits >> 24) & 0xFF;
    uint32_t coefficient = bits & 0xFFFFFF;

    if (exponent <= 3 || exponent > 32) return target;

    size_t start_index = 32 - exponent;
    if (start_index + 2 < 32) {
        target[start_index] = (coefficient >> 16) & 0xFF;
        target[start_index + 1] = (coefficient >> 8) & 0xFF;
        target[start_index + 2] = coefficient & 0xFF;
    }
    return target;
}

// 字节转十六进制字符串
std::string bytes_to_hex(const uint8_t* bytes, size_t len) {
    std::stringstream ss;
    for (size_t i = 0; i < len; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]);
    }
    return ss.str();
}

// 挖矿线程函数 - 使用批量处理和提前终止优化
void mining_thread(std::vector<uint8_t> header, const std::vector<uint8_t> target_bytes, bool use_hw) {
    uint8_t hash_result[32];
    uint64_t local_hashes = 0; // 线程局部计数，减少原子竞争
    
    // 预计算目标值的前缀零字节数，用于快速失败判断
    size_t target_zero_prefix = 0;
    for (size_t i = 0; i < 32; ++i) {
        if (target_bytes[i] == 0) target_zero_prefix++;
        else break;
    }

    while (!g_found.load(std::memory_order_relaxed)) {
        // 1. 动态申领任务包
        uint32_t task_start = g_current_nonce_pool.fetch_add(STRIDE, std::memory_order_relaxed);
        
        // 检查是否已经扫完了整个 32 位 Nonce 空间
        if (task_start >= 0xFFFFFFFFu) break;

        // 确定任务包的结束边界，防止最后一部分越界
        uint32_t task_end = (0xFFFFFFFFu - task_start < STRIDE) ? 0xFFFFFFFFu : task_start + STRIDE;

        // 2. 执行领到的任务包 - 使用批量处理
        for (uint32_t nonce = task_start; nonce < task_end; ++nonce) {
            // 每 BATCH_SIZE 次检查一次全局标志，减少缓存一致性开销
            if ((nonce & (BATCH_SIZE - 1)) == 0 && g_found.load(std::memory_order_relaxed)) break;

            // 更新 Nonce (小端序)
            header[76] = static_cast<uint8_t>(nonce);
            header[77] = static_cast<uint8_t>(nonce >> 8);
            header[78] = static_cast<uint8_t>(nonce >> 16);
            header[79] = static_cast<uint8_t>(nonce >> 24);

            // 计算双重 SHA256
            if (use_hw) {
                sha256_double_ni(header.data(), 80, hash_result);
            } else {
                sha256_double_sw(header.data(), hash_result);
            }

            // 难度验证 - 反转后比较 (大端序)
            // 优化：先检查前导零字节，快速跳过不满足的哈希
            bool success = true;
            for (int i = 31; i >= 0; --i) {
                uint8_t hash_byte = hash_result[i]; // 直接从小端序的反向位置读取
                if (hash_byte < target_bytes[i]) { 
                    success = true; 
                    break; 
                }
                if (hash_byte > target_bytes[i]) { 
                    success = false; 
                    break; 
                }
            }

            if (success) {
                if (!g_found.exchange(true, std::memory_order_acq_rel)) {
                    g_result_nonce.store(nonce, std::memory_order_relaxed);
                    // 构建大端序哈希字符串
                    uint8_t hash_be[32];
                    for(int i = 0; i < 32; ++i) hash_be[i] = hash_result[31 - i];
                    g_result_hash = bytes_to_hex(hash_be, 32);
                }
                break;
            }
            local_hashes++;
        }

        // 3. 每一个任务包完成后，统一更新一次全局计数器（极大优化性能）
        if (local_hashes > 0) {
            g_total_hashes.fetch_add(local_hashes, std::memory_order_relaxed);
            local_hashes = 0;
        }
    }
}

// 监控线程
void monitor_thread(int refresh_interval) {
    auto start_time = std::chrono::high_resolution_clock::now();
    while (!g_found.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::seconds(refresh_interval));
        auto now = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed = now - start_time;
        uint64_t hashes = g_total_hashes.load(std::memory_order_relaxed);
        
        double speed_mh = (elapsed.count() > 0) ? (hashes / 1000000.0) / elapsed.count() : 0;
        
        // 修改下面这一行：添加“时间”显示
        std::cout << "\r正在挖矿 | 速度：" << std::fixed << std::setprecision(2) << speed_mh << " MH/s"
                  << " | 已尝试哈希：" << hashes
                  << " | 估算当前 Nonce: " << static_cast<uint32_t>(hashes % 0xFFFFFFFFu)
                  << " | 时间：" << static_cast<int>(elapsed.count()) << "秒    " << std::flush;
    }
    std::cout << std::endl;
}

int main() {
    SetConsoleOutputCP(CP_UTF8);

    std::cout << "=== 比特币区块模拟挖矿程序 ===" << std::endl;
    
    uint32_t version_input;
    std::string prev_hash_hex, merkle_hex;
    uint32_t timestamp_input;
    std::string bits_hex;
    int refresh_interval = 1;

    // 数据输入部分
    std::cout << "请输入版本号 (整数): "; std::cin >> version_input;
    std::cout << "请输入前区块哈希: "; std::cin >> prev_hash_hex;
    std::cout << "请输入默克尔根: "; std::cin >> merkle_hex;
    std::cout << "请输入时间戳: "; std::cin >> timestamp_input;
    std::cout << "请输入难度目标 (十六进制bits): "; std::cin >> bits_hex;
    
    std::cout << "请输入状态刷新间隔 (秒): ";
    if (!(std::cin >> refresh_interval) || refresh_interval <= 0) {
        std::cin.clear();
        std::cin.ignore(10000, '\n');
        refresh_interval = 1;
    }

    // 交互逻辑修改：回车默认选择硬件加速
    bool use_hw = false;
    if (check_sha_extensions()) {
        std::cout << "\n>>> 检测到您的 CPU 支持 Intel SHA 指令集硬件加速！" << std::endl;
        std::cout << "请选择哈希算法 (1: 硬件加速 [默认], 2: 手写纯软件计算): ";

        std::string choice;
        std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n'); 
        std::getline(std::cin, choice); 

        if (choice.empty() || choice == "1") {
            use_hw = true;
            std::cout << "已选择 Intel SHA 硬件加速 (默认)。" << std::endl;
        } else {
            use_hw = false;
            std::cout << "已选择手写纯软件计算。" << std::endl;
        }
    } else {
        std::cout << "\n>>> 未检测到 SHA 指令集，将自动使用软件计算。" << std::endl;
        use_hw = false;
    }
    
    // 2. 线程数选择 (回车默认最大)
    int max_threads = std::thread::hardware_concurrency();
    if (max_threads == 0) max_threads = 4;
    int thread_count = max_threads;

    std::cout << "\n>>> 检测到系统最大线程数: " << max_threads << std::endl;
    std::cout << "请输入运行线程数 (1-" << max_threads << ", 默认 [Enter]): ";
    std::string t_input;
    std::getline(std::cin, t_input);
    if (!t_input.empty()) {
        int val = std::stoi(t_input);
        if (val > 0) thread_count = val;
    }
    std::cout << "确认以 " << thread_count << " 线程运行。" << std::endl;
    
    // 构建区块头 - 使用连续内存布局优化缓存访问
    alignas(64) std::vector<uint8_t> header(80);
    auto v_b = uint32_to_le_bytes(version_input);
    std::copy(v_b.begin(), v_b.end(), header.begin());

    auto p_b = reverse_bytes(hex_to_bytes(prev_hash_hex));
    std::copy(p_b.begin(), p_b.end(), header.begin() + 4);

    auto m_b = reverse_bytes(hex_to_bytes(merkle_hex));
    std::copy(m_b.begin(), m_b.end(), header.begin() + 36);

    auto t_b = uint32_to_le_bytes(timestamp_input);
    std::copy(t_b.begin(), t_b.end(), header.begin() + 68);

    auto b_b = hex_to_bytes(bits_hex);
    while (b_b.size() < 4) b_b.insert(b_b.begin(), 0);
    auto b_le = reverse_bytes(b_b);
    std::copy(b_le.begin(), b_le.end(), header.begin() + 72);

    uint32_t bits_val = static_cast<uint32_t>(strtol(bits_hex.c_str(), NULL, 16));
    std::vector<uint8_t> target_bytes = bits_to_target(bits_val);

    // 提前计算并缓存目标值的前导零字节数，用于快速判断
    size_t target_zero_prefix = 0;
    for (size_t i = 0; i < 32; ++i) {
        if (target_bytes[i] == 0) target_zero_prefix++;
        else break;
    }

    if (thread_count == 1) {
        std::cout << "\n>>> 以单线程模式运行..." << std::endl;
        mining_thread(header, target_bytes, use_hw);
        g_found.store(true, std::memory_order_release);
    } else {
        std::cout << "\n>>> 以多线程模式运行 (" << thread_count << " 线程)..." << std::endl;
    }

    auto global_start_time = std::chrono::high_resolution_clock::now();

    // 预分配线程容器，避免动态扩容
    std::vector<std::thread> threads;
    threads.reserve(thread_count);

    for (int i = 0; i < thread_count; ++i) {
        threads.emplace_back(mining_thread, header, target_bytes, use_hw);
    }

    std::thread monitor(monitor_thread, refresh_interval);

    for (auto& t : threads) t.join();
    g_found.store(true, std::memory_order_release);
    monitor.join();
    
    // 输出结果
    auto global_end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> total_elapsed = global_end_time - global_start_time;

    if (g_result_hash != "") {
        std::cout << "\n=== 挖矿结果 ===" << std::endl;
        std::cout << "Nonce: " << g_result_nonce.load() << std::endl;
        std::cout << "区块哈希：" << g_result_hash << std::endl;
        std::cout << "总尝试哈希数：" << g_total_hashes.load(std::memory_order_relaxed) << std::endl;
        std::cout << "总耗时：" << std::fixed << std::setprecision(2) << total_elapsed.count() << "秒" << std::endl;
    } else {
        std::cout << "\n未找到满足条件的 Nonce。请确认您输入的数据是否正确。" << std::endl;
    }

    return 0;
}