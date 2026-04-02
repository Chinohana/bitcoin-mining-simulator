# 比特币区块模拟挖矿程序 (Bitcoin Block Mining Simulator)

一个高性能的多线程比特币区块模拟挖矿程序，支持 Intel SHA 指令集硬件加速和纯软件计算两种模式。

## 功能特性

- 🔧 **双模式 SHA-256 计算**
  - Intel SHA 扩展指令集硬件加速 (`sha256_ni.hpp`)
  - 纯软件手写实现 (`sha256_sw.hpp`)
  
- 🚀 **高性能多线程挖矿**
  - 支持自定义线程数
  - 动态任务分配机制
  - 原子操作保证线程安全
  
- 📊 **实时状态监控**
  - 实时哈希率显示
  - 总哈希计数统计
  - 可配置的状态刷新间隔

- 💻 **智能 CPU 检测**
  - 自动检测 CPU SHA 指令集支持
  - 根据硬件能力推荐最优计算模式

## 项目结构

```
├── mining_sim.cpp    # 主程序入口，包含挖矿逻辑
├── sha256_ni.hpp     # Intel SHA 硬件加速实现
├── sha256_sw.hpp     # 纯软件 SHA-256 实现
├── LICENSE           # 开源许可证
└── README.md         # 项目说明文档
```

## 系统要求

⚠️ **平台限制**: 本程序**仅支持 Windows 平台**，且必须使用 **MSVC 编译器**。

### 硬件要求
- **CPU**: x86_64 架构处理器
- **推荐**: 支持 Intel SHA 扩展和 AVX2 指令集的 CPU (Intel Goldmont 或更新架构)

### 软件要求
- **操作系统**: Windows 10/11
- **编译器**: Microsoft Visual C++ (MSVC)
- **开发环境**: Visual Studio 或 Visual Studio Build Tools

## 编译方法

### Windows (MSVC) - 唯一支持的编译方式

使用以下命令进行编译（启用全程序优化和 AVX2 指令集）：

```bash
cl /O2 /Ot /GL /Ob2 /arch:AVX2 /GS- /utf-8 /EHsc mining_sim.cpp /link /LTCG
```

#### 编译参数说明

| 参数 | 说明 |
|------|------|
| `/O2` | 最大速度优化 |
| `/Ot` | 内联函数优化 |
| `/GL` | 全程序优化 (配合 `/LTCG`) |
| `/Ob2` | 激进内联扩展 |
| `/arch:AVX2` | 启用 AVX2 指令集 |
| `/GS-` | 禁用安全检查 (提升性能) |
| `/utf-8` | 使用 UTF-8 编码 |
| `/EHsc` | 启用 C++ 异常处理 |
| `/link /LTCG` | 链接时全程序优化 |

### 其他平台

❌ **不支持** Linux、macOS 或其他编译器 (GCC/Clang)。

## 使用方法

运行程序后，按提示输入以下参数：

1. **版本号** (整数): 区块版本号
2. **前区块哈希**: 上一个区块的哈希值 (十六进制字符串)
3. **默克尔根**: 交易默克尔树根哈希 (十六进制字符串)
4. **时间戳**: 区块时间戳 (Unix 时间戳)
5. **难度目标**: 以 bits 格式表示的难度目标 (十六进制)
6. **状态刷新间隔**: 界面刷新频率 (秒，默认 1 秒)

### 运行示例

```bash
./mining_sim
```

程序将显示类似以下交互：

```
=== 比特币区块模拟挖矿程序 ===
请输入版本号 (整数): 536870912
请输入前区块哈希: 0000000000000000000a1b2c3d4e5f6...
请输入默克尔根: a1b2c3d4e5f6...
请输入时间戳: 1234567890
请输入难度目标 (十六进制 bits): 1d00ffff
请输入状态刷新间隔 (秒): 1

>>> 检测到您的 CPU 支持 Intel SHA 指令集硬件加速！
请选择哈希算法 (1: 硬件加速 [默认], 2: 手写纯软件计算): [直接回车选择默认]
已选择 Intel SHA 硬件加速 (默认)。

>>> 检测到系统最大线程数: 8
请输入运行线程数 (1-8, 默认 [Enter]): [直接回车使用全部线程]
确认以 8 线程运行。
```

## 技术细节

### SHA-256 实现

#### 硬件加速模式 (`sha256_ni.hpp`)
- 利用 Intel SHA 扩展指令集
- 使用 `_mm_sha256msg1_epu32`、`_mm_sha256rnds2_epu32` 等专用指令
- 性能比软件实现提升 3-5 倍

#### 软件实现模式 (`sha256_sw.hpp`)
- 完全手写的标准 SHA-256 算法
- 不依赖任何硬件特性，兼容性最佳
- 适用于不支持 SHA 指令集的旧 CPU

### 多线程架构

- **任务分配**: 采用原子计数器动态分配 nonce 搜索空间
- **局部计数**: 每个线程维护本地哈希计数，定期同步到全局计数器
- **提前终止**: 找到解后立即通知所有线程停止

### 区块头结构

程序按照比特币协议构建 80 字节区块头：

```
偏移量 | 大小 | 字段
-------|------|----------
0      | 4    | 版本号 (小端序)
4      | 32   | 前区块哈希 (反转后)
36     | 32   | 默克尔根 (反转后)
68     | 4    | 时间戳 (小端序)
72     | 4    | 难度 bits (小端序)
76     | 4    | Nonce (挖矿变量)
```

## 输出说明

程序运行时会实时显示：

- **当前 Nonce**: 正在测试的 nonce 值
- **哈希率**: 每秒计算的哈希次数 (H/s, KH/s, MH/s)
- **总哈希数**: 累计计算的哈希总数
- **目标值**: 当前难度对应的目标阈值

找到有效解时显示：

```
[找到解!]
Nonce: 12345678
Hash: 0000abcd...
```

## 注意事项

⚠️ **重要提示**:
- 本程序仅用于**学习和模拟**目的，**不是**拿来挖矿的！
- 请确保输入的区块数据格式正确，你可以在api.blockchair.com上查询区块的信息。

## 许可证

本项目采用 MIT 许可证。详见 [LICENSE](LICENSE) 文件。

## 致谢

- **SHA-Intrinsics**: `sha256-ni.hpp` 基于 [https://github.com/noloader/SHA-Intrinsics](https://github.com/noloader/SHA-Intrinsics) 的代码实现。

## 参考资料

- [比特币协议文档](https://en.bitcoin.it/wiki/Protocol_documentation)
- [Intel SHA Extensions](https://www.intel.com/content/www/us/en/develop/documentation/extension-ref-manual.html)
- [FIPS 180-4 SHA-256 标准](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)

## 贡献

欢迎提交 Issue 和 Pull Request！

---

**免责声明**: 本软件仅供教育和研究用途。
