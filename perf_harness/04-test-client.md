# 04 — xquic 压测客户端 test_h3_client

目标：用 `$PERF/dreamwind1985/xquic` 这份源码编出 `test_h3_client`，作为 HTTP/3 客户端去压 tengine（02）或 nginx（03）的 QUIC 服务。

> 注意源码不是 `alibaba-tengine/libs/xquic`，而是独立克隆 `dreamwind1985/xquic`（本手册所在仓库）。两者的 `tests/` 内容不同，本文命令只对后者验证过。

## 1. 一键构建

```bash
export PERF=/home/dreamwind.ll/git/perf

$PERF/test/poc/build_test_h3_client.sh            # 增量
$PERF/test/poc/build_test_h3_client.sh --clean    # 清空构建目录重建

# 产物
ls -lh $PERF/test/poc/build-h3client/test_h3_client   # 约 21M
```

可选环境变量：`WORKSPACE`（自动探测）、`XQUIC_SRC`（默认 `<ws>/dreamwind1985/xquic`）、`BORINGSSL_SRC`、`BUILD_ROOT`（默认 `test/poc/build-h3client`）、`SSL_TYPE=boringssl|babassl`、`JOBS`。

## 2. 手工命令

```bash
export PERF=/home/dreamwind.ll/git/perf

cmake -S $PERF/dreamwind1985/xquic -B $PERF/test/poc/build-h3client \
    -DCMAKE_BUILD_TYPE=Release \
    -DXQC_ENABLE_TESTING=ON \
    -DSSL_TYPE=boringssl \
    -DSSL_INC_PATH=$PERF/boringssl/include \
    -DSSL_LIB_PATH="$PERF/boringssl/build/libssl.a;$PERF/boringssl/build/libcrypto.a" \
    -DCMAKE_EXE_LINKER_FLAGS="-lstdc++" \
    -DCMAKE_SHARED_LINKER_FLAGS="-lstdc++"

cmake --build $PERF/test/poc/build-h3client --target test_h3_client -j "$(nproc)"
```

只编这一个目标，不要 `cmake --build`（全量会连带编一堆测试程序，耗时且容易碰到无关的编译问题）。

## 3. 三个必须知道的坑

### 3.1 `XQC_ENABLE_TESTING` 默认 OFF

`CMakeOptions.txt` 里 `option(XQC_ENABLE_TESTING "Enable Testing" OFF)`，而 `test_h3_client` 的 `add_executable` 整个包在 `if (XQC_ENABLE_TESTING)` 里（`CMakeLists.txt:439` 起）。不开这个开关，target 根本不存在，`--target test_h3_client` 会报 "No rule to make target"。

### 3.2 `tests/platform.c` 的遗留引用（本仓库已修）

上游 commit `540d4db`（"merge remained"）做了三件事：

1. 删除 `tests/platform.c`；
2. 把 `get_sys_errno()` / `set_sys_errno()` / `xqc_platform_init_env()` 改成 `tests/platform.h` 里的 `static inline` 实现；
3. 改了 `tests/CMakeLists.txt`，但**漏改根目录 `CMakeLists.txt`**。

根 `CMakeLists.txt` 原来有三处引用这个不存在的文件：

```cmake
add_executable(test_server tests/test_server.c  tests/platform.c  ${GETOPT_SOURCES})
add_executable(test_client tests/test_client.c  tests/platform.c ${GETOPT_SOURCES})
...
set(HQ_SOURCES
    "demo/xqc_hq_ctx.c"
    "demo/xqc_hq_conn.c"
    "demo/xqc_hq_request.c"
    "tests/platform.c"        # demo_client 也已改用 platform.h 内联版
)
```

后果不是 "Cannot find source file"，而是：

```
CMake Error at CMakeLists.txt:465 (add_executable):
  No SOURCES given to target: test_server
```

生成阶段直接失败，连 `test_h3_client` 的构建规则都写不出来。

**本仓库已按方案 2 修好**：删掉上述三处引用（对应提交 `653d19d del platform.c`）。`build_test_h3_client.sh` 仍保留幂等兜底：发现 `CMakeLists.txt` 里还有 `tests/platform.c` 就自动删掉，再配置——因此在未修复的分支/新克隆上也能一次构建成功。

如果换一份未修复的 xquic 源码，二选一：

- 改 `CMakeLists.txt` 删掉三处引用（推荐，源头修复）；
- 或从 `git show <删文件commit>^:tests/platform.c` 恢复文件（临时方案，会多一个未跟踪文件）。

### 3.3 链接需要 `-lstdc++` 和 libevent

`test_h3_client` 链接的是 `xquic-static`（不是 `.so`），BoringSSL 的 C++ 符号会直接进可执行文件，因此：

- `-DCMAKE_EXE_LINKER_FLAGS="-lstdc++"` 必需；
- CMakeLists 给测试目标已经写了 `-ldl -lpthread -levent -lm`，所以只需系统有 libevent 开发包（`/usr/include/event2/event.h`）。

`-DXQC_ENABLE_TESTING=ON` 还会 `find_package(CUnit 2.1)`，但它是可选的（只影响 `check` target），没装 CUnit 不影响编译。

## 4. 参数

```bash
$PERF/test/poc/build-h3client/test_h3_client -h
```

| 参数 | 含义 | 默认 |
|---|---|---|
| `-a` | 服务端地址，**只接受 IPv4 字面量**（不支持域名） | 127.0.0.1 |
| `-p` | 服务端端口 | 8443 |
| `-u` | host / SNI | 127.0.0.1 |
| `-T` | 传输层：0=H3，1=Transport，2=H3-ext | 0 |
| `-C` | 最大连接数 | 1000 |
| `-c` | 每秒新建连接数 | 1 |
| `-s` | 每条连接上的 stream 数 | 10 |
| `-q` | qpack header key-value 数 | 10 |
| `-b` | 请求 body 长度（字节） | 1024 |
| `-m` | 模式：0 并发，1 新建连接，2 单连接多流 | 0 |
| `-Q` / `-I` | 每次创建的请求数 / 请求间隔 | 1 / 0 |
| `-P` | 进程数 | 1 |
| `-r` | 0-RTT：0 关闭，1 开启 | 0 |
| `-H` | 自定义 header 文件 | — |
| `-D` | 打印调试信息到 stdout | 关 |

这是**压测模型**：启动后持续建立连接/发请求，不会自己退出，需要 `Ctrl-C` 或 `timeout` 结束。

## 5. 实测用法与预期输出

```bash
# 1) 先起一个 H3 服务端（02 的 tengine，UDP 18443）
cd $PERF && ./test/tengine-xquic-boringssl/sbin/tengine \
    -c $PERF/test/poc/tengine-run/conf/dual1.conf

# 2) 在运行期目录下跑客户端（避免把 session/token 文件拉在 perf 根目录）
cd $PERF/test/runtime
timeout 8 $PERF/test/poc/build-h3client/test_h3_client \
    -a 127.0.0.1 -p 18443 -u 127.0.0.1 -C 1 -s 3 -b 0
```

客户端输出：

```
xqc_client_save_token use client ip as the key. h3[0]     # 握手成功 + 0-RTT session 落盘
```

服务端 access.log（`test/poc/tengine-run/logs/access.log`）：

```
127.0.0.1 [...] "GET /index.html HTTP/3.0" 200 8
```

说明：请求路径固定为 `/index.html`，服务端 `return 200` 的 body 长度会对上 `-b` 之后的实际响应长度。

## 6. 运行期副作用

客户端会在**当前工作目录**生成这些文件：

```
test_session  tp_localhost  xqc_token  clog  b_stats  ckeys.log
```

分别对应 0-RTT session、transport params、token、qlog、统计。首次运行会打印 `read file error:test_session` 之类的提示，属正常（文件还不存在）。建议固定在 `test/runtime/` 下运行，符合工作区"根目录只保留 5 个目录"的约定。

## 7. 与 `demo_client` 的差异

`tests/` 里还有早期的 `demo_client`（02 的冒烟工具在 `test/poc/smoke/`），两者差别：

| | `test_h3_client` | `demo_client` |
|---|---|---|
| 定位 | 压测（多连接/多 stream、可配 qpack/body） | 单次请求冒烟 |
| 地址 | 只接受 IP | 只接受 IP，且 SNI 固定为 IP |
| 退出 | 持续跑，需手动结束 | 请求完自行退出 |
| 依赖 | libevent | libevent |
