# perf_harness — BoringSSL 版 QUIC / HTTP/3 编译手册

本目录记录在 `perf` 工作区内编译以下四类产物的完整过程与踩坑经验，目标是让后续接手的 AI 或工程师**只读文档即可复现编译**：

| 编号 | 目标 | 入口 | 产物 |
|---|---|---|---|
| 01 | BoringSSL 静态库（基础依赖） | 手工 cmake，或由 02 的 xquic 脚本内部完成 | `boringssl/build/libssl.a`、`libcrypto.a` |
| 02 | tengine（BabaSSL）+ libxquic（BoringSSL） | `alibaba-tengine/build_tengine_xquic_boringssl.sh` | `test/tengine-xquic-boringssl/sbin/tengine` |
| 03 | nginx 原生 HTTP/3 + BoringSSL | `sh auto/configure`（见 03） | `test/nginx-install/sbin/nginx` |
| 04 | xquic 压测客户端 `test_h3_client` | `test/poc/build_test_h3_client.sh` | `test/poc/build-h3client/test_h3_client` |

## 1. 工作区布局

```
/home/dreamwind.ll/git/perf/            # 记为 $PERF
├── alibaba-tengine/                    # tengine 源码（xquic 子模块在 libs/xquic）
│   ├── build_tengine_xquic_boringssl.sh
│   └── libs/xquic/scripts/
│       ├── build_xquic_boringssl.sh
│       └── README.build_xquic_boringssl.md
├── boringssl/                          # BoringSSL 源码，build/ 为构建目录
├── dreamwind1985/xquic/                # 另一份 xquic 源码（04 用它，含 perf_harness/）
├── nginx/                              # nginx 1.31.9 源码（无根 configure）
└── test/                               # 所有产物、脚本、运行期文件
    ├── nginx-install/                  # 03 的安装前缀
    ├── tengine-xquic-boringssl/        # 02 的安装前缀
    ├── poc/
    │   ├── build-boringssl/            # 02 的 xquic/BoringSSL 构建目录与 install/
    │   ├── build-h3client/             # 04 的构建目录
    │   ├── build_test_h3_client.sh     # 04 脚本
    │   ├── tengine-run/                # tengine 测试配置与证书
    │   └── smoke/                      # 早期 demo_client 等冒烟工具
    └── runtime/                        # 运行期文件（session/token/qlog/log）
```

**硬性约定**：`$PERF` 根目录只允许 5 个目录（`alibaba-tengine`、`boringssl`、`dreamwind1985`、`nginx`、`test`）。安装前缀、构建产物、运行期文件一律放 `test/` 下；不要留在根目录。

注意有两份 xquic 源码，用途不同：

- `alibaba-tengine/libs/xquic`：tengine 的子模块，02 用它构建 `libxquic.so`；
- `dreamwind1985/xquic`：独立克隆（含本目录），04 用它构建 `test_h3_client`。

## 2. 环境前提（先自检）

```bash
export PERF=/home/dreamwind.ll/git/perf

# 编译器（BoringSSL 必须用 clang，gcc 10.2 编 bcm.cc 会 ICE）
gcc --version | head -1        # 期望 10.2.1
clang --version | head -1      # 期望 15.x（/usr/bin/clang）
cmake --version | head -1
make --version | head -1

# BoringSSL 已构建的静态库（02/03/04 都依赖它）
ls -lh $PERF/boringssl/build/libssl.a $PERF/boringssl/build/libcrypto.a
# 期望 12M / 25M 左右

# tengine 路径依赖
ls $PERF/test/poc/build-boringssl/install/lib/libxquic.so   # 02 的 xquic 产物
ls /usr/local/babassl/lib/libssl.a                          # BabaSSL 安装前缀
ls /usr/local/include/jansson.h                             # mod_strategy
ls /usr/local/include/protobuf-c/protobuf-c.h               # ingress / vipserver

# 04 路径依赖
ls /usr/include/event2/event.h                              # libevent（-levent）
```

缺库时的处理写在 [05-troubleshooting.md](05-troubleshooting.md)。

## 3. 推荐执行顺序

```bash
export PERF=/home/dreamwind.ll/git/perf

# ① libxquic.so（BoringSSL 后端），产物 -> $PERF/test/poc/build-boringssl/install
$PERF/alibaba-tengine/libs/xquic/scripts/build_xquic_boringssl.sh

# ② tengine（BabaSSL 静态 + ①的 libxquic.so），产物 -> $PERF/test/tengine-xquic-boringssl
$PERF/alibaba-tengine/build_tengine_xquic_boringssl.sh

# ③ nginx 原生 HTTP/3（BoringSSL 静态），产物 -> $PERF/test/nginx-install
#    见 03-nginx-http3-boringssl.md（无脚本，命令固定）

# ④ test_h3_client（H3 压测客户端），产物 -> $PERF/test/poc/build-h3client
$PERF/test/poc/build_test_h3_client.sh
```

- ① 内部会先编 `boringssl/build` 里的 `ssl`、`crypto` 两个静态库，所以 01 通常不需要单独执行；只有在需要干净重建 BoringSSL 或排查 BoringSSL 自身问题时才单独跑 01。
- ② 依赖 ① 的产物，必须先跑 ①。
- ③、④ 只依赖 `boringssl/build/*.a`，与 ①② 互不依赖，可并行。
- 全部步骤都是增量构建；需要全量重建时各自加 `--clean`。

## 4. 最小验证

```bash
# ① libxquic.so：符号隔离（只导出 xqc_*，SSL_* 必须是 LOCAL）
readelf -d $PERF/test/poc/build-boringssl/install/lib/libxquic.so | grep -E "SONAME|NEEDED|RUNPATH|RPATH"

# ② tengine：版本 + 运行期查找路径
$PERF/test/tengine-xquic-boringssl/sbin/tengine -V
readelf -d $PERF/test/tengine-xquic-boringssl/sbin/tengine | grep RPATH
# 期望 RPATH 指向 test/poc/build-boringssl/install/lib

# ③ nginx：确认是 BoringSSL 且 HTTP/3 已编入
$PERF/test/nginx-install/sbin/nginx -V
# 期望：built with OpenSSL 1.1.1 (compatible; BoringSSL) (running with BoringSSL)
ldd $PERF/test/nginx-install/sbin/nginx | grep -E "libssl|libcrypto"   # 期望无输出

# ④ 客户端
$PERF/test/poc/build-h3client/test_h3_client -h
```

端到端（tengine 服务端 + H3 客户端）：

```bash
cd $PERF && ./test/tengine-xquic-boringssl/sbin/tengine \
    -c $PERF/test/poc/tengine-run/conf/dual1.conf     # 监听 UDP 18443

cd $PERF/test/runtime && \
  $PERF/test/poc/build-h3client/test_h3_client -a 127.0.0.1 -p 18443 -u 127.0.0.1 -C 1 -s 3 -b 0
# 客户端打印 xqc_client_save_token ... h3[0]；服务端 access.log 出现 "GET /index.html" 200
```

## 5. 文档索引

- [01-boringssl.md](01-boringssl.md)：BoringSSL 静态库构建、clang 要求、`-ggdb` 与 strip
- [02-tengine-xquic-boringssl.md](02-tengine-xquic-boringssl.md)：tengine + libxquic 双 TLS 库共存、伴随模块与宏、运行期限制
- [03-nginx-http3-boringssl.md](03-nginx-http3-boringssl.md)：nginx 原生 QUIC 链接 BoringSSL（不能用 `--with-openssl`）
- [04-test-client.md](04-test-client.md)：`test_h3_client` 构建（`XQC_ENABLE_TESTING` + `platform.c` 遗留引用）与压测用法
- [05-troubleshooting.md](05-troubleshooting.md)：跨三套构建的报错速查表

## 6. 关键结论（先记住这几条，能省掉大部分排查）

1. **BoringSSL 是 C++ 实现**：任何链接它的目标（`.so`、可执行文件、configure 探测）都必须补 `-lstdc++`。
2. **BoringSSL 不能走 OpenSSL 的脚本流程**：nginx `--with-openssl=<path>`、tengine 同理会调用 OpenSSL 的 `./config`，对 BoringSSL 无效，只能显式给 `include` 与 `.a`。
3. **BoringSSL 强制 `-ggdb`**：外部传 `-g0` 无效，调试信息会随 `--whole-archive` 进入 `libxquic.so`（4MB→23MB），只能链接后 `strip --strip-debug`。
4. **`libxquic.so` 用 version script 做符号隔离**（`scripts/xquic.lds`），BoringSSL 的 `SSL_*` 全部是 LOCAL，才允许 tengine 同时静态链接 BabaSSL 而不冲突。
5. **xquic 公开头文件 ABI 受 `xqc_configure.h` 宏影响**，`--with-xquic-inc` 必须指向与 `.so` 同一次构建的 `install/include`，不能用源码树。
6. **静态证书即可跑通**：tengine 侧只配 `xquic_ssl_certificate`（xquic 自己用 PEM 加载证书），不要指望 tengine 的 `ssl_certificate` 对 QUIC 生效——那是跨库 X509 对象，会失败。
