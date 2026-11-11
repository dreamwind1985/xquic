# 02 — tengine（BabaSSL）+ libxquic（BoringSSL）

目标：tengine 自身的 HTTPS/HTTP2 使用 **BabaSSL**，而 QUIC/HTTP3 由 **BoringSSL 版 libxquic.so** 提供。两套 TLS 实现在同一个进程里共存，靠 `libxquic.so` 的符号隔离保证不冲突。

## 1. 架构

```
tengine (BabaSSL 静态链接)
├── ngx_http_ssl_module          -> BabaSSL：TCP/TLS、HTTP/2
└── ngx_http_xquic_module        -> dlopen/link libxquic.so
                                     └── BoringSSL（--whole-archive 静态链入 .so）
```

不冲突的前提：`libs/xquic/scripts/xquic.lds` 这个 version script 把 `libxquic.so` 的导出符号限制为 `xqc_*`，BoringSSL 的 `SSL_*`/`X509_*` 全部是 LOCAL，不会与 tengine 里的 BabaSSL 同名符号互相顶替。

## 2. 一键构建（推荐）

```bash
export PERF=/home/dreamwind.ll/git/perf

# ① 先编 BoringSSL + libxquic.so，安装到 test/poc/build-boringssl/install
$PERF/alibaba-tengine/libs/xquic/scripts/build_xquic_boringssl.sh

# ② 再编 tengine，安装到 test/tengine-xquic-boringssl
$PERF/alibaba-tengine/build_tengine_xquic_boringssl.sh
```

- ① 的详细参数与校验见 `libs/xquic/scripts/README.build_xquic_boringssl.md`
- ② 必须看到 ① 的 `install/lib/libxquic.so` 存在，脚本会前置检查
- 增量构建；全量重建分别加 `--clean`
- 只改 tengine 侧参数想重编时：`SKIP_CONFIGURE=1` 可复用已有 Makefile 只跑 make

可用环境变量（都有默认值）：

| 变量 | 默认 | 说明 |
|---|---|---|
| `WORKSPACE` | 自动向上探测（含 `alibaba-tengine/` 与 `boringssl/`） | 工作区根 |
| `XQUIC_PREFIX` | `<ws>/test/poc/build-boringssl/install` | ① 的安装目录 |
| `BABASSL_PREFIX` | `/usr/local/babassl` | BabaSSL 安装前缀 |
| `INSTALL_PREFIX` | `<ws>/test/tengine-xquic-boringssl` | tengine 安装前缀 |
| `JOBS` | `nproc`（上限 64） | 并行度 |
| `WITH_DEBUG` | `0` | `1` 追加 `--with-debug` |
| `CONFIGURE_EXTRA` | 空 | 追加 configure 参数 |

## 3. 手工等价命令

### 3.1 libxquic.so（BoringSSL 后端）

```bash
export PERF=/home/dreamwind.ll/git/perf
XQUIC_SRC=$PERF/alibaba-tengine/libs/xquic
BUILD=$PERF/test/poc/build-boringssl

cmake -S "$XQUIC_SRC" -B "$BUILD/xquic" \
    -DCMAKE_BUILD_TYPE=Release \
    -DSSL_TYPE=boringssl \
    -DSSL_INC_PATH=$PERF/boringssl/include \
    -DSSL_LIB_PATH="$PERF/boringssl/build/libssl.a;$PERF/boringssl/build/libcrypto.a" \
    -DCMAKE_SHARED_LINKER_FLAGS="-lstdc++" \
    -DXQC_COMPAT_DUPLICATE=1 -DXQC_COMPAT_GENERATE_SR_PKT=1 \
    -DXQC_ENABLE_BBR2=1 -DXQC_ENABLE_COPA=1 -DXQC_ENABLE_RENO=1 -DXQC_ENABLE_UNLIMITED=1 \
    -DXQC_ENABLE_MP_INTEROP=1 -DXQC_NO_PID_PACKET_PROCESS=1 -DXQC_PROTECT_POOL_MEM=1 \
    -DXQC_PRINT_SECRET=1 -DXQC_ENABLE_FEC=1 -DXQC_ENABLE_XOR=1 -DXQC_ENABLE_RSC=1 \
    -DXQC_ENABLE_PKM=1

cmake --build "$BUILD/xquic" -j "$(nproc)"
strip --strip-debug "$BUILD/xquic/libxquic.so"

# 安装（头文件 + .so），tengine 的 --with-xquic-inc 必须指向这里
cmake --install "$BUILD/xquic" --prefix "$BUILD/install"
```

三个要点：

1. `SSL_TYPE=boringssl` + 显式 `SSL_INC_PATH`/`SSL_LIB_PATH`：xquic 的 `cmake/FindSSL.cmake` 只兼容旧的 BoringSSL 目录布局，新版必须绕过。
2. `-DCMAKE_SHARED_LINKER_FLAGS="-lstdc++"`：否则 `.so` 里 BoringSSL 的 C++ 符号在 dlopen 时未定义。
3. `strip --strip-debug`：BoringSSL 强制 `-ggdb`，不剥离则 `.so` 约 23MB。

上面这串 `XQC_*` 与 tengine 的 rpm 打包配置保持一致，其中 **`XQC_PROTECT_POOL_MEM` 会改变 `xqc_conn_settings_t` 的内存布局**，所以 `--with-xquic-inc` 必须使用与 `.so` 同一次构建产出的 `install/include`，绝不能用源码树里的 `include/`。

### 3.2 tengine

```bash
export PERF=/home/dreamwind.ll/git/perf
cd $PERF/alibaba-tengine

export OPENSSL_BIN=YES          # 关键：让 tengine 按“已安装前缀”处理，而不是去跑 ./config
./configure \
    --prefix=$PERF/test/tengine-xquic-boringssl \
    --sbin-path=$PERF/test/tengine-xquic-boringssl/sbin/tengine \
    --with-openssl=/usr/local/babassl \
    --with-http_ssl_module --with-http_v2_module \
    --with-xquic-inc=$PERF/test/poc/build-boringssl/install/include \
    --with-xquic-link=$PERF/test/poc/build-boringssl/install/lib \
    --with-xquic-lib=$PERF/test/poc/build-boringssl/install/lib \
    --add-module=modules/ngx_http_xquic_module \
    --add-module=modules/mod_common \
    --add-module=modules/mod_diamond \
    --add-module=modules/ngx_http_vipserver_module \
    --add-module=modules/mod_events \
    --add-module=modules/ngx_http_keyless \
    --add-module=modules/ngx_openssl_keyless \
    --add-module=modules/ngx_ingress_module \
    --add-module=modules/mod_strategy \
    --add-module=modules/mod_backend \
    --with-cc-opt="-Wno-error -DT_INGRESS_SHARED_MEMORY_PB -DT_VIPSERVER_UPDATE_PEER" \
    --with-ld-opt="-L/usr/local/lib -lprotobuf-c -ljansson"

make -j "$(nproc)"
make install
```

每个非显然参数的原因：

| 参数 | 不加会怎样 |
|---|---|
| `OPENSSL_BIN=YES` | tengine 发现 `--with-openssl` 指向已安装前缀时，仍会去 `$OPENSSL/.openssl` 走“重新编译 OpenSSL”分支而失败 |
| 9 个 `--add-module` | core 引用了 mod_common 的 `ngx_comm_encrypt.h`、mod_diamond 的 `ngx_http_diamond_app_get()`、vipserver 的 `ngx_http_ups_autoconf_*`、mod_events 的 `ngx_event_request.h`，缺头/缺符号 |
| `-DT_INGRESS_SHARED_MEMORY_PB` | `ngx_http_ssl_servername()` 等实现被包在该宏里，ssl_module 无条件引用 → 链接失败 |
| `-DT_VIPSERVER_UPDATE_PEER` | `ngx_http_ups_autoconf_update_peer()` 缺实现（原生由 mod_unit 打开，但会连带 mod_tair2，故用宏替代） |
| `-Wno-error` | tengine master 有既有告警，默认 `-Werror` 会中断编译 |
| `-L/usr/local/lib -lprotobuf-c -ljansson` | ingress/vipserver/strategy 的运行期依赖 |
| `--with-xquic-inc` 指 install | 头文件 ABI 与 `.so` 不匹配（见 3.1 第 3 点） |

## 4. 验证

```bash
T=$PERF/test/tengine-xquic-boringssl

# 版本（注意：tengine 本体链的是 BabaSSL，QUIC 才走 BoringSSL）
$T/sbin/tengine -V
# 期望：Tengine version: Tengine/2.5.11
#       babassl version: babassl/8.3.5

# 运行期查找路径必须是稳定安装目录（不是构建目录、不是源码树）
readelf -d $T/sbin/tengine | grep -E "RPATH|RUNPATH"
# 期望：.../test/poc/build-boringssl/install/lib

# 符号隔离：libxquic.so 只导出 xqc_*，SSL_* 为 LOCAL
readelf -sW $PERF/test/poc/build-boringssl/install/lib/libxquic.so | \
    awk '$5=="GLOBAL"{print $8}' | grep -c '^SSL_'      # 期望 0
readelf -sW $PERF/test/poc/build-boringssl/install/lib/libxquic.so | \
    awk '$5=="GLOBAL"{print $8}' | grep -c '^xqc_'      # 期望 > 0
```

## 5. 运行期：最小可用配置

**QUIC 的证书走 xquic 自己的 PEM 加载，不走 tengine 的 `ssl_certificate`。**

```nginx
http {
    # QUIC 证书（xquic 模块自己的指令，只写这一处即可握手成功）
    xquic_ssl_certificate     /abs/path/server.crt;
    xquic_ssl_certificate_key /abs/path/server.key;

    server {
        listen 18443 xquic;              # 纯 QUIC
        server_name 127.0.0.1;
        location / { return 200 "h3 ok\n"; }
    }
}
```

已知限制（都经过实测）：

| 项 | 现象 | 原因 |
|---|---|---|
| `$xquic_ssl_cipher` | **SIGSEGV** | `ngx_xquic_ssl_get_cipher_name` 拿 BoringSSL 的 `SSL*` 调 BabaSSL 的 `SSL_get_current_cipher` |
| `$xquic_ssl_protocol` | 恒为 `unknown` | 同上，`SSL_get_version` 跨库读对象 |
| `$ssl_protocol` | 空 | QUIC 连接没有 tengine 的 `ngx_ssl_connection_t`，`sscf->ssl.ctx` 为空 |
| 同时配 `ssl_certificate` + `xquic_ssl_certificate` | 握手失败，`conn_err:336` | tengine 把 BabaSSL 的 X509 传给 BoringSSL 的 `SSL_use_certificate`（`xqc_tls.c:1456`），跨库对象失败 |
| 单个 server 块混写 `listen 18443 ssl; listen 18443 xquic;` | QUIC 失败 `conn_err:336`，TCP 正常 | 同一 server 的 `ssl_certificate` 走了 QUIC 分支 |

结论：**静态证书场景零代码改动可用**；不要做 tengine `ssl_certificate` 与 QUIC 的混用，也即暂不需要 PEM 桥接改造。

## 6. 双栈（TCP + QUIC 同端口）必须拆两个 server 块

```nginx
http {
    xquic_ssl_certificate     /abs/server.crt;
    xquic_ssl_certificate_key /abs/server.key;

    # QUIC 块：只有 xquic，不带 ssl
    server {
        listen 18443 xquic;
        server_name 127.0.0.1;
        location / { return 200 "h3 ok\n"; }
    }

    # TCP 块：只带 ssl
    server {
        listen 18443 ssl;
        ssl_certificate     /abs/server.crt;
        ssl_certificate_key /abs/server.key;
        location / { return 200 "tcp ok\n"; }
    }
}
```

实测矩阵：

| 用例 | 布局 | QUIC | TCP |
|---|---|---|---|
| A | 两个 server，QUIC 块在前 | 200 | 200 |
| B | 两个 server，SSL 块在前 | 200 | 200 |
| C | 单个 server 混写两个 listen | 失败（`conn_err:336`） | 200 |

顺序无关，但**必须拆块**。

### SNI 行为（影响 server_name 的写法）

- 连接初始化只按 `地址:端口` 选 `default_server`（`hc->conf_ctx = hc->addr_conf->default_server->ctx`，`ngx_http_xquic.c:1706`）；
- 证书回调 `ngx_http_v3_cert_cb_lua` 只查 `virtual_names`（通配/正则名），**跳过精确名 hash**（`ngx_http_xquic.c:293-336`）；
- 因此写精确 `server_name example.com;` 不会让 QUIC 选中该 server，需要通配（`*.example.com`）或直接依赖默认 server。
