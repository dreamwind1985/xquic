# 03 — nginx 原生 HTTP/3 + BoringSSL

目标：在 `nginx 1.31.9` 上编出原生 QUIC/HTTP3（`--with-http_v3_module`），TLS 使用工作区里的 BoringSSL 静态库（不是系统 OpenSSL，也不是 BabaSSL）。

与 02 的关键区别：**nginx 的 QUIC 代码能直接对接 BoringSSL 的新 API，因此不需要 xquic**；但 nginx 的 `--with-openssl=<path>` 对 BoringSSL 无效。

## 1. 源码特点

- `$PERF/nginx` 是 nginx 1.31.9 源码，**根目录没有 `configure` 包装脚本**（`git ls-files` 也没有），必须用 `sh ./auto/configure`；
- `src/event/quic/` 存在，`ngx_event_quic.h` 里按宏分三套 API：BoringSSL / OpenSSL QUIC-compat / 旧 OpenSSL。BoringSSL 不定义 `OPENSSL_VERSION_NUMBER` 但定义 `OPENSSL_IS_BORINGSSL`，落入 `NGX_QUIC_BORINGSSL_API` 分支。

## 2. 为什么不能 `--with-openssl`

`auto/lib/openssl/make` 对 `--with-openssl=<path>` 的处理是：目标目录里如果有 `config` 脚本，就去执行它（OpenSSL/BabaSSL 的构建系统）。BoringSSL 没有这个脚本，也没法这样编。

正确做法：把 BoringSSL 的 `include` 与 `.a` 直接塞进 `--with-cc-opt` / `--with-ld-opt`。

## 3. 构建命令

```bash
export PERF=/home/dreamwind.ll/git/perf
cd $PERF/nginx

sh ./auto/configure \
    --prefix=$PERF/test/nginx-install \
    --with-http_ssl_module \
    --with-http_v2_module \
    --with-http_v3_module \
    --with-cc-opt="-O2 -I$PERF/boringssl/include" \
    --with-ld-opt="-L$PERF/boringssl/build -lstdc++ -lpthread -ldl"

make -j "$(nproc)"
make install
```

参数说明：

| 参数 | 作用 |
|---|---|
| `sh ./auto/configure` | 根目录无 `configure`，必须显式指定脚本路径 |
| `--with-http_v3_module` | 编入 QUIC/HTTP3 |
| `-I$PERF/boringssl/include` | 头文件 |
| `-L$PERF/boringssl/build` | 静态库目录（`libssl.a`、`libcrypto.a`） |
| `-lstdc++` | **必需**，BoringSSL 是 C++ 实现 |
| `-lpthread -ldl` | BoringSSL/nginx 线程与动态加载 |
| `-O2` 放在 `--with-cc-opt` 首位 | nginx 默认 `-O` 在前，`-O2` 追加在后才生效 |

## 4. 成功/失败判定

配置阶段必须看到这一行：

```
checking for BoringSSL-like QUIC API ... found
```

如果探测失败，先看 `$PERF/nginx/objs/autoconf.err`，最常见的错误是链接测试程序时报：

```
undefined reference to `__cxa_throw'
undefined reference to `typeinfo for std::exception'
```

这正是缺 `-lstdc++` 的症状——注意它发生在 **configure 的特征探测阶段**，不是 make 阶段。

## 5. 验证：二进制确实用了 BoringSSL

```bash
N=$PERF/test/nginx-install/sbin/nginx

# 版本串
$N -V
# 期望：built with OpenSSL 1.1.1 (compatible; BoringSSL) (running with BoringSSL)

# 没有动态依赖系统 OpenSSL
ldd $N | grep -E "libssl|libcrypto"      # 期望无输出

# 静态链入了 BoringSSL 的 C++ 符号
nm -C $N 2>/dev/null | grep -c "bssl::"  # 期望上千（实测约 2177）

# BoringSSL 的 SSL_* 是 local 绑定，不是动态导入
strings $N | grep -m2 -i boring

# 系统 OpenSSL 未被使用
readelf -d $N | grep NEEDED
```

后端归属的源码级证据（排查"到底走的哪套 API"时用）：

- 分支：`src/event/quic/ngx_event_quic.h` 的三级条件编译 → `NGX_QUIC_BORINGSSL_API`
- 调用点：`SSL_set_quic_method` / `SSL_provide_quic_data` / `SSL_set_quic_transport_params`
- `objs/ngx_event_quic_openssl_compat.o` 会被编译出来，但整个文件被 `#if (NGX_QUIC_OPENSSL_COMPAT)` 包住且该宏未定义，`nm` 查该 `.o` 里 `SSL_set_quic_method` 符号数为 0，属空占位，不要据此误判。

## 6. 冒烟运行

证书用绝对路径（相对路径会 `nginx -t` 失败）：

```bash
mkdir -p $PERF/test/nginx-install/certs && cd $PERF/test/nginx-install/certs
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout k.pem -out c.pem -subj "/CN=localhost"
```

`test/nginx-install/conf/quic-test.conf`：

```nginx
events { worker_connections 1024; }
http {
    server {
        listen 18443 quic reuseport;
        ssl_certificate     /home/dreamwind.ll/git/perf/test/nginx-install/certs/c.pem;
        ssl_certificate_key /home/dreamwind.ll/git/perf/test/nginx-install/certs/k.pem;
        ssl_protocols TLSv1.3;
        location / { return 200 "h3 ok\n"; }
    }
}
```

```bash
$PERF/test/nginx-install/sbin/nginx -t -c $PERF/test/nginx-install/conf/quic-test.conf
$PERF/test/nginx-install/sbin/nginx    -c $PERF/test/nginx-install/conf/quic-test.conf
ss -lunp | grep 18443          # 期望能看到 worker 监听 UDP 18443
$PERF/test/nginx-install/sbin/nginx -s stop -c $PERF/test/nginx-install/conf/quic-test.conf
```

> 本机没有支持 HTTP/3 的 curl（curl 7.61.1），所以 nginx 侧的端到端只能用 `nginx -t` + UDP 监听 + 符号证据链确认；真正的 H3 请求请用 04 的 `test_h3_client` 去连（注意 `-a` 只接受 IP）。

## 7. 迁移安装目录的注意点

nginx 二进制内嵌了 configure 时的 `--prefix`。如果把安装目录整体搬走（例如从 `$PERF/nginx-install` 移到 `$PERF/test/nginx-install`），必须用**完全相同的参数**重新 `configure --prefix=<新路径>` + `make install`，否则后续 `make install` 会写回旧路径。
