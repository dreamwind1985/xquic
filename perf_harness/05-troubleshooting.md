# 05 — 报错速查 / 踩坑总表

按"看到什么现象 → 为什么 → 怎么改"组织。条目都来自本工作区的真实构建与运行。

## 1. 编译阶段

| 现象 | 根因 | 解法 |
|---|---|---|
| `CMake Error at CMakeLists.txt:465 (add_executable): No SOURCES given to target: test_server` | 上游 `540d4db` 删了 `tests/platform.c`，但根 `CMakeLists.txt` 仍有 3 处引用 | 删掉这 3 处引用（本仓库已提交 `653d19d`，详见 04 §3.2）；或临时从 `git show 540d4db^:tests/platform.c` 恢复文件 |
| `The current CMakeCache.txt directory ... is different than the directory ... where CMakeCache.txt was created` | 构建目录被整体搬移（如 `.poc/` → `test/poc/`），缓存里记着旧绝对路径 | 删掉该构建子目录重配；xquic 脚本的 `reset_moved_build_dir()` 已自动处理（比对 `CMAKE_CACHEFILE_DIR`） |
| BoringSSL 编译 `crypto/fipsmodule/bcm.cc` 时 ICE（internal compiler error） | gcc 10.2.1 编不动该文件 | 用 clang：`CC=clang CXX=clang++ cmake ...` |
| `undefined reference to '__cxa_throw'` / `typeinfo for std::exception` | BoringSSL 是 C++ 实现，链接方没带 `-lstdc++` | cmake：`-DCMAKE_SHARED_LINKER_FLAGS="-lstdc++"` / `-DCMAKE_EXE_LINKER_FLAGS="-lstdc++"`；nginx：`--with-ld-opt=... -lstdc++` |
| xquic cmake 找不到 SSL，或 `FindSSL.cmake` 报路径不匹配 | 新版 BoringSSL 库在 `build/` 或 `build/ssl|crypto/`，`FindSSL.cmake` 只认一种旧布局 | 显式传 `-DSSL_TYPE=boringssl -DSSL_INC_PATH=<inc> -DSSL_LIB_PATH="<libssl.a>;<libcrypto.a>"` |
| tengine `./configure --with-openssl=/usr/local/babassl` 阶段报错、去编 OpenSSL | 该路径下有 `config` 脚本时 tengine 会走"重新编译 OpenSSL"分支 | `export OPENSSL_BIN=YES`（脚本按"已安装前缀"判定后自动设置） |
| tengine 编译报缺 `ngx_comm_encrypt.h` / `ngx_event_request.h` / `ngx_http_ups_autoconf_*` | core 与 xquic 模块依赖内置伴随模块 | 加 `--add-module`：mod_common、mod_diamond、ngx_http_vipserver_module、mod_events、ngx_http_keyless、ngx_openssl_keyless、ngx_ingress_module、mod_strategy、mod_backend |
| tengine 链接报 `ngx_http_ssl_servername` / `ngx_http_ups_autoconf_update_peer` 未定义 | 实现被包在 `T_INGRESS_SHARED_MEMORY_PB` / `T_VIPSERVER_UPDATE_PEER` 里 | `--with-cc-opt="-DT_INGRESS_SHARED_MEMORY_PB -DT_VIPSERVER_UPDATE_PEER"` |
| tengine make 因告警中断（`-Werror`） | master 存在既有告警 | `--with-cc-opt="-Wno-error"` |
| tengine 链接缺 `jansson` / `protobuf-c` | ingress/vipserver/strategy 的运行期依赖在 `/usr/local` | `--with-ld-opt="-L/usr/local/lib -lprotobuf-c -ljansson"` |
| nginx 执行 `./configure` 报 No such file | 该源码树根目录没有 `configure` 包装脚本 | `sh ./auto/configure ...` |
| nginx configure 报 `BoringSSL-like QUIC API ... not found` | 链接探测失败，最常见是缺 `-lstdc++` | 看 `nginx/objs/autoconf.err`；补 `-lstdc++ -lpthread -ldl` 后重跑 |
| 04 的 `--target test_h3_client` 报 `No rule to make target` | `XQC_ENABLE_TESTING` 默认 OFF，target 没生成 | 加 `-DXQC_ENABLE_TESTING=ON` |
| 04 链接缺 `event_new` / `event_add` | 缺 libevent | 装 libevent 开发包（`/usr/include/event2/event.h`） |

## 2. 运行阶段

| 现象 | 根因 | 解法 |
|---|---|---|
| QUIC 握手失败，`conn_err:336`，服务端 `SSL_use_certificate` 报错（`xqc_tls.c:1456`） | tengine 的 `ssl_certificate`（BabaSSL 的 X509 对象）被传给 BoringSSL | QUIC 只用 `xquic_ssl_certificate`，别在同一场景混用 `ssl_certificate`（见 02 §5） |
| 使用 `$xquic_ssl_cipher` 时进程 **SIGSEGV** | `ngx_xquic_ssl_get_cipher_name` 用 BoringSSL 的 `SSL*` 调 BabaSSL 的 `SSL_get_current_cipher` | 不要用这个变量 |
| `$xquic_ssl_protocol` 恒为 `unknown`，`$ssl_protocol` 为空 | 同上跨库读对象；QUIC 连接也没有 tengine 的 `ngx_ssl_connection_t` | 不要依赖这些变量做逻辑 |
| 单个 server 块同时 `listen 18443 ssl;` + `listen 18443 xquic;`，QUIC 失败 TCP 正常 | 同 server 的 `ssl_certificate` 走进了 QUIC 分支 | 拆成两个 server 块（见 02 §6），顺序无关 |
| 配了精确 `server_name example.com;` 但 QUIC 仍用默认 server | QUIC 选 server 只看 `地址:端口` 的 default_server；证书回调只查 `virtual_names`（通配/正则） | 用通配 `*.example.com`，或直接依赖 default server |
| `libxquic.so` 体积 23MB，`strings` 里大量构建机路径 | BoringSSL 强制 `-ggdb`，DWARF 随 `--whole-archive` 进入 `.so` | `strip --strip-debug libxquic.so`（脚本默认做） |
| `dlopen("libxquic.so")` 报 `__cxxabiv1` / `__cxa_*` 未定义 | `.so` 链接时没带 `-lstdc++` | 重编时加 `-DCMAKE_SHARED_LINKER_FLAGS="-lstdc++"` |
| 搬动安装目录后，tengine 启动找不到 `libxquic.so`，或 `make install` 又写回旧目录 | tengine 把 `--with-xquic-link` 写成 RPATH；nginx 二进制内嵌 `--prefix` | 安装前缀固定放 `test/` 下重跑 configure；或运行期用 `-p` 覆盖 |
| 客户端报 `Connection refused`，但服务端日志有 `init connection` | 服务端进程在握手后已退出（被沙箱回收、崩溃、或 `pkill` 杀掉） | 先 `pgrep -x tengine` 确认存活；调试时用 `gdb -batch -ex run -ex bt` 抓栈 |
| `demo_client` / `test_h3_client` 报 `invalid server address: localhost` | 客户端只接受 IPv4 字面量，不解析域名 | 用 `127.0.0.1` |
| `test_h3_client` 跑完不退出、也不打印统计 | 它是压测模型，按 `-C`/`-c` 持续建连 | 用 `timeout N ...` 或 `Ctrl-C` 结束 |
| 客户端 stdout 重定向到文件后内容为空 | 被 `timeout` 杀掉时 stdio 块缓冲未 flush | 加 `stdbuf -oL -eL`，或让它在 pty 里跑 |

## 3. 脚本编写经验（本工作区脚本踩过的坑）

| 写法 | 问题 | 正确写法 |
|---|---|---|
| `VAR=$(cd "$1" && pwd)` 且 `$1` 可能为空 | bash 下 `cd ""` **返回成功且停在当前目录**，导致工作区探测错位（`perf/test/test/poc/...`） | 只在变量非空时绝对化：`[ -n "${X:-}" ] && X=$(resolve_abs "$X")`，否则走 `find_workspace` |
| `ls a b 2>/dev/null` 取存在的那个 | `ls` 只要有任一参数不存在就返回非 0，`set -e` 下直接退出 | 用 `find <dir> -maxdepth N -name X | head -1`，或 `|| true` |
| `[ cond ] && cmd` 作为独立语句 | 条件为假时整条返回 1，`set -e` 下脚本静默退出 | 写成 `if [ cond ]; then cmd; fi` |
| `pkill -f "dual1.conf"` | 会匹配到当前 shell 自己的命令行，把自己杀掉 | `pkill -x tengine` |
| heredoc 里直接写 `$xquic_ssl_*` | `set -u` 下被当变量展开，报 unbound variable | 转义：`\$xquic_ssl_*` |
| `rm -rf "$BUILD_ROOT"` 直接清理 | `BUILD_ROOT` 被误设为 `/` 或工作区根时灾难性 | 白名单校验：只允许 `*/build-*`、`*/.poc/*` 等模式 |

## 4. 环境限制备忘

- 本机没有支持 HTTP/3 的 curl（7.61.1），HTTP/3 端到端只能用 `test_h3_client` 或 `demo_client`。
- 后台进程用 `setsid nohup` 启动仍可能被运行环境回收；需要稳定服务时用带 `daemon off; master_process off;` 的前台方式挂在保活终端里。
- `inotify`/`setsockopt(new-udp-hash)` 在容器里可能报警（`nginx: [alert] |xquic| setsockopt(new-udp-hash) failed, ignored|`），不影响功能。
