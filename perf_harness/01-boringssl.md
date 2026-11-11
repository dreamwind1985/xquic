# 01 — BoringSSL 静态库

BoringSSL 是 02（libxquic.so）、03（nginx HTTP/3）、04（test_h3_client）的共同依赖。正常情况下它由 02 的脚本自动构建；本文用于干净重建或排查 BoringSSL 自身问题。

## 1. 为什么必须用 clang

本机 gcc 10.2.1 编译 `boringssl/crypto/fipsmodule/bcm.cc` 会触发编译器内部错误（ICE）。改用 clang 15 正常。BoringSSL 自己也只对 clang 做完整测试，因此：

```
CC=clang  CXX=clang++
```

`-ggdb` 是 BoringSSL 在 `CMakeLists.txt` 内**强制追加**的（追加位置在调用方 `CMAKE_C_FLAGS` 之后），传 `-g0` 无法关闭，见第 4 节。

## 2. 构建命令

```bash
export PERF=/home/dreamwind.ll/git/perf
cd $PERF/boringssl

# 配置：静态库 + PIC（PIC 是后续 --whole-archive 进 libxquic.so 的前提）
CC=clang CXX=clang++ cmake -S . -B build \
    -DBUILD_SHARED_LIBS=0 \
    -DBUILD_TESTING=OFF \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_FLAGS="-fPIC" \
    -DCMAKE_CXX_FLAGS="-fPIC" \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON

# 只编 ssl 和 crypto 两个目标（全量 target 会带上测试与工具，耗时翻倍）
cmake --build build --target ssl crypto -j "$(nproc)"
```

全量重建时先 `rm -rf build`。构建目录固定为 `boringssl/build`，02/03/04 都从这里取库。

## 3. 产物位置（新旧版本布局不同）

不同 BoringSSL 版本库的落盘位置不同，消费方必须兼容两种：

```
boringssl/build/libssl.a        boringssl/build/ssl/libssl.a
boringssl/build/libcrypto.a     boringssl/build/crypto/libcrypto.a
```

当前工作区的实际情况：

```bash
ls -lh $PERF/boringssl/build/libssl.a $PERF/boringssl/build/libcrypto.a
# 约 12M / 25M
```

下游统一用这两个变量：

```bash
SSL_INC_PATH=$PERF/boringssl/include
SSL_LIB_PATH="$PERF/boringssl/build/libssl.a;$PERF/boringssl/build/libcrypto.a"
```

在 cmake 参数里 `SSL_LIB_PATH` 是用**分号分隔的绝对路径**，不能写成 `-lssl`，因为 xquic 的 `cmake/FindSSL.cmake` 只认特定目录布局，必须显式绕开它（见 02）。

## 4. 调试信息与体积（必须知道）

`boringssl/CMakeLists.txt` 内部以 `set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ... -ggdb ...")` 的形式在自己那一串标志**末尾**追加 `-ggdb`，覆盖调用方传入的 `-g0`。

后果：BoringSSL 的 DWARF 信息会随 `--whole-archive` 全部进入 `libxquic.so`：

- 体积从约 4.2MB 膨胀到约 23.8MB；
- 含约 1585 条构建机绝对路径字符串。

处理方式：**链接后剥离**，不要试图在 BoringSSL 侧关闭调试信息。

```bash
strip --strip-debug $PERF/test/poc/build-boringssl/install/lib/libxquic.so
```

剥离后仍残留约 229 条路径字符串，来自 BoringSSL 源码里的 `__FILE__` 字面量，属代码本身，无法去除也无运行期影响。

## 5. 验证

```bash
# 库存在且是静态归档
file $PERF/boringssl/build/libssl.a            # 期望 "current ar archive"
ls -lh $PERF/boringssl/build/lib{crypto,ssl}.a

# 是 BoringSSL：静态库里只有源码路径，版本串只出现在最终二进制里
# （nginx 为 "built with OpenSSL 1.1.1 (compatible; BoringSSL)"；
#   tengine 自己链的是 BabaSSL，-V 显示 "babassl version: babassl/8.3.5"）
strings $PERF/boringssl/build/libssl.a | grep -m2 "/boringssl/"

# 是 C++ 实现：存在 bssl:: 命名空间符号（消费方必须 -lstdc++ 的直接证据）
nm -C $PERF/boringssl/build/libssl.a 2>/dev/null | grep -m3 "bssl::"

# 头文件
ls $PERF/boringssl/include/openssl/ssl.h
```

## 6. 供下游使用的参数速查

| 消费方 | 需要的参数 |
|---|---|
| libxquic.so（02） | `-DSSL_TYPE=boringssl -DSSL_INC_PATH=<inc> -DSSL_LIB_PATH="<libssl.a>;<libcrypto.a>" -DCMAKE_SHARED_LINKER_FLAGS="-lstdc++"` |
| nginx（03） | `--with-cc-opt="-O2 -I<inc>" --with-ld-opt="-L<build> -lstdc++ -lpthread -ldl"` |
| test_h3_client（04） | 同 02，另加 `-DCMAKE_EXE_LINKER_FLAGS="-lstdc++"` |

共性：**头文件用 `boringssl/include`，库用 `boringssl/build` 下的 `.a`，链接一律补 `-lstdc++`。**
