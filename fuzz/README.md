# Fuzzing

libFuzzer harnesses for the code that parses untrusted network input, built
with AddressSanitizer and UndefinedBehaviorSanitizer. They need Clang 19 or
newer: Clang 18 cannot build eventloop against libstdc++ 13, which enables
`std::expected` only for `__cpp_concepts >= 202002`.

| Harness | Input |
| --- | --- |
| `fuzz_http1_session` | HTTP/1.1 connection bytes: heads, pipelining, routed bodies, static responses |
| `fuzz_http2_session` | HTTP/2 frames after the client preface, with static and routed streams |
| `fuzz_hpack` | HPACK header blocks through one decoder, so dynamic-table state carries over |
| `fuzz_qpack` | A QPACK field section and encoder-stream instructions |
| `fuzz_http3_request` | HTTP/3 request-stream frames, QPACK decoding, and request validation |
| `fuzz_quic` | QUIC packet headers and frame sequences |
| `fuzz_chunked` | HTTP/1.1 chunked bodies |

Harnesses that read a stream take a first byte that chooses how many bytes
arrive per read, so parsers see every split point.

```sh
CC=clang-20 CXX=clang++-20 cmake -S . -B build-fuzz -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DBUILD_TESTING=OFF -DEVENTLOOP_FUZZERS=ON
cmake --build build-fuzz -j --target fuzz_http2_session
mkdir -p corpus/http2_session
./build-fuzz/fuzz_http2_session -max_total_time=600 corpus/http2_session
```

A crash leaves `crash-<hash>` in the working directory; rerun the harness
with that file as its only argument to reproduce it under the sanitizers.
