window.BENCHMARK_DATA = {
  "lastUpdate": 1782149026721,
  "repoUrl": "https://github.com/ShenChen1/ufifo",
  "entries": {
    "ufifo Performance Benchmark": [
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "1beaddc72193b946fd8fa87321318f3bb78806f3",
          "message": "ci: remove invalid auto-mutate-gh-pages for benchmark-action",
          "timestamp": "2026-03-09T17:35:41Z",
          "tree_id": "f2e1be4cdc1aac22537f472b69d2556a69106b74",
          "url": "https://github.com/ShenChen1/ufifo/commit/1beaddc72193b946fd8fa87321318f3bb78806f3"
        },
        "date": 1773078099028,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 575863,
            "unit": "ops/sec",
            "extra": "Latency: 1736.5 ns/op, Bandwidth: 2.20 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 578723,
            "unit": "ops/sec",
            "extra": "Latency: 1727.9 ns/op, Bandwidth: 35.32 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 571833,
            "unit": "ops/sec",
            "extra": "Latency: 1748.8 ns/op, Bandwidth: 139.61 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 569777,
            "unit": "ops/sec",
            "extra": "Latency: 1755.1 ns/op, Bandwidth: 556.42 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 554862,
            "unit": "ops/sec",
            "extra": "Latency: 1802.3 ns/op, Bandwidth: 2167.43 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 568954,
            "unit": "ops/sec",
            "extra": "Latency: 1757.6 ns/op, Bandwidth: 2.17 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 568144,
            "unit": "ops/sec",
            "extra": "Latency: 1760.1 ns/op, Bandwidth: 34.68 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 565406,
            "unit": "ops/sec",
            "extra": "Latency: 1768.6 ns/op, Bandwidth: 138.04 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 563227,
            "unit": "ops/sec",
            "extra": "Latency: 1775.5 ns/op, Bandwidth: 550.03 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 543607,
            "unit": "ops/sec",
            "extra": "Latency: 1839.6 ns/op, Bandwidth: 2123.46 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 1121051,
            "unit": "ops/sec",
            "extra": "Latency: 892.0 ns/op, Bandwidth: 4.28 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 1114413,
            "unit": "ops/sec",
            "extra": "Latency: 897.3 ns/op, Bandwidth: 68.02 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 1033825,
            "unit": "ops/sec",
            "extra": "Latency: 967.3 ns/op, Bandwidth: 252.40 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 1093488,
            "unit": "ops/sec",
            "extra": "Latency: 914.5 ns/op, Bandwidth: 1067.86 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 422103,
            "unit": "ops/sec",
            "extra": "Latency: 2369.1 ns/op, Bandwidth: 1.61 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 407679,
            "unit": "ops/sec",
            "extra": "Latency: 2452.9 ns/op, Bandwidth: 24.88 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 413513,
            "unit": "ops/sec",
            "extra": "Latency: 2418.3 ns/op, Bandwidth: 100.96 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 384746,
            "unit": "ops/sec",
            "extra": "Latency: 2599.1 ns/op, Bandwidth: 375.73 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 567280,
            "unit": "ops/sec",
            "extra": "Latency: 1762.8 ns/op, Bandwidth: 2.16 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 528759,
            "unit": "ops/sec",
            "extra": "Latency: 1891.2 ns/op, Bandwidth: 32.27 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 530010,
            "unit": "ops/sec",
            "extra": "Latency: 1886.8 ns/op, Bandwidth: 129.40 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 527132,
            "unit": "ops/sec",
            "extra": "Latency: 1897.1 ns/op, Bandwidth: 514.78 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 552934,
            "unit": "ops/sec",
            "extra": "Latency: 1808.5 ns/op, Bandwidth: 2.11 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 563093,
            "unit": "ops/sec",
            "extra": "Latency: 1775.9 ns/op, Bandwidth: 34.37 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 552794,
            "unit": "ops/sec",
            "extra": "Latency: 1809.0 ns/op, Bandwidth: 134.96 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 517448,
            "unit": "ops/sec",
            "extra": "Latency: 1932.6 ns/op, Bandwidth: 505.32 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 279195,
            "unit": "ops/sec",
            "extra": "Latency: 3581.7 ns/op, Bandwidth: 1.07 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 266459,
            "unit": "ops/sec",
            "extra": "Latency: 3752.9 ns/op, Bandwidth: 16.26 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 279609,
            "unit": "ops/sec",
            "extra": "Latency: 3576.4 ns/op, Bandwidth: 68.26 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 203335,
            "unit": "ops/sec",
            "extra": "Latency: 4918.0 ns/op, Bandwidth: 0.78 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 199484,
            "unit": "ops/sec",
            "extra": "Latency: 5012.9 ns/op, Bandwidth: 12.18 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 198844,
            "unit": "ops/sec",
            "extra": "Latency: 5029.1 ns/op, Bandwidth: 48.55 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 142156,
            "unit": "ops/sec",
            "extra": "Latency: 7034.5 ns/op, Bandwidth: 0.54 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 140968,
            "unit": "ops/sec",
            "extra": "Latency: 7093.8 ns/op, Bandwidth: 8.60 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 135616,
            "unit": "ops/sec",
            "extra": "Latency: 7373.7 ns/op, Bandwidth: 33.11 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 140144,
            "unit": "ops/sec",
            "extra": "Latency: 7135.5 ns/op, Bandwidth: 136.86 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "756e3aa4ec705da3d8e3b8aa46d545cff164b990",
          "message": "feat: split RX and TX readiness for epoll",
          "timestamp": "2026-03-21T16:46:23Z",
          "tree_id": "2c403e88812c355d3c47fa6488bdcfccc600e014",
          "url": "https://github.com/ShenChen1/ufifo/commit/756e3aa4ec705da3d8e3b8aa46d545cff164b990"
        },
        "date": 1774112034900,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 567354,
            "unit": "ops/sec",
            "extra": "Latency: 1762.6 ns/op, Bandwidth: 2.16 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 567108,
            "unit": "ops/sec",
            "extra": "Latency: 1763.3 ns/op, Bandwidth: 34.61 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 567376,
            "unit": "ops/sec",
            "extra": "Latency: 1762.5 ns/op, Bandwidth: 138.52 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 560074,
            "unit": "ops/sec",
            "extra": "Latency: 1785.5 ns/op, Bandwidth: 546.95 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 542018,
            "unit": "ops/sec",
            "extra": "Latency: 1845.0 ns/op, Bandwidth: 2117.26 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 557590,
            "unit": "ops/sec",
            "extra": "Latency: 1793.4 ns/op, Bandwidth: 2.13 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 557215,
            "unit": "ops/sec",
            "extra": "Latency: 1794.6 ns/op, Bandwidth: 34.01 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 556217,
            "unit": "ops/sec",
            "extra": "Latency: 1797.9 ns/op, Bandwidth: 135.80 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 553901,
            "unit": "ops/sec",
            "extra": "Latency: 1805.4 ns/op, Bandwidth: 540.92 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 534828,
            "unit": "ops/sec",
            "extra": "Latency: 1869.8 ns/op, Bandwidth: 2089.17 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 1075339,
            "unit": "ops/sec",
            "extra": "Latency: 929.9 ns/op, Bandwidth: 4.10 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 1089508,
            "unit": "ops/sec",
            "extra": "Latency: 917.8 ns/op, Bandwidth: 66.50 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 1083640,
            "unit": "ops/sec",
            "extra": "Latency: 922.8 ns/op, Bandwidth: 264.56 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 1013764,
            "unit": "ops/sec",
            "extra": "Latency: 986.4 ns/op, Bandwidth: 990.00 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 399845,
            "unit": "ops/sec",
            "extra": "Latency: 2501.0 ns/op, Bandwidth: 1.53 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 392166,
            "unit": "ops/sec",
            "extra": "Latency: 2549.9 ns/op, Bandwidth: 23.94 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 395801,
            "unit": "ops/sec",
            "extra": "Latency: 2526.5 ns/op, Bandwidth: 96.63 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 384865,
            "unit": "ops/sec",
            "extra": "Latency: 2598.3 ns/op, Bandwidth: 375.84 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 562643,
            "unit": "ops/sec",
            "extra": "Latency: 1777.3 ns/op, Bandwidth: 2.15 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 551325,
            "unit": "ops/sec",
            "extra": "Latency: 1813.8 ns/op, Bandwidth: 33.65 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 565996,
            "unit": "ops/sec",
            "extra": "Latency: 1766.8 ns/op, Bandwidth: 138.18 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 560944,
            "unit": "ops/sec",
            "extra": "Latency: 1782.7 ns/op, Bandwidth: 547.80 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 548416,
            "unit": "ops/sec",
            "extra": "Latency: 1823.4 ns/op, Bandwidth: 2.09 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 557279,
            "unit": "ops/sec",
            "extra": "Latency: 1794.4 ns/op, Bandwidth: 34.01 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 559360,
            "unit": "ops/sec",
            "extra": "Latency: 1787.8 ns/op, Bandwidth: 136.56 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 556338,
            "unit": "ops/sec",
            "extra": "Latency: 1797.5 ns/op, Bandwidth: 543.30 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 277256,
            "unit": "ops/sec",
            "extra": "Latency: 3606.8 ns/op, Bandwidth: 1.06 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 275829,
            "unit": "ops/sec",
            "extra": "Latency: 3625.4 ns/op, Bandwidth: 16.84 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 273108,
            "unit": "ops/sec",
            "extra": "Latency: 3661.6 ns/op, Bandwidth: 66.68 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 195383,
            "unit": "ops/sec",
            "extra": "Latency: 5118.2 ns/op, Bandwidth: 0.75 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 195145,
            "unit": "ops/sec",
            "extra": "Latency: 5124.4 ns/op, Bandwidth: 11.91 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 189958,
            "unit": "ops/sec",
            "extra": "Latency: 5264.3 ns/op, Bandwidth: 46.38 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 146682,
            "unit": "ops/sec",
            "extra": "Latency: 6817.5 ns/op, Bandwidth: 0.56 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 141481,
            "unit": "ops/sec",
            "extra": "Latency: 7068.1 ns/op, Bandwidth: 8.64 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 145623,
            "unit": "ops/sec",
            "extra": "Latency: 6867.1 ns/op, Bandwidth: 35.55 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 143569,
            "unit": "ops/sec",
            "extra": "Latency: 6965.3 ns/op, Bandwidth: 140.20 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "sc",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "9092dbb7aa619814502b9f43d5f920dbd874ff6e",
          "message": "feat: reduce redundant `sendto` in epoll mode",
          "timestamp": "2026-04-14T02:12:46+08:00",
          "tree_id": "c6f899bda58c1c70f560a7c593127cb64ecdd6b9",
          "url": "https://github.com/ShenChen1/ufifo/commit/9092dbb7aa619814502b9f43d5f920dbd874ff6e"
        },
        "date": 1776104014250,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 33415402,
            "unit": "ops/sec",
            "extra": "Latency: 29.9 ns/op, Bandwidth: 127.47 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 33946381,
            "unit": "ops/sec",
            "extra": "Latency: 29.5 ns/op, Bandwidth: 2071.92 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 29434069,
            "unit": "ops/sec",
            "extra": "Latency: 34.0 ns/op, Bandwidth: 7186.05 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 23555068,
            "unit": "ops/sec",
            "extra": "Latency: 42.5 ns/op, Bandwidth: 23003.00 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 11975299,
            "unit": "ops/sec",
            "extra": "Latency: 83.5 ns/op, Bandwidth: 46778.51 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 24952106,
            "unit": "ops/sec",
            "extra": "Latency: 40.1 ns/op, Bandwidth: 95.18 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 25166377,
            "unit": "ops/sec",
            "extra": "Latency: 39.7 ns/op, Bandwidth: 1536.03 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 22484466,
            "unit": "ops/sec",
            "extra": "Latency: 44.5 ns/op, Bandwidth: 5489.37 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 19021907,
            "unit": "ops/sec",
            "extra": "Latency: 52.6 ns/op, Bandwidth: 18576.08 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 11171496,
            "unit": "ops/sec",
            "extra": "Latency: 89.5 ns/op, Bandwidth: 43638.65 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 10077273,
            "unit": "ops/sec",
            "extra": "Latency: 99.2 ns/op, Bandwidth: 38.44 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 11539132,
            "unit": "ops/sec",
            "extra": "Latency: 86.7 ns/op, Bandwidth: 704.29 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 13105103,
            "unit": "ops/sec",
            "extra": "Latency: 76.3 ns/op, Bandwidth: 3199.49 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 9913762,
            "unit": "ops/sec",
            "extra": "Latency: 100.9 ns/op, Bandwidth: 9681.41 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 5711411,
            "unit": "ops/sec",
            "extra": "Latency: 175.1 ns/op, Bandwidth: 21.79 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 4935376,
            "unit": "ops/sec",
            "extra": "Latency: 202.6 ns/op, Bandwidth: 301.23 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 4324184,
            "unit": "ops/sec",
            "extra": "Latency: 231.3 ns/op, Bandwidth: 1055.71 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 2209747,
            "unit": "ops/sec",
            "extra": "Latency: 452.5 ns/op, Bandwidth: 2157.96 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 33473659,
            "unit": "ops/sec",
            "extra": "Latency: 29.9 ns/op, Bandwidth: 127.69 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 33732938,
            "unit": "ops/sec",
            "extra": "Latency: 29.6 ns/op, Bandwidth: 2058.90 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 22057693,
            "unit": "ops/sec",
            "extra": "Latency: 45.3 ns/op, Bandwidth: 5385.18 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 22752789,
            "unit": "ops/sec",
            "extra": "Latency: 44.0 ns/op, Bandwidth: 22219.52 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 24983302,
            "unit": "ops/sec",
            "extra": "Latency: 40.0 ns/op, Bandwidth: 95.30 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 25342744,
            "unit": "ops/sec",
            "extra": "Latency: 39.5 ns/op, Bandwidth: 1546.80 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 22508519,
            "unit": "ops/sec",
            "extra": "Latency: 44.4 ns/op, Bandwidth: 5495.24 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 19073929,
            "unit": "ops/sec",
            "extra": "Latency: 52.4 ns/op, Bandwidth: 18626.88 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 4175979,
            "unit": "ops/sec",
            "extra": "Latency: 239.5 ns/op, Bandwidth: 15.93 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 3937770,
            "unit": "ops/sec",
            "extra": "Latency: 254.0 ns/op, Bandwidth: 240.34 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 3423129,
            "unit": "ops/sec",
            "extra": "Latency: 292.1 ns/op, Bandwidth: 835.72 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 3829618,
            "unit": "ops/sec",
            "extra": "Latency: 261.1 ns/op, Bandwidth: 14.61 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 3597055,
            "unit": "ops/sec",
            "extra": "Latency: 278.0 ns/op, Bandwidth: 219.55 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 3392889,
            "unit": "ops/sec",
            "extra": "Latency: 294.7 ns/op, Bandwidth: 828.34 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 3557172,
            "unit": "ops/sec",
            "extra": "Latency: 281.1 ns/op, Bandwidth: 13.57 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 3244237,
            "unit": "ops/sec",
            "extra": "Latency: 308.2 ns/op, Bandwidth: 198.01 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 2939395,
            "unit": "ops/sec",
            "extra": "Latency: 340.2 ns/op, Bandwidth: 717.63 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 1748169,
            "unit": "ops/sec",
            "extra": "Latency: 572.0 ns/op, Bandwidth: 1707.20 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "7314c9ce47d425a0ff1ae25b8d5428fcfdc0dfcd",
          "message": "refactor: replace ufifo_drain_fd with ufifo_drain_rx/tx_fd",
          "timestamp": "2026-04-14T14:46:53Z",
          "tree_id": "c18a923e31f87b6b46ab2cc35b2c1c2e3aa41585",
          "url": "https://github.com/ShenChen1/ufifo/commit/7314c9ce47d425a0ff1ae25b8d5428fcfdc0dfcd"
        },
        "date": 1776178064082,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 33670458,
            "unit": "ops/sec",
            "extra": "Latency: 29.7 ns/op, Bandwidth: 128.44 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 33994656,
            "unit": "ops/sec",
            "extra": "Latency: 29.4 ns/op, Bandwidth: 2074.87 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 29207943,
            "unit": "ops/sec",
            "extra": "Latency: 34.2 ns/op, Bandwidth: 7130.85 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 23508304,
            "unit": "ops/sec",
            "extra": "Latency: 42.5 ns/op, Bandwidth: 22957.33 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 12252557,
            "unit": "ops/sec",
            "extra": "Latency: 81.6 ns/op, Bandwidth: 47861.55 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 25165103,
            "unit": "ops/sec",
            "extra": "Latency: 39.7 ns/op, Bandwidth: 96.00 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 24534333,
            "unit": "ops/sec",
            "extra": "Latency: 40.8 ns/op, Bandwidth: 1497.46 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 22727510,
            "unit": "ops/sec",
            "extra": "Latency: 44.0 ns/op, Bandwidth: 5548.71 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 19385233,
            "unit": "ops/sec",
            "extra": "Latency: 51.6 ns/op, Bandwidth: 18930.89 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 11224476,
            "unit": "ops/sec",
            "extra": "Latency: 89.1 ns/op, Bandwidth: 43845.61 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 11091625,
            "unit": "ops/sec",
            "extra": "Latency: 90.2 ns/op, Bandwidth: 42.31 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 12192343,
            "unit": "ops/sec",
            "extra": "Latency: 82.0 ns/op, Bandwidth: 744.16 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 13388287,
            "unit": "ops/sec",
            "extra": "Latency: 74.7 ns/op, Bandwidth: 3268.62 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 9386431,
            "unit": "ops/sec",
            "extra": "Latency: 106.5 ns/op, Bandwidth: 9166.44 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 6345423,
            "unit": "ops/sec",
            "extra": "Latency: 157.6 ns/op, Bandwidth: 24.21 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 5216905,
            "unit": "ops/sec",
            "extra": "Latency: 191.7 ns/op, Bandwidth: 318.41 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 4966728,
            "unit": "ops/sec",
            "extra": "Latency: 201.3 ns/op, Bandwidth: 1212.58 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 2884021,
            "unit": "ops/sec",
            "extra": "Latency: 346.7 ns/op, Bandwidth: 2816.43 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 33240587,
            "unit": "ops/sec",
            "extra": "Latency: 30.1 ns/op, Bandwidth: 126.80 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 33568458,
            "unit": "ops/sec",
            "extra": "Latency: 29.8 ns/op, Bandwidth: 2048.86 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 28924527,
            "unit": "ops/sec",
            "extra": "Latency: 34.6 ns/op, Bandwidth: 7061.65 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 23377606,
            "unit": "ops/sec",
            "extra": "Latency: 42.8 ns/op, Bandwidth: 22829.69 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 25281446,
            "unit": "ops/sec",
            "extra": "Latency: 39.6 ns/op, Bandwidth: 96.44 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 25560738,
            "unit": "ops/sec",
            "extra": "Latency: 39.1 ns/op, Bandwidth: 1560.10 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 22522673,
            "unit": "ops/sec",
            "extra": "Latency: 44.4 ns/op, Bandwidth: 5498.70 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 19151240,
            "unit": "ops/sec",
            "extra": "Latency: 52.2 ns/op, Bandwidth: 18702.38 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 4300848,
            "unit": "ops/sec",
            "extra": "Latency: 232.5 ns/op, Bandwidth: 16.41 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 3854888,
            "unit": "ops/sec",
            "extra": "Latency: 259.4 ns/op, Bandwidth: 235.28 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 3756829,
            "unit": "ops/sec",
            "extra": "Latency: 266.2 ns/op, Bandwidth: 917.19 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 3608121,
            "unit": "ops/sec",
            "extra": "Latency: 277.2 ns/op, Bandwidth: 13.76 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 3584647,
            "unit": "ops/sec",
            "extra": "Latency: 279.0 ns/op, Bandwidth: 218.79 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 3420623,
            "unit": "ops/sec",
            "extra": "Latency: 292.3 ns/op, Bandwidth: 835.11 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 3247440,
            "unit": "ops/sec",
            "extra": "Latency: 307.9 ns/op, Bandwidth: 12.39 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 3338180,
            "unit": "ops/sec",
            "extra": "Latency: 299.6 ns/op, Bandwidth: 203.75 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 2972069,
            "unit": "ops/sec",
            "extra": "Latency: 336.5 ns/op, Bandwidth: 725.60 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 1790185,
            "unit": "ops/sec",
            "extra": "Latency: 558.6 ns/op, Bandwidth: 1748.23 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "7314c9ce47d425a0ff1ae25b8d5428fcfdc0dfcd",
          "message": "refactor: replace ufifo_drain_fd with ufifo_drain_rx/tx_fd",
          "timestamp": "2026-04-14T14:46:53Z",
          "tree_id": "c18a923e31f87b6b46ab2cc35b2c1c2e3aa41585",
          "url": "https://github.com/ShenChen1/ufifo/commit/7314c9ce47d425a0ff1ae25b8d5428fcfdc0dfcd"
        },
        "date": 1776271052072,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 33336639,
            "unit": "ops/sec",
            "extra": "Latency: 30.0 ns/op, Bandwidth: 127.17 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 34180485,
            "unit": "ops/sec",
            "extra": "Latency: 29.3 ns/op, Bandwidth: 2086.21 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 29292721,
            "unit": "ops/sec",
            "extra": "Latency: 34.1 ns/op, Bandwidth: 7151.54 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 23594056,
            "unit": "ops/sec",
            "extra": "Latency: 42.4 ns/op, Bandwidth: 23041.07 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 12155693,
            "unit": "ops/sec",
            "extra": "Latency: 82.3 ns/op, Bandwidth: 47483.18 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 25156635,
            "unit": "ops/sec",
            "extra": "Latency: 39.8 ns/op, Bandwidth: 95.96 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 25251390,
            "unit": "ops/sec",
            "extra": "Latency: 39.6 ns/op, Bandwidth: 1541.22 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 22668093,
            "unit": "ops/sec",
            "extra": "Latency: 44.1 ns/op, Bandwidth: 5534.20 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 19187947,
            "unit": "ops/sec",
            "extra": "Latency: 52.1 ns/op, Bandwidth: 18738.23 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 11189176,
            "unit": "ops/sec",
            "extra": "Latency: 89.4 ns/op, Bandwidth: 43707.72 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 11168089,
            "unit": "ops/sec",
            "extra": "Latency: 89.5 ns/op, Bandwidth: 42.60 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 13709214,
            "unit": "ops/sec",
            "extra": "Latency: 72.9 ns/op, Bandwidth: 836.74 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 16261624,
            "unit": "ops/sec",
            "extra": "Latency: 61.5 ns/op, Bandwidth: 3970.12 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 10559694,
            "unit": "ops/sec",
            "extra": "Latency: 94.7 ns/op, Bandwidth: 10312.20 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 6728694,
            "unit": "ops/sec",
            "extra": "Latency: 148.6 ns/op, Bandwidth: 25.67 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 5521839,
            "unit": "ops/sec",
            "extra": "Latency: 181.1 ns/op, Bandwidth: 337.03 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 5155095,
            "unit": "ops/sec",
            "extra": "Latency: 194.0 ns/op, Bandwidth: 1258.57 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 2859457,
            "unit": "ops/sec",
            "extra": "Latency: 349.7 ns/op, Bandwidth: 2792.44 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 33486014,
            "unit": "ops/sec",
            "extra": "Latency: 29.9 ns/op, Bandwidth: 127.74 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 33637612,
            "unit": "ops/sec",
            "extra": "Latency: 29.7 ns/op, Bandwidth: 2053.08 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 28900986,
            "unit": "ops/sec",
            "extra": "Latency: 34.6 ns/op, Bandwidth: 7055.90 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 23420464,
            "unit": "ops/sec",
            "extra": "Latency: 42.7 ns/op, Bandwidth: 22871.55 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 25316981,
            "unit": "ops/sec",
            "extra": "Latency: 39.5 ns/op, Bandwidth: 96.58 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 24001952,
            "unit": "ops/sec",
            "extra": "Latency: 41.7 ns/op, Bandwidth: 1464.96 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 22556522,
            "unit": "ops/sec",
            "extra": "Latency: 44.3 ns/op, Bandwidth: 5506.96 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 19180113,
            "unit": "ops/sec",
            "extra": "Latency: 52.1 ns/op, Bandwidth: 18730.58 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 4126238,
            "unit": "ops/sec",
            "extra": "Latency: 242.4 ns/op, Bandwidth: 15.74 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 4080945,
            "unit": "ops/sec",
            "extra": "Latency: 245.0 ns/op, Bandwidth: 249.08 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 3495897,
            "unit": "ops/sec",
            "extra": "Latency: 286.0 ns/op, Bandwidth: 853.49 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 3629077,
            "unit": "ops/sec",
            "extra": "Latency: 275.6 ns/op, Bandwidth: 13.84 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 3762832,
            "unit": "ops/sec",
            "extra": "Latency: 265.8 ns/op, Bandwidth: 229.67 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 3311325,
            "unit": "ops/sec",
            "extra": "Latency: 302.0 ns/op, Bandwidth: 808.43 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 3835026,
            "unit": "ops/sec",
            "extra": "Latency: 260.8 ns/op, Bandwidth: 14.63 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 3161955,
            "unit": "ops/sec",
            "extra": "Latency: 316.3 ns/op, Bandwidth: 192.99 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 2821918,
            "unit": "ops/sec",
            "extra": "Latency: 354.4 ns/op, Bandwidth: 688.94 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 1866128,
            "unit": "ops/sec",
            "extra": "Latency: 535.9 ns/op, Bandwidth: 1822.39 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "161369871+google-labs-jules[bot]@users.noreply.github.com",
            "name": "google-labs-jules[bot]",
            "username": "google-labs-jules[bot]"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "sc",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "876b1ec780fd088e37a6a37391850522c95e5bb1",
          "message": "feat: lazy cleanup for dead attached processes",
          "timestamp": "2026-04-16T01:37:21+08:00",
          "tree_id": "d4ff6dfde090dc515a3c1ad627880657f93ddf1f",
          "url": "https://github.com/ShenChen1/ufifo/commit/876b1ec780fd088e37a6a37391850522c95e5bb1"
        },
        "date": 1776274664188,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 32796662,
            "unit": "ops/sec",
            "extra": "Latency: 30.5 ns/op, Bandwidth: 125.11 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 34114370,
            "unit": "ops/sec",
            "extra": "Latency: 29.3 ns/op, Bandwidth: 2082.18 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 28961372,
            "unit": "ops/sec",
            "extra": "Latency: 34.5 ns/op, Bandwidth: 7070.65 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 23377828,
            "unit": "ops/sec",
            "extra": "Latency: 42.8 ns/op, Bandwidth: 22829.91 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 9952966,
            "unit": "ops/sec",
            "extra": "Latency: 100.5 ns/op, Bandwidth: 38878.78 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 24909987,
            "unit": "ops/sec",
            "extra": "Latency: 40.1 ns/op, Bandwidth: 95.02 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 23124407,
            "unit": "ops/sec",
            "extra": "Latency: 43.2 ns/op, Bandwidth: 1411.40 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 21549771,
            "unit": "ops/sec",
            "extra": "Latency: 46.4 ns/op, Bandwidth: 5261.17 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 11935899,
            "unit": "ops/sec",
            "extra": "Latency: 83.8 ns/op, Bandwidth: 11656.15 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 9386515,
            "unit": "ops/sec",
            "extra": "Latency: 106.5 ns/op, Bandwidth: 36666.07 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 10416149,
            "unit": "ops/sec",
            "extra": "Latency: 96.0 ns/op, Bandwidth: 39.73 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 14412659,
            "unit": "ops/sec",
            "extra": "Latency: 69.4 ns/op, Bandwidth: 879.68 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 15109266,
            "unit": "ops/sec",
            "extra": "Latency: 66.2 ns/op, Bandwidth: 3688.79 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 10191463,
            "unit": "ops/sec",
            "extra": "Latency: 98.1 ns/op, Bandwidth: 9952.60 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 6062829,
            "unit": "ops/sec",
            "extra": "Latency: 164.9 ns/op, Bandwidth: 23.13 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 5114422,
            "unit": "ops/sec",
            "extra": "Latency: 195.5 ns/op, Bandwidth: 312.16 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 5028500,
            "unit": "ops/sec",
            "extra": "Latency: 198.9 ns/op, Bandwidth: 1227.66 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 2649687,
            "unit": "ops/sec",
            "extra": "Latency: 377.4 ns/op, Bandwidth: 2587.58 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 33209889,
            "unit": "ops/sec",
            "extra": "Latency: 30.1 ns/op, Bandwidth: 126.69 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 33456386,
            "unit": "ops/sec",
            "extra": "Latency: 29.9 ns/op, Bandwidth: 2042.02 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 28710801,
            "unit": "ops/sec",
            "extra": "Latency: 34.8 ns/op, Bandwidth: 7009.47 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 23374485,
            "unit": "ops/sec",
            "extra": "Latency: 42.8 ns/op, Bandwidth: 22826.65 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 24590872,
            "unit": "ops/sec",
            "extra": "Latency: 40.7 ns/op, Bandwidth: 93.81 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 25234223,
            "unit": "ops/sec",
            "extra": "Latency: 39.6 ns/op, Bandwidth: 1540.17 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 22465802,
            "unit": "ops/sec",
            "extra": "Latency: 44.5 ns/op, Bandwidth: 5484.81 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 19158899,
            "unit": "ops/sec",
            "extra": "Latency: 52.2 ns/op, Bandwidth: 18709.86 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 4042015,
            "unit": "ops/sec",
            "extra": "Latency: 247.4 ns/op, Bandwidth: 15.42 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 3645281,
            "unit": "ops/sec",
            "extra": "Latency: 274.3 ns/op, Bandwidth: 222.49 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 3517737,
            "unit": "ops/sec",
            "extra": "Latency: 284.3 ns/op, Bandwidth: 858.82 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 3695564,
            "unit": "ops/sec",
            "extra": "Latency: 270.6 ns/op, Bandwidth: 14.10 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 3578488,
            "unit": "ops/sec",
            "extra": "Latency: 279.4 ns/op, Bandwidth: 218.41 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 3120857,
            "unit": "ops/sec",
            "extra": "Latency: 320.4 ns/op, Bandwidth: 761.93 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 3784465,
            "unit": "ops/sec",
            "extra": "Latency: 264.2 ns/op, Bandwidth: 14.44 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 3354208,
            "unit": "ops/sec",
            "extra": "Latency: 298.1 ns/op, Bandwidth: 204.72 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 2982541,
            "unit": "ops/sec",
            "extra": "Latency: 335.3 ns/op, Bandwidth: 728.16 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 1785383,
            "unit": "ops/sec",
            "extra": "Latency: 560.1 ns/op, Bandwidth: 1743.54 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "161369871+google-labs-jules[bot]@users.noreply.github.com",
            "name": "google-labs-jules[bot]",
            "username": "google-labs-jules[bot]"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "sc",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "876b1ec780fd088e37a6a37391850522c95e5bb1",
          "message": "feat: lazy cleanup for dead attached processes",
          "timestamp": "2026-04-16T01:37:21+08:00",
          "tree_id": "d4ff6dfde090dc515a3c1ad627880657f93ddf1f",
          "url": "https://github.com/ShenChen1/ufifo/commit/876b1ec780fd088e37a6a37391850522c95e5bb1"
        },
        "date": 1776274804937,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 41658755,
            "unit": "ops/sec",
            "extra": "Latency: 24.0 ns/op, Bandwidth: 158.92 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 42948943,
            "unit": "ops/sec",
            "extra": "Latency: 23.3 ns/op, Bandwidth: 2621.40 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 29154606,
            "unit": "ops/sec",
            "extra": "Latency: 34.3 ns/op, Bandwidth: 7117.82 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 23720330,
            "unit": "ops/sec",
            "extra": "Latency: 42.2 ns/op, Bandwidth: 23164.38 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 12788853,
            "unit": "ops/sec",
            "extra": "Latency: 78.2 ns/op, Bandwidth: 49956.46 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 31279164,
            "unit": "ops/sec",
            "extra": "Latency: 32.0 ns/op, Bandwidth: 119.32 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 31806551,
            "unit": "ops/sec",
            "extra": "Latency: 31.4 ns/op, Bandwidth: 1941.32 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 22333124,
            "unit": "ops/sec",
            "extra": "Latency: 44.8 ns/op, Bandwidth: 5452.42 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 19994529,
            "unit": "ops/sec",
            "extra": "Latency: 50.0 ns/op, Bandwidth: 19525.91 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 11724749,
            "unit": "ops/sec",
            "extra": "Latency: 85.3 ns/op, Bandwidth: 45799.80 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 9315110,
            "unit": "ops/sec",
            "extra": "Latency: 107.4 ns/op, Bandwidth: 35.53 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 9449477,
            "unit": "ops/sec",
            "extra": "Latency: 105.8 ns/op, Bandwidth: 576.75 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 9419944,
            "unit": "ops/sec",
            "extra": "Latency: 106.2 ns/op, Bandwidth: 2299.79 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 6624594,
            "unit": "ops/sec",
            "extra": "Latency: 151.0 ns/op, Bandwidth: 6469.33 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 8029390,
            "unit": "ops/sec",
            "extra": "Latency: 124.5 ns/op, Bandwidth: 30.63 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 4628111,
            "unit": "ops/sec",
            "extra": "Latency: 216.1 ns/op, Bandwidth: 282.48 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 5060377,
            "unit": "ops/sec",
            "extra": "Latency: 197.6 ns/op, Bandwidth: 1235.44 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 2323347,
            "unit": "ops/sec",
            "extra": "Latency: 430.4 ns/op, Bandwidth: 2268.89 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 42568933,
            "unit": "ops/sec",
            "extra": "Latency: 23.5 ns/op, Bandwidth: 162.39 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 42976581,
            "unit": "ops/sec",
            "extra": "Latency: 23.3 ns/op, Bandwidth: 2623.08 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 28708795,
            "unit": "ops/sec",
            "extra": "Latency: 34.8 ns/op, Bandwidth: 7008.98 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 23900402,
            "unit": "ops/sec",
            "extra": "Latency: 41.8 ns/op, Bandwidth: 23340.24 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 31312515,
            "unit": "ops/sec",
            "extra": "Latency: 31.9 ns/op, Bandwidth: 119.45 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 31496455,
            "unit": "ops/sec",
            "extra": "Latency: 31.7 ns/op, Bandwidth: 1922.39 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 22241250,
            "unit": "ops/sec",
            "extra": "Latency: 45.0 ns/op, Bandwidth: 5429.99 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 19618658,
            "unit": "ops/sec",
            "extra": "Latency: 51.0 ns/op, Bandwidth: 19158.85 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 4622767,
            "unit": "ops/sec",
            "extra": "Latency: 216.3 ns/op, Bandwidth: 17.63 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 3939882,
            "unit": "ops/sec",
            "extra": "Latency: 253.8 ns/op, Bandwidth: 240.47 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 3483767,
            "unit": "ops/sec",
            "extra": "Latency: 287.0 ns/op, Bandwidth: 850.53 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 3781497,
            "unit": "ops/sec",
            "extra": "Latency: 264.4 ns/op, Bandwidth: 14.43 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 3432451,
            "unit": "ops/sec",
            "extra": "Latency: 291.3 ns/op, Bandwidth: 209.50 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 3045890,
            "unit": "ops/sec",
            "extra": "Latency: 328.3 ns/op, Bandwidth: 743.63 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 4167766,
            "unit": "ops/sec",
            "extra": "Latency: 239.9 ns/op, Bandwidth: 15.90 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 3116681,
            "unit": "ops/sec",
            "extra": "Latency: 320.9 ns/op, Bandwidth: 190.23 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 2955803,
            "unit": "ops/sec",
            "extra": "Latency: 338.3 ns/op, Bandwidth: 721.63 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 1564304,
            "unit": "ops/sec",
            "extra": "Latency: 639.3 ns/op, Bandwidth: 1527.64 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "d45c29171463898b1dfd37c2da6797b966974bcf",
          "message": "feat: implement CPU thread affinity pinning for benchmark threads",
          "timestamp": "2026-04-15T17:45:12Z",
          "tree_id": "3def476c8552572462232f0ef463d5e2969f71f3",
          "url": "https://github.com/ShenChen1/ufifo/commit/d45c29171463898b1dfd37c2da6797b966974bcf"
        },
        "date": 1776275168219,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 23484922,
            "unit": "ops/sec",
            "extra": "Latency: 42.6 ns/op, Bandwidth: 89.59 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 23155148,
            "unit": "ops/sec",
            "extra": "Latency: 43.2 ns/op, Bandwidth: 1413.28 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 22230150,
            "unit": "ops/sec",
            "extra": "Latency: 45.0 ns/op, Bandwidth: 5427.28 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 20001251,
            "unit": "ops/sec",
            "extra": "Latency: 50.0 ns/op, Bandwidth: 19532.47 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 12493396,
            "unit": "ops/sec",
            "extra": "Latency: 80.0 ns/op, Bandwidth: 48802.33 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 16383518,
            "unit": "ops/sec",
            "extra": "Latency: 61.0 ns/op, Bandwidth: 62.50 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 16538729,
            "unit": "ops/sec",
            "extra": "Latency: 60.5 ns/op, Bandwidth: 1009.44 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 16030017,
            "unit": "ops/sec",
            "extra": "Latency: 62.4 ns/op, Bandwidth: 3913.58 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 15005432,
            "unit": "ops/sec",
            "extra": "Latency: 66.6 ns/op, Bandwidth: 14653.74 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 10998560,
            "unit": "ops/sec",
            "extra": "Latency: 90.9 ns/op, Bandwidth: 42963.13 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 26132894,
            "unit": "ops/sec",
            "extra": "Latency: 38.3 ns/op, Bandwidth: 99.69 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 22545254,
            "unit": "ops/sec",
            "extra": "Latency: 44.4 ns/op, Bandwidth: 1376.05 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 20685817,
            "unit": "ops/sec",
            "extra": "Latency: 48.3 ns/op, Bandwidth: 5050.25 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 22470565,
            "unit": "ops/sec",
            "extra": "Latency: 44.5 ns/op, Bandwidth: 21943.91 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 2459680,
            "unit": "ops/sec",
            "extra": "Latency: 406.6 ns/op, Bandwidth: 9.38 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 2490961,
            "unit": "ops/sec",
            "extra": "Latency: 401.5 ns/op, Bandwidth: 152.04 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 2340202,
            "unit": "ops/sec",
            "extra": "Latency: 427.3 ns/op, Bandwidth: 571.34 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 2233954,
            "unit": "ops/sec",
            "extra": "Latency: 447.6 ns/op, Bandwidth: 2181.60 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 23409748,
            "unit": "ops/sec",
            "extra": "Latency: 42.7 ns/op, Bandwidth: 89.30 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 23206276,
            "unit": "ops/sec",
            "extra": "Latency: 43.1 ns/op, Bandwidth: 1416.40 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 22362476,
            "unit": "ops/sec",
            "extra": "Latency: 44.7 ns/op, Bandwidth: 5459.59 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 19579471,
            "unit": "ops/sec",
            "extra": "Latency: 51.1 ns/op, Bandwidth: 19120.58 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 16613886,
            "unit": "ops/sec",
            "extra": "Latency: 60.2 ns/op, Bandwidth: 63.38 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 16590137,
            "unit": "ops/sec",
            "extra": "Latency: 60.3 ns/op, Bandwidth: 1012.58 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 16032595,
            "unit": "ops/sec",
            "extra": "Latency: 62.4 ns/op, Bandwidth: 3914.21 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 14974074,
            "unit": "ops/sec",
            "extra": "Latency: 66.8 ns/op, Bandwidth: 14623.12 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 2346269,
            "unit": "ops/sec",
            "extra": "Latency: 426.2 ns/op, Bandwidth: 8.95 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 2212981,
            "unit": "ops/sec",
            "extra": "Latency: 451.9 ns/op, Bandwidth: 135.07 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 2069903,
            "unit": "ops/sec",
            "extra": "Latency: 483.1 ns/op, Bandwidth: 505.35 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 2432931,
            "unit": "ops/sec",
            "extra": "Latency: 411.0 ns/op, Bandwidth: 9.28 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 2277780,
            "unit": "ops/sec",
            "extra": "Latency: 439.0 ns/op, Bandwidth: 139.02 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 2189280,
            "unit": "ops/sec",
            "extra": "Latency: 456.8 ns/op, Bandwidth: 534.49 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 11305334,
            "unit": "ops/sec",
            "extra": "Latency: 88.5 ns/op, Bandwidth: 43.13 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 11057189,
            "unit": "ops/sec",
            "extra": "Latency: 90.4 ns/op, Bandwidth: 674.88 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 10598540,
            "unit": "ops/sec",
            "extra": "Latency: 94.4 ns/op, Bandwidth: 2587.53 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 10381159,
            "unit": "ops/sec",
            "extra": "Latency: 96.3 ns/op, Bandwidth: 10137.85 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "4f0810fc4027ff922f2c0d19ae6954cbd4673569",
          "message": "feat: implement CPU thread affinity pinning for benchmark threads",
          "timestamp": "2026-04-15T17:54:20Z",
          "tree_id": "3f3afb0d93ef700f9e832c4b9c8e52c9dfb4abfd",
          "url": "https://github.com/ShenChen1/ufifo/commit/4f0810fc4027ff922f2c0d19ae6954cbd4673569"
        },
        "date": 1776275748445,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 54803559,
            "unit": "ops/sec",
            "extra": "Latency: 18.2 ns/op, Bandwidth: 209.06 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 55339951,
            "unit": "ops/sec",
            "extra": "Latency: 18.1 ns/op, Bandwidth: 3377.68 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 38057740,
            "unit": "ops/sec",
            "extra": "Latency: 26.3 ns/op, Bandwidth: 9291.44 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 30823795,
            "unit": "ops/sec",
            "extra": "Latency: 32.4 ns/op, Bandwidth: 30101.36 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 16542540,
            "unit": "ops/sec",
            "extra": "Latency: 60.5 ns/op, Bandwidth: 64619.30 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 40255479,
            "unit": "ops/sec",
            "extra": "Latency: 24.8 ns/op, Bandwidth: 153.56 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 40854213,
            "unit": "ops/sec",
            "extra": "Latency: 24.5 ns/op, Bandwidth: 2493.54 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 29146987,
            "unit": "ops/sec",
            "extra": "Latency: 34.3 ns/op, Bandwidth: 7115.96 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 25792958,
            "unit": "ops/sec",
            "extra": "Latency: 38.8 ns/op, Bandwidth: 25188.44 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 15187681,
            "unit": "ops/sec",
            "extra": "Latency: 65.8 ns/op, Bandwidth: 59326.88 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 11974934,
            "unit": "ops/sec",
            "extra": "Latency: 83.5 ns/op, Bandwidth: 45.68 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 12133060,
            "unit": "ops/sec",
            "extra": "Latency: 82.4 ns/op, Bandwidth: 740.54 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 12976226,
            "unit": "ops/sec",
            "extra": "Latency: 77.1 ns/op, Bandwidth: 3168.02 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 8795555,
            "unit": "ops/sec",
            "extra": "Latency: 113.7 ns/op, Bandwidth: 8589.41 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 10527821,
            "unit": "ops/sec",
            "extra": "Latency: 95.0 ns/op, Bandwidth: 40.16 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 6281327,
            "unit": "ops/sec",
            "extra": "Latency: 159.2 ns/op, Bandwidth: 383.38 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 6378325,
            "unit": "ops/sec",
            "extra": "Latency: 156.8 ns/op, Bandwidth: 1557.21 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 2959756,
            "unit": "ops/sec",
            "extra": "Latency: 337.9 ns/op, Bandwidth: 2890.39 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 54872618,
            "unit": "ops/sec",
            "extra": "Latency: 18.2 ns/op, Bandwidth: 209.32 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 56296200,
            "unit": "ops/sec",
            "extra": "Latency: 17.8 ns/op, Bandwidth: 3436.05 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 37129074,
            "unit": "ops/sec",
            "extra": "Latency: 26.9 ns/op, Bandwidth: 9064.72 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 30866296,
            "unit": "ops/sec",
            "extra": "Latency: 32.4 ns/op, Bandwidth: 30142.87 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 39467633,
            "unit": "ops/sec",
            "extra": "Latency: 25.3 ns/op, Bandwidth: 150.56 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 40277964,
            "unit": "ops/sec",
            "extra": "Latency: 24.8 ns/op, Bandwidth: 2458.37 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 29091739,
            "unit": "ops/sec",
            "extra": "Latency: 34.4 ns/op, Bandwidth: 7102.48 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 25328782,
            "unit": "ops/sec",
            "extra": "Latency: 39.5 ns/op, Bandwidth: 24735.14 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 5653492,
            "unit": "ops/sec",
            "extra": "Latency: 176.9 ns/op, Bandwidth: 21.57 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 4742640,
            "unit": "ops/sec",
            "extra": "Latency: 210.9 ns/op, Bandwidth: 289.47 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 4518713,
            "unit": "ops/sec",
            "extra": "Latency: 221.3 ns/op, Bandwidth: 1103.20 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 4719103,
            "unit": "ops/sec",
            "extra": "Latency: 211.9 ns/op, Bandwidth: 18.00 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 4439462,
            "unit": "ops/sec",
            "extra": "Latency: 225.3 ns/op, Bandwidth: 270.96 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 4036651,
            "unit": "ops/sec",
            "extra": "Latency: 247.7 ns/op, Bandwidth: 985.51 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 11216311,
            "unit": "ops/sec",
            "extra": "Latency: 89.2 ns/op, Bandwidth: 42.79 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 10190232,
            "unit": "ops/sec",
            "extra": "Latency: 98.1 ns/op, Bandwidth: 621.96 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 9881564,
            "unit": "ops/sec",
            "extra": "Latency: 101.2 ns/op, Bandwidth: 2412.49 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 6136072,
            "unit": "ops/sec",
            "extra": "Latency: 163.0 ns/op, Bandwidth: 5992.26 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "4f0810fc4027ff922f2c0d19ae6954cbd4673569",
          "message": "feat: implement CPU thread affinity pinning for benchmark threads",
          "timestamp": "2026-04-15T17:54:20Z",
          "tree_id": "3f3afb0d93ef700f9e832c4b9c8e52c9dfb4abfd",
          "url": "https://github.com/ShenChen1/ufifo/commit/4f0810fc4027ff922f2c0d19ae6954cbd4673569"
        },
        "date": 1776276347109,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 33038827,
            "unit": "ops/sec",
            "extra": "Latency: 30.3 ns/op, Bandwidth: 126.03 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 33044351,
            "unit": "ops/sec",
            "extra": "Latency: 30.3 ns/op, Bandwidth: 2016.87 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 28519220,
            "unit": "ops/sec",
            "extra": "Latency: 35.1 ns/op, Bandwidth: 6962.70 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 20893845,
            "unit": "ops/sec",
            "extra": "Latency: 47.9 ns/op, Bandwidth: 20404.15 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 11422787,
            "unit": "ops/sec",
            "extra": "Latency: 87.5 ns/op, Bandwidth: 44620.26 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 24726744,
            "unit": "ops/sec",
            "extra": "Latency: 40.4 ns/op, Bandwidth: 94.33 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 25264244,
            "unit": "ops/sec",
            "extra": "Latency: 39.6 ns/op, Bandwidth: 1542.01 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 22238994,
            "unit": "ops/sec",
            "extra": "Latency: 45.0 ns/op, Bandwidth: 5429.44 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 19015333,
            "unit": "ops/sec",
            "extra": "Latency: 52.6 ns/op, Bandwidth: 18569.66 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 11056512,
            "unit": "ops/sec",
            "extra": "Latency: 90.4 ns/op, Bandwidth: 43189.50 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 10411460,
            "unit": "ops/sec",
            "extra": "Latency: 96.0 ns/op, Bandwidth: 39.72 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 12960391,
            "unit": "ops/sec",
            "extra": "Latency: 77.2 ns/op, Bandwidth: 791.04 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 14552861,
            "unit": "ops/sec",
            "extra": "Latency: 68.7 ns/op, Bandwidth: 3552.94 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 10521747,
            "unit": "ops/sec",
            "extra": "Latency: 95.0 ns/op, Bandwidth: 10275.14 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 6585816,
            "unit": "ops/sec",
            "extra": "Latency: 151.8 ns/op, Bandwidth: 25.12 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 5074173,
            "unit": "ops/sec",
            "extra": "Latency: 197.1 ns/op, Bandwidth: 309.70 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 4573329,
            "unit": "ops/sec",
            "extra": "Latency: 218.7 ns/op, Bandwidth: 1116.54 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 2745082,
            "unit": "ops/sec",
            "extra": "Latency: 364.3 ns/op, Bandwidth: 2680.74 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 28970600,
            "unit": "ops/sec",
            "extra": "Latency: 34.5 ns/op, Bandwidth: 110.51 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 29184470,
            "unit": "ops/sec",
            "extra": "Latency: 34.3 ns/op, Bandwidth: 1781.28 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 25254995,
            "unit": "ops/sec",
            "extra": "Latency: 39.6 ns/op, Bandwidth: 6165.77 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 21022533,
            "unit": "ops/sec",
            "extra": "Latency: 47.6 ns/op, Bandwidth: 20529.82 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 24934155,
            "unit": "ops/sec",
            "extra": "Latency: 40.1 ns/op, Bandwidth: 95.12 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 25151566,
            "unit": "ops/sec",
            "extra": "Latency: 39.8 ns/op, Bandwidth: 1535.13 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 22314663,
            "unit": "ops/sec",
            "extra": "Latency: 44.8 ns/op, Bandwidth: 5447.92 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 18784476,
            "unit": "ops/sec",
            "extra": "Latency: 53.2 ns/op, Bandwidth: 18344.21 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 4092361,
            "unit": "ops/sec",
            "extra": "Latency: 244.4 ns/op, Bandwidth: 15.61 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 4166266,
            "unit": "ops/sec",
            "extra": "Latency: 240.0 ns/op, Bandwidth: 254.29 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 3614168,
            "unit": "ops/sec",
            "extra": "Latency: 276.7 ns/op, Bandwidth: 882.37 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 3466005,
            "unit": "ops/sec",
            "extra": "Latency: 288.5 ns/op, Bandwidth: 13.22 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 3473769,
            "unit": "ops/sec",
            "extra": "Latency: 287.9 ns/op, Bandwidth: 212.02 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 3331322,
            "unit": "ops/sec",
            "extra": "Latency: 300.2 ns/op, Bandwidth: 813.31 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 10109680,
            "unit": "ops/sec",
            "extra": "Latency: 98.9 ns/op, Bandwidth: 38.57 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 9706751,
            "unit": "ops/sec",
            "extra": "Latency: 103.0 ns/op, Bandwidth: 592.45 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 9588536,
            "unit": "ops/sec",
            "extra": "Latency: 104.3 ns/op, Bandwidth: 2340.95 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 6717852,
            "unit": "ops/sec",
            "extra": "Latency: 148.9 ns/op, Bandwidth: 6560.40 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "19bf21874e7c0f9295e30ae6ed9a57a71620c29e",
          "message": "fix: prevent self-reaping and fix raw shm test\n\n- src/ufifo.c: Skip current process's user_id in `__ufifo_try_reap_dead_readers` to avoid self-reaping caused by F_OFD_GETLK behavior on the same open file description.\n\n- test/ufifo_test.cpp: Explicitly set `init_done` to 1 in `VersionMismatchViaRawShm` to bypass the crash check and properly trigger the intended version mismatch assertion.",
          "timestamp": "2026-04-20T01:39:17Z",
          "tree_id": "9a61fd0b79d571f60685cad69153705ad5f8b8ac",
          "url": "https://github.com/ShenChen1/ufifo/commit/19bf21874e7c0f9295e30ae6ed9a57a71620c29e"
        },
        "date": 1776649264843,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 54183030,
            "unit": "ops/sec",
            "extra": "Latency: 18.5 ns/op, Bandwidth: 206.69 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 56155423,
            "unit": "ops/sec",
            "extra": "Latency: 17.8 ns/op, Bandwidth: 3427.46 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 38367354,
            "unit": "ops/sec",
            "extra": "Latency: 26.1 ns/op, Bandwidth: 9367.03 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 30835150,
            "unit": "ops/sec",
            "extra": "Latency: 32.4 ns/op, Bandwidth: 30112.45 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 16624114,
            "unit": "ops/sec",
            "extra": "Latency: 60.2 ns/op, Bandwidth: 64937.95 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 40057309,
            "unit": "ops/sec",
            "extra": "Latency: 25.0 ns/op, Bandwidth: 152.81 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 40084292,
            "unit": "ops/sec",
            "extra": "Latency: 24.9 ns/op, Bandwidth: 2446.55 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 28900218,
            "unit": "ops/sec",
            "extra": "Latency: 34.6 ns/op, Bandwidth: 7055.72 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 25745223,
            "unit": "ops/sec",
            "extra": "Latency: 38.8 ns/op, Bandwidth: 25141.82 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 14862654,
            "unit": "ops/sec",
            "extra": "Latency: 67.3 ns/op, Bandwidth: 58057.24 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 11803773,
            "unit": "ops/sec",
            "extra": "Latency: 84.7 ns/op, Bandwidth: 45.03 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 12019181,
            "unit": "ops/sec",
            "extra": "Latency: 83.2 ns/op, Bandwidth: 733.59 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 11626330,
            "unit": "ops/sec",
            "extra": "Latency: 86.0 ns/op, Bandwidth: 2838.46 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 8494585,
            "unit": "ops/sec",
            "extra": "Latency: 117.7 ns/op, Bandwidth: 8295.49 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 8990755,
            "unit": "ops/sec",
            "extra": "Latency: 111.2 ns/op, Bandwidth: 34.30 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 5599003,
            "unit": "ops/sec",
            "extra": "Latency: 178.6 ns/op, Bandwidth: 341.74 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 5719678,
            "unit": "ops/sec",
            "extra": "Latency: 174.8 ns/op, Bandwidth: 1396.41 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 2972139,
            "unit": "ops/sec",
            "extra": "Latency: 336.5 ns/op, Bandwidth: 2902.48 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 55330737,
            "unit": "ops/sec",
            "extra": "Latency: 18.1 ns/op, Bandwidth: 211.07 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 56418497,
            "unit": "ops/sec",
            "extra": "Latency: 17.7 ns/op, Bandwidth: 3443.51 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 37496319,
            "unit": "ops/sec",
            "extra": "Latency: 26.7 ns/op, Bandwidth: 9154.37 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 30934593,
            "unit": "ops/sec",
            "extra": "Latency: 32.3 ns/op, Bandwidth: 30209.56 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 39997609,
            "unit": "ops/sec",
            "extra": "Latency: 25.0 ns/op, Bandwidth: 152.58 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 40380790,
            "unit": "ops/sec",
            "extra": "Latency: 24.8 ns/op, Bandwidth: 2464.65 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 29070588,
            "unit": "ops/sec",
            "extra": "Latency: 34.4 ns/op, Bandwidth: 7097.31 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 25204082,
            "unit": "ops/sec",
            "extra": "Latency: 39.7 ns/op, Bandwidth: 24613.36 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 6374462,
            "unit": "ops/sec",
            "extra": "Latency: 156.9 ns/op, Bandwidth: 24.32 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 4575849,
            "unit": "ops/sec",
            "extra": "Latency: 218.5 ns/op, Bandwidth: 279.29 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 4511583,
            "unit": "ops/sec",
            "extra": "Latency: 221.7 ns/op, Bandwidth: 1101.46 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 4791222,
            "unit": "ops/sec",
            "extra": "Latency: 208.7 ns/op, Bandwidth: 18.28 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 4378338,
            "unit": "ops/sec",
            "extra": "Latency: 228.4 ns/op, Bandwidth: 267.23 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 4064326,
            "unit": "ops/sec",
            "extra": "Latency: 246.0 ns/op, Bandwidth: 992.27 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 10521862,
            "unit": "ops/sec",
            "extra": "Latency: 95.0 ns/op, Bandwidth: 40.14 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 9751753,
            "unit": "ops/sec",
            "extra": "Latency: 102.5 ns/op, Bandwidth: 595.20 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 9302723,
            "unit": "ops/sec",
            "extra": "Latency: 107.5 ns/op, Bandwidth: 2271.17 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 6060087,
            "unit": "ops/sec",
            "extra": "Latency: 165.0 ns/op, Bandwidth: 5918.05 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "19bf21874e7c0f9295e30ae6ed9a57a71620c29e",
          "message": "fix: prevent self-reaping and fix raw shm test\n\n- src/ufifo.c: Skip current process's user_id in `__ufifo_try_reap_dead_readers` to avoid self-reaping caused by F_OFD_GETLK behavior on the same open file description.\n\n- test/ufifo_test.cpp: Explicitly set `init_done` to 1 in `VersionMismatchViaRawShm` to bypass the crash check and properly trigger the intended version mismatch assertion.",
          "timestamp": "2026-04-20T01:39:17Z",
          "tree_id": "9a61fd0b79d571f60685cad69153705ad5f8b8ac",
          "url": "https://github.com/ShenChen1/ufifo/commit/19bf21874e7c0f9295e30ae6ed9a57a71620c29e"
        },
        "date": 1776650251990,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 32472164,
            "unit": "ops/sec",
            "extra": "Latency: 30.8 ns/op, Bandwidth: 123.87 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 33390884,
            "unit": "ops/sec",
            "extra": "Latency: 29.9 ns/op, Bandwidth: 2038.02 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 28615635,
            "unit": "ops/sec",
            "extra": "Latency: 34.9 ns/op, Bandwidth: 6986.24 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 22385794,
            "unit": "ops/sec",
            "extra": "Latency: 44.7 ns/op, Bandwidth: 21861.13 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 12013257,
            "unit": "ops/sec",
            "extra": "Latency: 83.2 ns/op, Bandwidth: 46926.78 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 24727005,
            "unit": "ops/sec",
            "extra": "Latency: 40.4 ns/op, Bandwidth: 94.33 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 25356695,
            "unit": "ops/sec",
            "extra": "Latency: 39.4 ns/op, Bandwidth: 1547.65 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 22452288,
            "unit": "ops/sec",
            "extra": "Latency: 44.5 ns/op, Bandwidth: 5481.52 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 19148090,
            "unit": "ops/sec",
            "extra": "Latency: 52.2 ns/op, Bandwidth: 18699.31 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 11175617,
            "unit": "ops/sec",
            "extra": "Latency: 89.5 ns/op, Bandwidth: 43654.75 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 10642331,
            "unit": "ops/sec",
            "extra": "Latency: 94.0 ns/op, Bandwidth: 40.60 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 12734881,
            "unit": "ops/sec",
            "extra": "Latency: 78.5 ns/op, Bandwidth: 777.28 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 13644010,
            "unit": "ops/sec",
            "extra": "Latency: 73.3 ns/op, Bandwidth: 3331.06 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 9543750,
            "unit": "ops/sec",
            "extra": "Latency: 104.8 ns/op, Bandwidth: 9320.07 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 6016670,
            "unit": "ops/sec",
            "extra": "Latency: 166.2 ns/op, Bandwidth: 22.95 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 4498795,
            "unit": "ops/sec",
            "extra": "Latency: 222.3 ns/op, Bandwidth: 274.58 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 4341655,
            "unit": "ops/sec",
            "extra": "Latency: 230.3 ns/op, Bandwidth: 1059.97 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 2809984,
            "unit": "ops/sec",
            "extra": "Latency: 355.9 ns/op, Bandwidth: 2744.13 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 32622727,
            "unit": "ops/sec",
            "extra": "Latency: 30.7 ns/op, Bandwidth: 124.45 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 33089778,
            "unit": "ops/sec",
            "extra": "Latency: 30.2 ns/op, Bandwidth: 2019.64 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 28259606,
            "unit": "ops/sec",
            "extra": "Latency: 35.4 ns/op, Bandwidth: 6899.32 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 22298373,
            "unit": "ops/sec",
            "extra": "Latency: 44.8 ns/op, Bandwidth: 21775.76 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 24986764,
            "unit": "ops/sec",
            "extra": "Latency: 40.0 ns/op, Bandwidth: 95.32 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 25116571,
            "unit": "ops/sec",
            "extra": "Latency: 39.8 ns/op, Bandwidth: 1532.99 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 22358312,
            "unit": "ops/sec",
            "extra": "Latency: 44.7 ns/op, Bandwidth: 5458.57 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 18394166,
            "unit": "ops/sec",
            "extra": "Latency: 54.4 ns/op, Bandwidth: 17963.05 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 4184962,
            "unit": "ops/sec",
            "extra": "Latency: 239.0 ns/op, Bandwidth: 15.96 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 3648033,
            "unit": "ops/sec",
            "extra": "Latency: 274.1 ns/op, Bandwidth: 222.66 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 3726314,
            "unit": "ops/sec",
            "extra": "Latency: 268.4 ns/op, Bandwidth: 909.74 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 3490509,
            "unit": "ops/sec",
            "extra": "Latency: 286.5 ns/op, Bandwidth: 13.32 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 3585021,
            "unit": "ops/sec",
            "extra": "Latency: 278.9 ns/op, Bandwidth: 218.81 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 3181422,
            "unit": "ops/sec",
            "extra": "Latency: 314.3 ns/op, Bandwidth: 776.71 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 10304031,
            "unit": "ops/sec",
            "extra": "Latency: 97.0 ns/op, Bandwidth: 39.31 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 9568097,
            "unit": "ops/sec",
            "extra": "Latency: 104.5 ns/op, Bandwidth: 583.99 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 9056560,
            "unit": "ops/sec",
            "extra": "Latency: 110.4 ns/op, Bandwidth: 2211.07 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 6700257,
            "unit": "ops/sec",
            "extra": "Latency: 149.2 ns/op, Bandwidth: 6543.22 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "bf8c1aa897c74105ddf586ab6471bcaa77e371e3",
          "message": "fix: change UFIFO_LOCK_THREAD to use PTHREAD_PROCESS_SHARED",
          "timestamp": "2026-04-20T17:00:20Z",
          "tree_id": "b5ff0dc89a1c2d6cc49e7e41d773ca3ee304fb97",
          "url": "https://github.com/ShenChen1/ufifo/commit/bf8c1aa897c74105ddf586ab6471bcaa77e371e3"
        },
        "date": 1776704527086,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 32705187,
            "unit": "ops/sec",
            "extra": "Latency: 30.6 ns/op, Bandwidth: 124.76 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 33430821,
            "unit": "ops/sec",
            "extra": "Latency: 29.9 ns/op, Bandwidth: 2040.46 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 29114389,
            "unit": "ops/sec",
            "extra": "Latency: 34.3 ns/op, Bandwidth: 7108.01 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 23296687,
            "unit": "ops/sec",
            "extra": "Latency: 42.9 ns/op, Bandwidth: 22750.67 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 12041710,
            "unit": "ops/sec",
            "extra": "Latency: 83.0 ns/op, Bandwidth: 47037.93 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 26736044,
            "unit": "ops/sec",
            "extra": "Latency: 37.4 ns/op, Bandwidth: 101.99 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 28655531,
            "unit": "ops/sec",
            "extra": "Latency: 34.9 ns/op, Bandwidth: 1748.99 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 24317723,
            "unit": "ops/sec",
            "extra": "Latency: 41.1 ns/op, Bandwidth: 5936.94 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 21077340,
            "unit": "ops/sec",
            "extra": "Latency: 47.4 ns/op, Bandwidth: 20583.34 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 11829173,
            "unit": "ops/sec",
            "extra": "Latency: 84.5 ns/op, Bandwidth: 46207.71 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 10619603,
            "unit": "ops/sec",
            "extra": "Latency: 94.2 ns/op, Bandwidth: 40.51 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 12122434,
            "unit": "ops/sec",
            "extra": "Latency: 82.5 ns/op, Bandwidth: 739.89 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 15588930,
            "unit": "ops/sec",
            "extra": "Latency: 64.1 ns/op, Bandwidth: 3805.89 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 10408286,
            "unit": "ops/sec",
            "extra": "Latency: 96.1 ns/op, Bandwidth: 10164.34 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 5745362,
            "unit": "ops/sec",
            "extra": "Latency: 174.1 ns/op, Bandwidth: 21.92 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 4903219,
            "unit": "ops/sec",
            "extra": "Latency: 203.9 ns/op, Bandwidth: 299.27 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 4380733,
            "unit": "ops/sec",
            "extra": "Latency: 228.3 ns/op, Bandwidth: 1069.51 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 2309189,
            "unit": "ops/sec",
            "extra": "Latency: 433.1 ns/op, Bandwidth: 2255.07 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 33349440,
            "unit": "ops/sec",
            "extra": "Latency: 30.0 ns/op, Bandwidth: 127.22 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 33755419,
            "unit": "ops/sec",
            "extra": "Latency: 29.6 ns/op, Bandwidth: 2060.27 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 28794966,
            "unit": "ops/sec",
            "extra": "Latency: 34.7 ns/op, Bandwidth: 7030.02 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 23375129,
            "unit": "ops/sec",
            "extra": "Latency: 42.8 ns/op, Bandwidth: 22827.27 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 28161373,
            "unit": "ops/sec",
            "extra": "Latency: 35.5 ns/op, Bandwidth: 107.43 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 28539824,
            "unit": "ops/sec",
            "extra": "Latency: 35.0 ns/op, Bandwidth: 1741.93 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 24685994,
            "unit": "ops/sec",
            "extra": "Latency: 40.5 ns/op, Bandwidth: 6026.85 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 20649293,
            "unit": "ops/sec",
            "extra": "Latency: 48.4 ns/op, Bandwidth: 20165.33 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 4698121,
            "unit": "ops/sec",
            "extra": "Latency: 212.9 ns/op, Bandwidth: 17.92 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 4381330,
            "unit": "ops/sec",
            "extra": "Latency: 228.2 ns/op, Bandwidth: 267.42 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 3533510,
            "unit": "ops/sec",
            "extra": "Latency: 283.0 ns/op, Bandwidth: 862.67 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 4322630,
            "unit": "ops/sec",
            "extra": "Latency: 231.3 ns/op, Bandwidth: 16.49 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 4447575,
            "unit": "ops/sec",
            "extra": "Latency: 224.8 ns/op, Bandwidth: 271.46 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 3520856,
            "unit": "ops/sec",
            "extra": "Latency: 284.0 ns/op, Bandwidth: 859.58 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 9757655,
            "unit": "ops/sec",
            "extra": "Latency: 102.5 ns/op, Bandwidth: 37.22 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 8996764,
            "unit": "ops/sec",
            "extra": "Latency: 111.2 ns/op, Bandwidth: 549.12 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 9260402,
            "unit": "ops/sec",
            "extra": "Latency: 108.0 ns/op, Bandwidth: 2260.84 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 6762992,
            "unit": "ops/sec",
            "extra": "Latency: 147.9 ns/op, Bandwidth: 6604.48 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "bf8c1aa897c74105ddf586ab6471bcaa77e371e3",
          "message": "fix: change UFIFO_LOCK_THREAD to use PTHREAD_PROCESS_SHARED",
          "timestamp": "2026-04-20T17:00:20Z",
          "tree_id": "b5ff0dc89a1c2d6cc49e7e41d773ca3ee304fb97",
          "url": "https://github.com/ShenChen1/ufifo/commit/bf8c1aa897c74105ddf586ab6471bcaa77e371e3"
        },
        "date": 1776705098779,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 32996431,
            "unit": "ops/sec",
            "extra": "Latency: 30.3 ns/op, Bandwidth: 125.87 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 33432180,
            "unit": "ops/sec",
            "extra": "Latency: 29.9 ns/op, Bandwidth: 2040.54 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 29060084,
            "unit": "ops/sec",
            "extra": "Latency: 34.4 ns/op, Bandwidth: 7094.75 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 23476701,
            "unit": "ops/sec",
            "extra": "Latency: 42.6 ns/op, Bandwidth: 22926.47 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 11918685,
            "unit": "ops/sec",
            "extra": "Latency: 83.9 ns/op, Bandwidth: 46557.36 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 28415687,
            "unit": "ops/sec",
            "extra": "Latency: 35.2 ns/op, Bandwidth: 108.40 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 28715627,
            "unit": "ops/sec",
            "extra": "Latency: 34.8 ns/op, Bandwidth: 1752.66 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 24721556,
            "unit": "ops/sec",
            "extra": "Latency: 40.5 ns/op, Bandwidth: 6035.54 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 20877462,
            "unit": "ops/sec",
            "extra": "Latency: 47.9 ns/op, Bandwidth: 20388.15 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 11562683,
            "unit": "ops/sec",
            "extra": "Latency: 86.5 ns/op, Bandwidth: 45166.73 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 10986026,
            "unit": "ops/sec",
            "extra": "Latency: 91.0 ns/op, Bandwidth: 41.91 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 13047130,
            "unit": "ops/sec",
            "extra": "Latency: 76.6 ns/op, Bandwidth: 796.33 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 12069651,
            "unit": "ops/sec",
            "extra": "Latency: 82.9 ns/op, Bandwidth: 2946.69 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 9790252,
            "unit": "ops/sec",
            "extra": "Latency: 102.1 ns/op, Bandwidth: 9560.79 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 6018518,
            "unit": "ops/sec",
            "extra": "Latency: 166.2 ns/op, Bandwidth: 22.96 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 5132914,
            "unit": "ops/sec",
            "extra": "Latency: 194.8 ns/op, Bandwidth: 313.29 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 4648337,
            "unit": "ops/sec",
            "extra": "Latency: 215.1 ns/op, Bandwidth: 1134.85 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 2467393,
            "unit": "ops/sec",
            "extra": "Latency: 405.3 ns/op, Bandwidth: 2409.56 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 33312991,
            "unit": "ops/sec",
            "extra": "Latency: 30.0 ns/op, Bandwidth: 127.08 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 33715718,
            "unit": "ops/sec",
            "extra": "Latency: 29.7 ns/op, Bandwidth: 2057.84 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 28715257,
            "unit": "ops/sec",
            "extra": "Latency: 34.8 ns/op, Bandwidth: 7010.56 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 23461698,
            "unit": "ops/sec",
            "extra": "Latency: 42.6 ns/op, Bandwidth: 22911.81 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 28160171,
            "unit": "ops/sec",
            "extra": "Latency: 35.5 ns/op, Bandwidth: 107.42 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 28516362,
            "unit": "ops/sec",
            "extra": "Latency: 35.1 ns/op, Bandwidth: 1740.50 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 24698040,
            "unit": "ops/sec",
            "extra": "Latency: 40.5 ns/op, Bandwidth: 6029.79 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 20581986,
            "unit": "ops/sec",
            "extra": "Latency: 48.6 ns/op, Bandwidth: 20099.60 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 4803928,
            "unit": "ops/sec",
            "extra": "Latency: 208.2 ns/op, Bandwidth: 18.33 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 4299730,
            "unit": "ops/sec",
            "extra": "Latency: 232.6 ns/op, Bandwidth: 262.43 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 3597423,
            "unit": "ops/sec",
            "extra": "Latency: 278.0 ns/op, Bandwidth: 878.28 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 4411226,
            "unit": "ops/sec",
            "extra": "Latency: 226.7 ns/op, Bandwidth: 16.83 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 4455969,
            "unit": "ops/sec",
            "extra": "Latency: 224.4 ns/op, Bandwidth: 271.97 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 3754555,
            "unit": "ops/sec",
            "extra": "Latency: 266.3 ns/op, Bandwidth: 916.64 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 9563979,
            "unit": "ops/sec",
            "extra": "Latency: 104.6 ns/op, Bandwidth: 36.48 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 8819732,
            "unit": "ops/sec",
            "extra": "Latency: 113.4 ns/op, Bandwidth: 538.31 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 9312826,
            "unit": "ops/sec",
            "extra": "Latency: 107.4 ns/op, Bandwidth: 2273.64 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 6849185,
            "unit": "ops/sec",
            "extra": "Latency: 146.0 ns/op, Bandwidth: 6688.66 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "123859b3b51fff384d551a0b627d2682caacebf4",
          "message": "refactor: split ufifo.c into smaller specialized modules\n\nThis change resolves the excessive size of `ufifo.c` by modularizing its responsibilities into focused, single-responsibility files without modifying the public API:\n- `ufifo_sync.c`: Synchronization primitives (mutexes, semaphores, file locks).\n- `ufifo_epoll.c`: epoll notification and socket communications.\n- `ufifo_init.c`: Shared memory allocation, attaching, and user registration.\n- `ufifo_info.c`: Diagnostic dumps and version queries.\n- `ufifo_opts.c`: Core data access operations (put, get, peek, etc.).\n- `ufifo_internal.h`: Internal declarations shared across these new modules.\n\nThe changes preserve 100% ABI and API compatibility while significantly improving code readability and maintainability. All existing tests continue to pass.",
          "timestamp": "2026-04-20T18:07:10Z",
          "tree_id": "46822d3704188cd47e8a78bd5529714b8765c401",
          "url": "https://github.com/ShenChen1/ufifo/commit/123859b3b51fff384d551a0b627d2682caacebf4"
        },
        "date": 1776708488685,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 39712723,
            "unit": "ops/sec",
            "extra": "Latency: 25.2 ns/op, Bandwidth: 151.49 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 40208948,
            "unit": "ops/sec",
            "extra": "Latency: 24.9 ns/op, Bandwidth: 2454.16 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 27708595,
            "unit": "ops/sec",
            "extra": "Latency: 36.1 ns/op, Bandwidth: 6764.79 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 23282860,
            "unit": "ops/sec",
            "extra": "Latency: 43.0 ns/op, Bandwidth: 22737.17 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 12596421,
            "unit": "ops/sec",
            "extra": "Latency: 79.4 ns/op, Bandwidth: 49204.77 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 32128212,
            "unit": "ops/sec",
            "extra": "Latency: 31.1 ns/op, Bandwidth: 122.56 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 32806227,
            "unit": "ops/sec",
            "extra": "Latency: 30.5 ns/op, Bandwidth: 2002.33 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 21971181,
            "unit": "ops/sec",
            "extra": "Latency: 45.5 ns/op, Bandwidth: 5364.06 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 20365913,
            "unit": "ops/sec",
            "extra": "Latency: 49.1 ns/op, Bandwidth: 19888.59 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 11910222,
            "unit": "ops/sec",
            "extra": "Latency: 84.0 ns/op, Bandwidth: 46524.30 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 9564332,
            "unit": "ops/sec",
            "extra": "Latency: 104.6 ns/op, Bandwidth: 36.49 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 9764524,
            "unit": "ops/sec",
            "extra": "Latency: 102.4 ns/op, Bandwidth: 595.98 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 9927551,
            "unit": "ops/sec",
            "extra": "Latency: 100.7 ns/op, Bandwidth: 2423.72 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 6719832,
            "unit": "ops/sec",
            "extra": "Latency: 148.8 ns/op, Bandwidth: 6562.34 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 2225950,
            "unit": "ops/sec",
            "extra": "Latency: 449.2 ns/op, Bandwidth: 8.49 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 2440043,
            "unit": "ops/sec",
            "extra": "Latency: 409.8 ns/op, Bandwidth: 148.93 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 2213214,
            "unit": "ops/sec",
            "extra": "Latency: 451.8 ns/op, Bandwidth: 540.34 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 1667072,
            "unit": "ops/sec",
            "extra": "Latency: 599.9 ns/op, Bandwidth: 1628.00 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 38460795,
            "unit": "ops/sec",
            "extra": "Latency: 26.0 ns/op, Bandwidth: 146.72 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 39094810,
            "unit": "ops/sec",
            "extra": "Latency: 25.6 ns/op, Bandwidth: 2386.16 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 27164824,
            "unit": "ops/sec",
            "extra": "Latency: 36.8 ns/op, Bandwidth: 6632.04 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 23044787,
            "unit": "ops/sec",
            "extra": "Latency: 43.4 ns/op, Bandwidth: 22504.67 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 32930086,
            "unit": "ops/sec",
            "extra": "Latency: 30.4 ns/op, Bandwidth: 125.62 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 33188325,
            "unit": "ops/sec",
            "extra": "Latency: 30.1 ns/op, Bandwidth: 2025.65 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 22390636,
            "unit": "ops/sec",
            "extra": "Latency: 44.7 ns/op, Bandwidth: 5466.46 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 20284782,
            "unit": "ops/sec",
            "extra": "Latency: 49.3 ns/op, Bandwidth: 19809.36 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 4582250,
            "unit": "ops/sec",
            "extra": "Latency: 218.2 ns/op, Bandwidth: 17.48 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 3893910,
            "unit": "ops/sec",
            "extra": "Latency: 256.8 ns/op, Bandwidth: 237.67 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 3404015,
            "unit": "ops/sec",
            "extra": "Latency: 293.8 ns/op, Bandwidth: 831.06 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 4422773,
            "unit": "ops/sec",
            "extra": "Latency: 226.1 ns/op, Bandwidth: 16.87 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 3825093,
            "unit": "ops/sec",
            "extra": "Latency: 261.4 ns/op, Bandwidth: 233.47 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 2795195,
            "unit": "ops/sec",
            "extra": "Latency: 357.8 ns/op, Bandwidth: 682.42 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 8876750,
            "unit": "ops/sec",
            "extra": "Latency: 112.7 ns/op, Bandwidth: 33.86 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 8234416,
            "unit": "ops/sec",
            "extra": "Latency: 121.4 ns/op, Bandwidth: 502.59 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 8013906,
            "unit": "ops/sec",
            "extra": "Latency: 124.8 ns/op, Bandwidth: 1956.52 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 4913442,
            "unit": "ops/sec",
            "extra": "Latency: 203.5 ns/op, Bandwidth: 4798.28 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "123859b3b51fff384d551a0b627d2682caacebf4",
          "message": "refactor: split ufifo.c into smaller specialized modules\n\nThis change resolves the excessive size of `ufifo.c` by modularizing its responsibilities into focused, single-responsibility files without modifying the public API:\n- `ufifo_sync.c`: Synchronization primitives (mutexes, semaphores, file locks).\n- `ufifo_epoll.c`: epoll notification and socket communications.\n- `ufifo_init.c`: Shared memory allocation, attaching, and user registration.\n- `ufifo_info.c`: Diagnostic dumps and version queries.\n- `ufifo_opts.c`: Core data access operations (put, get, peek, etc.).\n- `ufifo_internal.h`: Internal declarations shared across these new modules.\n\nThe changes preserve 100% ABI and API compatibility while significantly improving code readability and maintainability. All existing tests continue to pass.",
          "timestamp": "2026-04-20T18:07:10Z",
          "tree_id": "46822d3704188cd47e8a78bd5529714b8765c401",
          "url": "https://github.com/ShenChen1/ufifo/commit/123859b3b51fff384d551a0b627d2682caacebf4"
        },
        "date": 1776708587773,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 31183203,
            "unit": "ops/sec",
            "extra": "Latency: 32.1 ns/op, Bandwidth: 118.95 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 32101860,
            "unit": "ops/sec",
            "extra": "Latency: 31.2 ns/op, Bandwidth: 1959.34 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 27203301,
            "unit": "ops/sec",
            "extra": "Latency: 36.8 ns/op, Bandwidth: 6641.43 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 22624185,
            "unit": "ops/sec",
            "extra": "Latency: 44.2 ns/op, Bandwidth: 22093.93 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 11894853,
            "unit": "ops/sec",
            "extra": "Latency: 84.1 ns/op, Bandwidth: 46464.27 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 25321283,
            "unit": "ops/sec",
            "extra": "Latency: 39.5 ns/op, Bandwidth: 96.59 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 25596743,
            "unit": "ops/sec",
            "extra": "Latency: 39.1 ns/op, Bandwidth: 1562.30 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 22791588,
            "unit": "ops/sec",
            "extra": "Latency: 43.9 ns/op, Bandwidth: 5564.35 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 19413240,
            "unit": "ops/sec",
            "extra": "Latency: 51.5 ns/op, Bandwidth: 18958.24 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 11299420,
            "unit": "ops/sec",
            "extra": "Latency: 88.5 ns/op, Bandwidth: 44138.36 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 10744455,
            "unit": "ops/sec",
            "extra": "Latency: 93.1 ns/op, Bandwidth: 40.99 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 15869680,
            "unit": "ops/sec",
            "extra": "Latency: 63.0 ns/op, Bandwidth: 968.61 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 18623600,
            "unit": "ops/sec",
            "extra": "Latency: 53.7 ns/op, Bandwidth: 4546.78 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 9860036,
            "unit": "ops/sec",
            "extra": "Latency: 101.4 ns/op, Bandwidth: 9628.94 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 5704544,
            "unit": "ops/sec",
            "extra": "Latency: 175.3 ns/op, Bandwidth: 21.76 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 4163195,
            "unit": "ops/sec",
            "extra": "Latency: 240.2 ns/op, Bandwidth: 254.10 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 4032341,
            "unit": "ops/sec",
            "extra": "Latency: 248.0 ns/op, Bandwidth: 984.46 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 2767967,
            "unit": "ops/sec",
            "extra": "Latency: 361.3 ns/op, Bandwidth: 2703.09 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 31327754,
            "unit": "ops/sec",
            "extra": "Latency: 31.9 ns/op, Bandwidth: 119.51 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 31716534,
            "unit": "ops/sec",
            "extra": "Latency: 31.5 ns/op, Bandwidth: 1935.82 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 27203346,
            "unit": "ops/sec",
            "extra": "Latency: 36.8 ns/op, Bandwidth: 6641.44 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 22332793,
            "unit": "ops/sec",
            "extra": "Latency: 44.8 ns/op, Bandwidth: 21809.37 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 25611227,
            "unit": "ops/sec",
            "extra": "Latency: 39.0 ns/op, Bandwidth: 97.70 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 25866389,
            "unit": "ops/sec",
            "extra": "Latency: 38.7 ns/op, Bandwidth: 1578.76 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 22994937,
            "unit": "ops/sec",
            "extra": "Latency: 43.5 ns/op, Bandwidth: 5614.00 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 19418345,
            "unit": "ops/sec",
            "extra": "Latency: 51.5 ns/op, Bandwidth: 18963.23 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 4093251,
            "unit": "ops/sec",
            "extra": "Latency: 244.3 ns/op, Bandwidth: 15.61 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 4313460,
            "unit": "ops/sec",
            "extra": "Latency: 231.8 ns/op, Bandwidth: 263.27 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 3522391,
            "unit": "ops/sec",
            "extra": "Latency: 283.9 ns/op, Bandwidth: 859.96 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 4021323,
            "unit": "ops/sec",
            "extra": "Latency: 248.7 ns/op, Bandwidth: 15.34 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 3801102,
            "unit": "ops/sec",
            "extra": "Latency: 263.1 ns/op, Bandwidth: 232.00 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 3491677,
            "unit": "ops/sec",
            "extra": "Latency: 286.4 ns/op, Bandwidth: 852.46 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 9805607,
            "unit": "ops/sec",
            "extra": "Latency: 102.0 ns/op, Bandwidth: 37.41 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 8881580,
            "unit": "ops/sec",
            "extra": "Latency: 112.6 ns/op, Bandwidth: 542.09 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 9134961,
            "unit": "ops/sec",
            "extra": "Latency: 109.5 ns/op, Bandwidth: 2230.22 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 6728529,
            "unit": "ops/sec",
            "extra": "Latency: 148.6 ns/op, Bandwidth: 6570.83 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "123859b3b51fff384d551a0b627d2682caacebf4",
          "message": "refactor: split ufifo.c into smaller specialized modules\n\nThis change resolves the excessive size of `ufifo.c` by modularizing its responsibilities into focused, single-responsibility files without modifying the public API:\n- `ufifo_sync.c`: Synchronization primitives (mutexes, semaphores, file locks).\n- `ufifo_epoll.c`: epoll notification and socket communications.\n- `ufifo_init.c`: Shared memory allocation, attaching, and user registration.\n- `ufifo_info.c`: Diagnostic dumps and version queries.\n- `ufifo_opts.c`: Core data access operations (put, get, peek, etc.).\n- `ufifo_internal.h`: Internal declarations shared across these new modules.\n\nThe changes preserve 100% ABI and API compatibility while significantly improving code readability and maintainability. All existing tests continue to pass.",
          "timestamp": "2026-04-20T18:07:10Z",
          "tree_id": "46822d3704188cd47e8a78bd5529714b8765c401",
          "url": "https://github.com/ShenChen1/ufifo/commit/123859b3b51fff384d551a0b627d2682caacebf4"
        },
        "date": 1776708654969,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 31403592,
            "unit": "ops/sec",
            "extra": "Latency: 31.8 ns/op, Bandwidth: 119.80 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 32208580,
            "unit": "ops/sec",
            "extra": "Latency: 31.0 ns/op, Bandwidth: 1965.86 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 27145184,
            "unit": "ops/sec",
            "extra": "Latency: 36.8 ns/op, Bandwidth: 6627.24 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 22593441,
            "unit": "ops/sec",
            "extra": "Latency: 44.3 ns/op, Bandwidth: 22063.91 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 8909079,
            "unit": "ops/sec",
            "extra": "Latency: 112.2 ns/op, Bandwidth: 34801.09 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 22123559,
            "unit": "ops/sec",
            "extra": "Latency: 45.2 ns/op, Bandwidth: 84.39 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 27127913,
            "unit": "ops/sec",
            "extra": "Latency: 36.9 ns/op, Bandwidth: 1655.76 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 24050952,
            "unit": "ops/sec",
            "extra": "Latency: 41.6 ns/op, Bandwidth: 5871.81 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 20249158,
            "unit": "ops/sec",
            "extra": "Latency: 49.4 ns/op, Bandwidth: 19774.57 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 11586290,
            "unit": "ops/sec",
            "extra": "Latency: 86.3 ns/op, Bandwidth: 45258.95 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 10225686,
            "unit": "ops/sec",
            "extra": "Latency: 97.8 ns/op, Bandwidth: 39.01 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 14964395,
            "unit": "ops/sec",
            "extra": "Latency: 66.8 ns/op, Bandwidth: 913.35 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 16687196,
            "unit": "ops/sec",
            "extra": "Latency: 59.9 ns/op, Bandwidth: 4074.02 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 10228673,
            "unit": "ops/sec",
            "extra": "Latency: 97.8 ns/op, Bandwidth: 9988.94 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 4779600,
            "unit": "ops/sec",
            "extra": "Latency: 209.2 ns/op, Bandwidth: 18.23 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 4462012,
            "unit": "ops/sec",
            "extra": "Latency: 224.1 ns/op, Bandwidth: 272.34 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 3907761,
            "unit": "ops/sec",
            "extra": "Latency: 255.9 ns/op, Bandwidth: 954.04 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 2236494,
            "unit": "ops/sec",
            "extra": "Latency: 447.1 ns/op, Bandwidth: 2184.08 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 31106254,
            "unit": "ops/sec",
            "extra": "Latency: 32.1 ns/op, Bandwidth: 118.66 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 31683430,
            "unit": "ops/sec",
            "extra": "Latency: 31.6 ns/op, Bandwidth: 1933.80 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 27150697,
            "unit": "ops/sec",
            "extra": "Latency: 36.8 ns/op, Bandwidth: 6628.59 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 22319272,
            "unit": "ops/sec",
            "extra": "Latency: 44.8 ns/op, Bandwidth: 21796.16 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 26827168,
            "unit": "ops/sec",
            "extra": "Latency: 37.3 ns/op, Bandwidth: 102.34 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 27159319,
            "unit": "ops/sec",
            "extra": "Latency: 36.8 ns/op, Bandwidth: 1657.67 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 23989903,
            "unit": "ops/sec",
            "extra": "Latency: 41.7 ns/op, Bandwidth: 5856.91 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 20122608,
            "unit": "ops/sec",
            "extra": "Latency: 49.7 ns/op, Bandwidth: 19650.98 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 4574842,
            "unit": "ops/sec",
            "extra": "Latency: 218.6 ns/op, Bandwidth: 17.45 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 5055340,
            "unit": "ops/sec",
            "extra": "Latency: 197.8 ns/op, Bandwidth: 308.55 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 3452590,
            "unit": "ops/sec",
            "extra": "Latency: 289.6 ns/op, Bandwidth: 842.92 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 4000858,
            "unit": "ops/sec",
            "extra": "Latency: 249.9 ns/op, Bandwidth: 15.26 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 3860094,
            "unit": "ops/sec",
            "extra": "Latency: 259.1 ns/op, Bandwidth: 235.60 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 3308553,
            "unit": "ops/sec",
            "extra": "Latency: 302.2 ns/op, Bandwidth: 807.75 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 10049808,
            "unit": "ops/sec",
            "extra": "Latency: 99.5 ns/op, Bandwidth: 38.34 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 9345672,
            "unit": "ops/sec",
            "extra": "Latency: 107.0 ns/op, Bandwidth: 570.41 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 9500144,
            "unit": "ops/sec",
            "extra": "Latency: 105.3 ns/op, Bandwidth: 2319.37 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 6760997,
            "unit": "ops/sec",
            "extra": "Latency: 147.9 ns/op, Bandwidth: 6602.54 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "123859b3b51fff384d551a0b627d2682caacebf4",
          "message": "refactor: split ufifo.c into smaller specialized modules\n\nThis change resolves the excessive size of `ufifo.c` by modularizing its responsibilities into focused, single-responsibility files without modifying the public API:\n- `ufifo_sync.c`: Synchronization primitives (mutexes, semaphores, file locks).\n- `ufifo_epoll.c`: epoll notification and socket communications.\n- `ufifo_init.c`: Shared memory allocation, attaching, and user registration.\n- `ufifo_info.c`: Diagnostic dumps and version queries.\n- `ufifo_opts.c`: Core data access operations (put, get, peek, etc.).\n- `ufifo_internal.h`: Internal declarations shared across these new modules.\n\nThe changes preserve 100% ABI and API compatibility while significantly improving code readability and maintainability. All existing tests continue to pass.",
          "timestamp": "2026-04-20T18:07:10Z",
          "tree_id": "46822d3704188cd47e8a78bd5529714b8765c401",
          "url": "https://github.com/ShenChen1/ufifo/commit/123859b3b51fff384d551a0b627d2682caacebf4"
        },
        "date": 1776708703018,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 31607350,
            "unit": "ops/sec",
            "extra": "Latency: 31.6 ns/op, Bandwidth: 120.57 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 31713924,
            "unit": "ops/sec",
            "extra": "Latency: 31.5 ns/op, Bandwidth: 1935.66 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 27074220,
            "unit": "ops/sec",
            "extra": "Latency: 36.9 ns/op, Bandwidth: 6609.92 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 22459666,
            "unit": "ops/sec",
            "extra": "Latency: 44.5 ns/op, Bandwidth: 21933.27 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 11858728,
            "unit": "ops/sec",
            "extra": "Latency: 84.3 ns/op, Bandwidth: 46323.16 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 26765920,
            "unit": "ops/sec",
            "extra": "Latency: 37.4 ns/op, Bandwidth: 102.10 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 27001177,
            "unit": "ops/sec",
            "extra": "Latency: 37.0 ns/op, Bandwidth: 1648.02 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 24014812,
            "unit": "ops/sec",
            "extra": "Latency: 41.6 ns/op, Bandwidth: 5862.99 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 20125521,
            "unit": "ops/sec",
            "extra": "Latency: 49.7 ns/op, Bandwidth: 19653.83 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 11561206,
            "unit": "ops/sec",
            "extra": "Latency: 86.5 ns/op, Bandwidth: 45160.96 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 10340629,
            "unit": "ops/sec",
            "extra": "Latency: 96.7 ns/op, Bandwidth: 39.45 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 11967789,
            "unit": "ops/sec",
            "extra": "Latency: 83.6 ns/op, Bandwidth: 730.46 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 13951828,
            "unit": "ops/sec",
            "extra": "Latency: 71.7 ns/op, Bandwidth: 3406.21 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 9719209,
            "unit": "ops/sec",
            "extra": "Latency: 102.9 ns/op, Bandwidth: 9491.42 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 4951434,
            "unit": "ops/sec",
            "extra": "Latency: 202.0 ns/op, Bandwidth: 18.89 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 3885619,
            "unit": "ops/sec",
            "extra": "Latency: 257.4 ns/op, Bandwidth: 237.16 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 3195289,
            "unit": "ops/sec",
            "extra": "Latency: 313.0 ns/op, Bandwidth: 780.10 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 2668456,
            "unit": "ops/sec",
            "extra": "Latency: 374.7 ns/op, Bandwidth: 2605.91 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 31257489,
            "unit": "ops/sec",
            "extra": "Latency: 32.0 ns/op, Bandwidth: 119.24 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 31592538,
            "unit": "ops/sec",
            "extra": "Latency: 31.7 ns/op, Bandwidth: 1928.26 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 27085183,
            "unit": "ops/sec",
            "extra": "Latency: 36.9 ns/op, Bandwidth: 6612.59 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 22290021,
            "unit": "ops/sec",
            "extra": "Latency: 44.9 ns/op, Bandwidth: 21767.60 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 26746836,
            "unit": "ops/sec",
            "extra": "Latency: 37.4 ns/op, Bandwidth: 102.03 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 27068027,
            "unit": "ops/sec",
            "extra": "Latency: 36.9 ns/op, Bandwidth: 1652.10 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 23725308,
            "unit": "ops/sec",
            "extra": "Latency: 42.1 ns/op, Bandwidth: 5792.31 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 19989506,
            "unit": "ops/sec",
            "extra": "Latency: 50.0 ns/op, Bandwidth: 19521.00 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 4928504,
            "unit": "ops/sec",
            "extra": "Latency: 202.9 ns/op, Bandwidth: 18.80 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 3699016,
            "unit": "ops/sec",
            "extra": "Latency: 270.3 ns/op, Bandwidth: 225.77 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 3975769,
            "unit": "ops/sec",
            "extra": "Latency: 251.5 ns/op, Bandwidth: 970.65 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 3829786,
            "unit": "ops/sec",
            "extra": "Latency: 261.1 ns/op, Bandwidth: 14.61 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 3790321,
            "unit": "ops/sec",
            "extra": "Latency: 263.8 ns/op, Bandwidth: 231.34 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 3351596,
            "unit": "ops/sec",
            "extra": "Latency: 298.4 ns/op, Bandwidth: 818.26 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 10403035,
            "unit": "ops/sec",
            "extra": "Latency: 96.1 ns/op, Bandwidth: 39.68 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 9469449,
            "unit": "ops/sec",
            "extra": "Latency: 105.6 ns/op, Bandwidth: 577.97 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 9129277,
            "unit": "ops/sec",
            "extra": "Latency: 109.5 ns/op, Bandwidth: 2228.83 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 6456378,
            "unit": "ops/sec",
            "extra": "Latency: 154.9 ns/op, Bandwidth: 6305.06 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "8f5d0f1c84fd1ffaf745454b1eb3505310204700",
          "message": "init: add documentation",
          "timestamp": "2026-04-20T18:08:28Z",
          "tree_id": "e75817a3fa2bb677079e193fa9015c4945831112",
          "url": "https://github.com/ShenChen1/ufifo/commit/8f5d0f1c84fd1ffaf745454b1eb3505310204700"
        },
        "date": 1776708800757,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 31266061,
            "unit": "ops/sec",
            "extra": "Latency: 32.0 ns/op, Bandwidth: 119.27 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 32114293,
            "unit": "ops/sec",
            "extra": "Latency: 31.1 ns/op, Bandwidth: 1960.10 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 27370105,
            "unit": "ops/sec",
            "extra": "Latency: 36.5 ns/op, Bandwidth: 6682.15 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 22670621,
            "unit": "ops/sec",
            "extra": "Latency: 44.1 ns/op, Bandwidth: 22139.28 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 11893620,
            "unit": "ops/sec",
            "extra": "Latency: 84.1 ns/op, Bandwidth: 46459.45 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 26595091,
            "unit": "ops/sec",
            "extra": "Latency: 37.6 ns/op, Bandwidth: 101.45 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 27198922,
            "unit": "ops/sec",
            "extra": "Latency: 36.8 ns/op, Bandwidth: 1660.09 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 23488635,
            "unit": "ops/sec",
            "extra": "Latency: 42.6 ns/op, Bandwidth: 5734.53 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 19268613,
            "unit": "ops/sec",
            "extra": "Latency: 51.9 ns/op, Bandwidth: 18817.00 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 11577517,
            "unit": "ops/sec",
            "extra": "Latency: 86.4 ns/op, Bandwidth: 45224.68 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 9753372,
            "unit": "ops/sec",
            "extra": "Latency: 102.5 ns/op, Bandwidth: 37.21 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 14038915,
            "unit": "ops/sec",
            "extra": "Latency: 71.2 ns/op, Bandwidth: 856.87 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 12163177,
            "unit": "ops/sec",
            "extra": "Latency: 82.2 ns/op, Bandwidth: 2969.53 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 9413522,
            "unit": "ops/sec",
            "extra": "Latency: 106.2 ns/op, Bandwidth: 9192.89 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 4204084,
            "unit": "ops/sec",
            "extra": "Latency: 237.9 ns/op, Bandwidth: 16.04 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 4296456,
            "unit": "ops/sec",
            "extra": "Latency: 232.7 ns/op, Bandwidth: 262.23 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 3504467,
            "unit": "ops/sec",
            "extra": "Latency: 285.4 ns/op, Bandwidth: 855.58 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 2192222,
            "unit": "ops/sec",
            "extra": "Latency: 456.2 ns/op, Bandwidth: 2140.84 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 30289616,
            "unit": "ops/sec",
            "extra": "Latency: 33.0 ns/op, Bandwidth: 115.55 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 30552154,
            "unit": "ops/sec",
            "extra": "Latency: 32.7 ns/op, Bandwidth: 1864.76 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 26374083,
            "unit": "ops/sec",
            "extra": "Latency: 37.9 ns/op, Bandwidth: 6438.99 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 21941004,
            "unit": "ops/sec",
            "extra": "Latency: 45.6 ns/op, Bandwidth: 21426.76 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 25769622,
            "unit": "ops/sec",
            "extra": "Latency: 38.8 ns/op, Bandwidth: 98.30 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 25967414,
            "unit": "ops/sec",
            "extra": "Latency: 38.5 ns/op, Bandwidth: 1584.93 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 22991521,
            "unit": "ops/sec",
            "extra": "Latency: 43.5 ns/op, Bandwidth: 5613.16 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 19534647,
            "unit": "ops/sec",
            "extra": "Latency: 51.2 ns/op, Bandwidth: 19076.80 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 4311764,
            "unit": "ops/sec",
            "extra": "Latency: 231.9 ns/op, Bandwidth: 16.45 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 4433084,
            "unit": "ops/sec",
            "extra": "Latency: 225.6 ns/op, Bandwidth: 270.57 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 3595407,
            "unit": "ops/sec",
            "extra": "Latency: 278.1 ns/op, Bandwidth: 877.78 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 3937970,
            "unit": "ops/sec",
            "extra": "Latency: 253.9 ns/op, Bandwidth: 15.02 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 3638812,
            "unit": "ops/sec",
            "extra": "Latency: 274.8 ns/op, Bandwidth: 222.10 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 3251894,
            "unit": "ops/sec",
            "extra": "Latency: 307.5 ns/op, Bandwidth: 793.92 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 9631181,
            "unit": "ops/sec",
            "extra": "Latency: 103.8 ns/op, Bandwidth: 36.74 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 9072341,
            "unit": "ops/sec",
            "extra": "Latency: 110.2 ns/op, Bandwidth: 553.73 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 8977472,
            "unit": "ops/sec",
            "extra": "Latency: 111.4 ns/op, Bandwidth: 2191.77 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 6204992,
            "unit": "ops/sec",
            "extra": "Latency: 161.2 ns/op, Bandwidth: 6059.56 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "8f5d0f1c84fd1ffaf745454b1eb3505310204700",
          "message": "init: add documentation",
          "timestamp": "2026-04-20T18:08:28Z",
          "tree_id": "e75817a3fa2bb677079e193fa9015c4945831112",
          "url": "https://github.com/ShenChen1/ufifo/commit/8f5d0f1c84fd1ffaf745454b1eb3505310204700"
        },
        "date": 1776709012248,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 31604790,
            "unit": "ops/sec",
            "extra": "Latency: 31.6 ns/op, Bandwidth: 120.56 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 32148671,
            "unit": "ops/sec",
            "extra": "Latency: 31.1 ns/op, Bandwidth: 1962.20 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 27277404,
            "unit": "ops/sec",
            "extra": "Latency: 36.7 ns/op, Bandwidth: 6659.52 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 22627345,
            "unit": "ops/sec",
            "extra": "Latency: 44.2 ns/op, Bandwidth: 22097.02 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 11835822,
            "unit": "ops/sec",
            "extra": "Latency: 84.5 ns/op, Bandwidth: 46233.68 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 26841632,
            "unit": "ops/sec",
            "extra": "Latency: 37.3 ns/op, Bandwidth: 102.39 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 27122741,
            "unit": "ops/sec",
            "extra": "Latency: 36.9 ns/op, Bandwidth: 1655.44 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 23995935,
            "unit": "ops/sec",
            "extra": "Latency: 41.7 ns/op, Bandwidth: 5858.38 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 20064194,
            "unit": "ops/sec",
            "extra": "Latency: 49.8 ns/op, Bandwidth: 19593.94 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 11315359,
            "unit": "ops/sec",
            "extra": "Latency: 88.4 ns/op, Bandwidth: 44200.62 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 10177015,
            "unit": "ops/sec",
            "extra": "Latency: 98.3 ns/op, Bandwidth: 38.82 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 14171011,
            "unit": "ops/sec",
            "extra": "Latency: 70.6 ns/op, Bandwidth: 864.93 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 12676074,
            "unit": "ops/sec",
            "extra": "Latency: 78.9 ns/op, Bandwidth: 3094.74 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 11305665,
            "unit": "ops/sec",
            "extra": "Latency: 88.5 ns/op, Bandwidth: 11040.69 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 5086193,
            "unit": "ops/sec",
            "extra": "Latency: 196.6 ns/op, Bandwidth: 19.40 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 4785143,
            "unit": "ops/sec",
            "extra": "Latency: 209.0 ns/op, Bandwidth: 292.06 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 3813901,
            "unit": "ops/sec",
            "extra": "Latency: 262.2 ns/op, Bandwidth: 931.13 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 2261102,
            "unit": "ops/sec",
            "extra": "Latency: 442.3 ns/op, Bandwidth: 2208.11 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 31381689,
            "unit": "ops/sec",
            "extra": "Latency: 31.9 ns/op, Bandwidth: 119.71 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 31703527,
            "unit": "ops/sec",
            "extra": "Latency: 31.5 ns/op, Bandwidth: 1935.03 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 27169534,
            "unit": "ops/sec",
            "extra": "Latency: 36.8 ns/op, Bandwidth: 6633.19 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 22478305,
            "unit": "ops/sec",
            "extra": "Latency: 44.5 ns/op, Bandwidth: 21951.47 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 26874024,
            "unit": "ops/sec",
            "extra": "Latency: 37.2 ns/op, Bandwidth: 102.52 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 27083112,
            "unit": "ops/sec",
            "extra": "Latency: 36.9 ns/op, Bandwidth: 1653.02 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 23898468,
            "unit": "ops/sec",
            "extra": "Latency: 41.8 ns/op, Bandwidth: 5834.59 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 20229197,
            "unit": "ops/sec",
            "extra": "Latency: 49.4 ns/op, Bandwidth: 19755.07 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 6155768,
            "unit": "ops/sec",
            "extra": "Latency: 162.4 ns/op, Bandwidth: 23.48 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 5745800,
            "unit": "ops/sec",
            "extra": "Latency: 174.0 ns/op, Bandwidth: 350.70 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 3434199,
            "unit": "ops/sec",
            "extra": "Latency: 291.2 ns/op, Bandwidth: 838.43 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 3967816,
            "unit": "ops/sec",
            "extra": "Latency: 252.0 ns/op, Bandwidth: 15.14 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 3848584,
            "unit": "ops/sec",
            "extra": "Latency: 259.8 ns/op, Bandwidth: 234.90 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 3418502,
            "unit": "ops/sec",
            "extra": "Latency: 292.5 ns/op, Bandwidth: 834.60 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 10100779,
            "unit": "ops/sec",
            "extra": "Latency: 99.0 ns/op, Bandwidth: 38.53 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 9161345,
            "unit": "ops/sec",
            "extra": "Latency: 109.2 ns/op, Bandwidth: 559.16 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 9367161,
            "unit": "ops/sec",
            "extra": "Latency: 106.8 ns/op, Bandwidth: 2286.90 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 6817137,
            "unit": "ops/sec",
            "extra": "Latency: 146.7 ns/op, Bandwidth: 6657.36 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "e1f553c9b882744b8f98cd0542bc4cb0199d74ed",
          "message": "feat: add lsan support to CI",
          "timestamp": "2026-04-22T17:24:47Z",
          "tree_id": "ab6f6c3fb0b187f398cbb5ecc6151e81fea91eb0",
          "url": "https://github.com/ShenChen1/ufifo/commit/e1f553c9b882744b8f98cd0542bc4cb0199d74ed"
        },
        "date": 1776878726309,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 49906809,
            "unit": "ops/sec",
            "extra": "Latency: 20.0 ns/op, Bandwidth: 190.38 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 51002825,
            "unit": "ops/sec",
            "extra": "Latency: 19.6 ns/op, Bandwidth: 3112.97 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 35690073,
            "unit": "ops/sec",
            "extra": "Latency: 28.0 ns/op, Bandwidth: 8713.40 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 29833394,
            "unit": "ops/sec",
            "extra": "Latency: 33.5 ns/op, Bandwidth: 29134.17 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 16256876,
            "unit": "ops/sec",
            "extra": "Latency: 61.5 ns/op, Bandwidth: 63503.42 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 41671711,
            "unit": "ops/sec",
            "extra": "Latency: 24.0 ns/op, Bandwidth: 158.96 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 36792533,
            "unit": "ops/sec",
            "extra": "Latency: 27.2 ns/op, Bandwidth: 2245.64 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 28636647,
            "unit": "ops/sec",
            "extra": "Latency: 34.9 ns/op, Bandwidth: 6991.37 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 26486871,
            "unit": "ops/sec",
            "extra": "Latency: 37.8 ns/op, Bandwidth: 25866.08 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 14962524,
            "unit": "ops/sec",
            "extra": "Latency: 66.8 ns/op, Bandwidth: 58447.36 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 10365764,
            "unit": "ops/sec",
            "extra": "Latency: 96.5 ns/op, Bandwidth: 39.54 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 4174360,
            "unit": "ops/sec",
            "extra": "Latency: 239.6 ns/op, Bandwidth: 254.78 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 11712365,
            "unit": "ops/sec",
            "extra": "Latency: 85.4 ns/op, Bandwidth: 2859.46 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 8753714,
            "unit": "ops/sec",
            "extra": "Latency: 114.2 ns/op, Bandwidth: 8548.55 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 2712151,
            "unit": "ops/sec",
            "extra": "Latency: 368.7 ns/op, Bandwidth: 10.35 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 2687028,
            "unit": "ops/sec",
            "extra": "Latency: 372.2 ns/op, Bandwidth: 164.00 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 2728838,
            "unit": "ops/sec",
            "extra": "Latency: 366.5 ns/op, Bandwidth: 666.22 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 1853405,
            "unit": "ops/sec",
            "extra": "Latency: 539.5 ns/op, Bandwidth: 1809.97 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 50049490,
            "unit": "ops/sec",
            "extra": "Latency: 20.0 ns/op, Bandwidth: 190.92 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 50502141,
            "unit": "ops/sec",
            "extra": "Latency: 19.8 ns/op, Bandwidth: 3082.41 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 33895580,
            "unit": "ops/sec",
            "extra": "Latency: 29.5 ns/op, Bandwidth: 8275.29 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 29371642,
            "unit": "ops/sec",
            "extra": "Latency: 34.0 ns/op, Bandwidth: 28683.24 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 41712281,
            "unit": "ops/sec",
            "extra": "Latency: 24.0 ns/op, Bandwidth: 159.12 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 42346027,
            "unit": "ops/sec",
            "extra": "Latency: 23.6 ns/op, Bandwidth: 2584.60 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 29884168,
            "unit": "ops/sec",
            "extra": "Latency: 33.5 ns/op, Bandwidth: 7295.94 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 26340798,
            "unit": "ops/sec",
            "extra": "Latency: 38.0 ns/op, Bandwidth: 25723.44 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 8625360,
            "unit": "ops/sec",
            "extra": "Latency: 115.9 ns/op, Bandwidth: 32.90 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 5274160,
            "unit": "ops/sec",
            "extra": "Latency: 189.6 ns/op, Bandwidth: 321.91 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 3949528,
            "unit": "ops/sec",
            "extra": "Latency: 253.2 ns/op, Bandwidth: 964.24 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 5409608,
            "unit": "ops/sec",
            "extra": "Latency: 184.9 ns/op, Bandwidth: 20.64 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 4503847,
            "unit": "ops/sec",
            "extra": "Latency: 222.0 ns/op, Bandwidth: 274.89 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 4232051,
            "unit": "ops/sec",
            "extra": "Latency: 236.3 ns/op, Bandwidth: 1033.22 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 11447489,
            "unit": "ops/sec",
            "extra": "Latency: 87.4 ns/op, Bandwidth: 43.67 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 10663922,
            "unit": "ops/sec",
            "extra": "Latency: 93.8 ns/op, Bandwidth: 650.87 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 10026578,
            "unit": "ops/sec",
            "extra": "Latency: 99.7 ns/op, Bandwidth: 2447.89 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 6333337,
            "unit": "ops/sec",
            "extra": "Latency: 157.9 ns/op, Bandwidth: 6184.90 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "e1f553c9b882744b8f98cd0542bc4cb0199d74ed",
          "message": "feat: add lsan support to CI",
          "timestamp": "2026-04-22T17:24:47Z",
          "tree_id": "ab6f6c3fb0b187f398cbb5ecc6151e81fea91eb0",
          "url": "https://github.com/ShenChen1/ufifo/commit/e1f553c9b882744b8f98cd0542bc4cb0199d74ed"
        },
        "date": 1776879004931,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 38970546,
            "unit": "ops/sec",
            "extra": "Latency: 25.7 ns/op, Bandwidth: 148.66 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 39716589,
            "unit": "ops/sec",
            "extra": "Latency: 25.2 ns/op, Bandwidth: 2424.11 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 27475971,
            "unit": "ops/sec",
            "extra": "Latency: 36.4 ns/op, Bandwidth: 6708.00 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 23119728,
            "unit": "ops/sec",
            "extra": "Latency: 43.3 ns/op, Bandwidth: 22577.86 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 10867455,
            "unit": "ops/sec",
            "extra": "Latency: 92.0 ns/op, Bandwidth: 42450.99 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 28794270,
            "unit": "ops/sec",
            "extra": "Latency: 34.7 ns/op, Bandwidth: 109.84 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 31575286,
            "unit": "ops/sec",
            "extra": "Latency: 31.7 ns/op, Bandwidth: 1927.20 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 22235575,
            "unit": "ops/sec",
            "extra": "Latency: 45.0 ns/op, Bandwidth: 5428.61 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 20504366,
            "unit": "ops/sec",
            "extra": "Latency: 48.8 ns/op, Bandwidth: 20023.79 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 11869918,
            "unit": "ops/sec",
            "extra": "Latency: 84.2 ns/op, Bandwidth: 46366.87 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 9331078,
            "unit": "ops/sec",
            "extra": "Latency: 107.2 ns/op, Bandwidth: 35.60 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 9786433,
            "unit": "ops/sec",
            "extra": "Latency: 102.2 ns/op, Bandwidth: 597.32 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 10052622,
            "unit": "ops/sec",
            "extra": "Latency: 99.5 ns/op, Bandwidth: 2454.25 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 7114866,
            "unit": "ops/sec",
            "extra": "Latency: 140.6 ns/op, Bandwidth: 6948.11 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 5698733,
            "unit": "ops/sec",
            "extra": "Latency: 175.5 ns/op, Bandwidth: 21.74 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 3083860,
            "unit": "ops/sec",
            "extra": "Latency: 324.3 ns/op, Bandwidth: 188.22 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 4107163,
            "unit": "ops/sec",
            "extra": "Latency: 243.5 ns/op, Bandwidth: 1002.73 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 1766771,
            "unit": "ops/sec",
            "extra": "Latency: 566.0 ns/op, Bandwidth: 1725.36 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 38704412,
            "unit": "ops/sec",
            "extra": "Latency: 25.8 ns/op, Bandwidth: 147.65 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 39263873,
            "unit": "ops/sec",
            "extra": "Latency: 25.5 ns/op, Bandwidth: 2396.48 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 26345739,
            "unit": "ops/sec",
            "extra": "Latency: 38.0 ns/op, Bandwidth: 6432.07 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 22796177,
            "unit": "ops/sec",
            "extra": "Latency: 43.9 ns/op, Bandwidth: 22261.89 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 32407849,
            "unit": "ops/sec",
            "extra": "Latency: 30.9 ns/op, Bandwidth: 123.63 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 32806305,
            "unit": "ops/sec",
            "extra": "Latency: 30.5 ns/op, Bandwidth: 2002.34 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 23116475,
            "unit": "ops/sec",
            "extra": "Latency: 43.3 ns/op, Bandwidth: 5643.67 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 20537732,
            "unit": "ops/sec",
            "extra": "Latency: 48.7 ns/op, Bandwidth: 20056.38 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 4768329,
            "unit": "ops/sec",
            "extra": "Latency: 209.7 ns/op, Bandwidth: 18.19 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 3747376,
            "unit": "ops/sec",
            "extra": "Latency: 266.9 ns/op, Bandwidth: 228.72 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 3540530,
            "unit": "ops/sec",
            "extra": "Latency: 282.4 ns/op, Bandwidth: 864.39 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 4276166,
            "unit": "ops/sec",
            "extra": "Latency: 233.9 ns/op, Bandwidth: 16.31 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 3798298,
            "unit": "ops/sec",
            "extra": "Latency: 263.3 ns/op, Bandwidth: 231.83 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 3130521,
            "unit": "ops/sec",
            "extra": "Latency: 319.4 ns/op, Bandwidth: 764.29 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 8890111,
            "unit": "ops/sec",
            "extra": "Latency: 112.5 ns/op, Bandwidth: 33.91 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 8227531,
            "unit": "ops/sec",
            "extra": "Latency: 121.5 ns/op, Bandwidth: 502.17 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 7968777,
            "unit": "ops/sec",
            "extra": "Latency: 125.5 ns/op, Bandwidth: 1945.50 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 5020610,
            "unit": "ops/sec",
            "extra": "Latency: 199.2 ns/op, Bandwidth: 4902.94 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "sc",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "96507a67f4e92b4bde7b8ccd746263314ea2b644",
          "message": "test: improve benchmark stability",
          "timestamp": "2026-04-26T23:37:38+08:00",
          "tree_id": "a660c740ed269c3c81752d87beb1c7ecba602d9a",
          "url": "https://github.com/ShenChen1/ufifo/commit/96507a67f4e92b4bde7b8ccd746263314ea2b644"
        },
        "date": 1777217894800,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 29973758,
            "unit": "ops/sec",
            "extra": "Latency: 33.4 ns/op, Bandwidth: 114.34 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 30612544,
            "unit": "ops/sec",
            "extra": "Latency: 32.7 ns/op, Bandwidth: 1868.44 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 26692323,
            "unit": "ops/sec",
            "extra": "Latency: 37.5 ns/op, Bandwidth: 6516.68 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 22002450,
            "unit": "ops/sec",
            "extra": "Latency: 45.4 ns/op, Bandwidth: 21486.77 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 11674447,
            "unit": "ops/sec",
            "extra": "Latency: 85.7 ns/op, Bandwidth: 45603.31 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 26317335,
            "unit": "ops/sec",
            "extra": "Latency: 38.0 ns/op, Bandwidth: 100.39 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 21896614,
            "unit": "ops/sec",
            "extra": "Latency: 45.7 ns/op, Bandwidth: 1336.46 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 23750593,
            "unit": "ops/sec",
            "extra": "Latency: 42.1 ns/op, Bandwidth: 5798.48 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 20129566,
            "unit": "ops/sec",
            "extra": "Latency: 49.7 ns/op, Bandwidth: 19657.78 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 11221838,
            "unit": "ops/sec",
            "extra": "Latency: 89.1 ns/op, Bandwidth: 43835.30 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 10830448,
            "unit": "ops/sec",
            "extra": "Latency: 92.3 ns/op, Bandwidth: 41.31 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 13446783,
            "unit": "ops/sec",
            "extra": "Latency: 74.4 ns/op, Bandwidth: 820.73 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 15396250,
            "unit": "ops/sec",
            "extra": "Latency: 65.0 ns/op, Bandwidth: 3758.85 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 10196765,
            "unit": "ops/sec",
            "extra": "Latency: 98.1 ns/op, Bandwidth: 9957.78 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 4946437,
            "unit": "ops/sec",
            "extra": "Latency: 202.2 ns/op, Bandwidth: 18.87 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 3990849,
            "unit": "ops/sec",
            "extra": "Latency: 250.6 ns/op, Bandwidth: 243.58 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 3920625,
            "unit": "ops/sec",
            "extra": "Latency: 255.1 ns/op, Bandwidth: 957.18 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 2192568,
            "unit": "ops/sec",
            "extra": "Latency: 456.1 ns/op, Bandwidth: 2141.18 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 30155585,
            "unit": "ops/sec",
            "extra": "Latency: 33.2 ns/op, Bandwidth: 115.03 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 30412312,
            "unit": "ops/sec",
            "extra": "Latency: 32.9 ns/op, Bandwidth: 1856.22 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 26543942,
            "unit": "ops/sec",
            "extra": "Latency: 37.7 ns/op, Bandwidth: 6480.45 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 21959192,
            "unit": "ops/sec",
            "extra": "Latency: 45.5 ns/op, Bandwidth: 21444.52 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 26590438,
            "unit": "ops/sec",
            "extra": "Latency: 37.6 ns/op, Bandwidth: 101.43 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 26907105,
            "unit": "ops/sec",
            "extra": "Latency: 37.2 ns/op, Bandwidth: 1642.28 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 23702333,
            "unit": "ops/sec",
            "extra": "Latency: 42.2 ns/op, Bandwidth: 5786.70 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 19975129,
            "unit": "ops/sec",
            "extra": "Latency: 50.1 ns/op, Bandwidth: 19506.96 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 4492432,
            "unit": "ops/sec",
            "extra": "Latency: 222.6 ns/op, Bandwidth: 17.14 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 4127090,
            "unit": "ops/sec",
            "extra": "Latency: 242.3 ns/op, Bandwidth: 251.90 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 3560960,
            "unit": "ops/sec",
            "extra": "Latency: 280.8 ns/op, Bandwidth: 869.37 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 4155745,
            "unit": "ops/sec",
            "extra": "Latency: 240.6 ns/op, Bandwidth: 15.85 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 3995529,
            "unit": "ops/sec",
            "extra": "Latency: 250.3 ns/op, Bandwidth: 243.87 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 3523850,
            "unit": "ops/sec",
            "extra": "Latency: 283.8 ns/op, Bandwidth: 860.32 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 10981500,
            "unit": "ops/sec",
            "extra": "Latency: 91.1 ns/op, Bandwidth: 41.89 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 10163588,
            "unit": "ops/sec",
            "extra": "Latency: 98.4 ns/op, Bandwidth: 620.34 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 9843198,
            "unit": "ops/sec",
            "extra": "Latency: 101.6 ns/op, Bandwidth: 2403.12 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 6488785,
            "unit": "ops/sec",
            "extra": "Latency: 154.1 ns/op, Bandwidth: 6336.70 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "73aa1529daae69fbaae845a3c77f05624ae5ad3c",
          "message": "refactor: update ufifo_open to accept const char* name",
          "timestamp": "2026-04-27T14:44:15Z",
          "tree_id": "b44fe8d0ce2bf12971983b7d8fbfaaaa2d625b2c",
          "url": "https://github.com/ShenChen1/ufifo/commit/73aa1529daae69fbaae845a3c77f05624ae5ad3c"
        },
        "date": 1777301108733,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 40011144,
            "unit": "ops/sec",
            "extra": "Latency: 25.0 ns/op, Bandwidth: 152.63 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 40049366,
            "unit": "ops/sec",
            "extra": "Latency: 25.0 ns/op, Bandwidth: 2444.42 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 28345767,
            "unit": "ops/sec",
            "extra": "Latency: 35.3 ns/op, Bandwidth: 6920.35 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 23433173,
            "unit": "ops/sec",
            "extra": "Latency: 42.7 ns/op, Bandwidth: 22883.96 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 12737652,
            "unit": "ops/sec",
            "extra": "Latency: 78.5 ns/op, Bandwidth: 49756.45 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 32902065,
            "unit": "ops/sec",
            "extra": "Latency: 30.4 ns/op, Bandwidth: 125.51 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 32983561,
            "unit": "ops/sec",
            "extra": "Latency: 30.3 ns/op, Bandwidth: 2013.16 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 23680052,
            "unit": "ops/sec",
            "extra": "Latency: 42.2 ns/op, Bandwidth: 5781.26 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 20487653,
            "unit": "ops/sec",
            "extra": "Latency: 48.8 ns/op, Bandwidth: 20007.47 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 12052021,
            "unit": "ops/sec",
            "extra": "Latency: 83.0 ns/op, Bandwidth: 47078.21 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 9492289,
            "unit": "ops/sec",
            "extra": "Latency: 105.3 ns/op, Bandwidth: 36.21 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 10159291,
            "unit": "ops/sec",
            "extra": "Latency: 98.4 ns/op, Bandwidth: 620.07 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 9586924,
            "unit": "ops/sec",
            "extra": "Latency: 104.3 ns/op, Bandwidth: 2340.56 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 6883294,
            "unit": "ops/sec",
            "extra": "Latency: 145.3 ns/op, Bandwidth: 6721.97 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 4183769,
            "unit": "ops/sec",
            "extra": "Latency: 239.0 ns/op, Bandwidth: 15.96 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 2467177,
            "unit": "ops/sec",
            "extra": "Latency: 405.3 ns/op, Bandwidth: 150.58 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 2784831,
            "unit": "ops/sec",
            "extra": "Latency: 359.1 ns/op, Bandwidth: 679.89 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 1524234,
            "unit": "ops/sec",
            "extra": "Latency: 656.1 ns/op, Bandwidth: 1488.51 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 39615068,
            "unit": "ops/sec",
            "extra": "Latency: 25.2 ns/op, Bandwidth: 151.12 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 40154848,
            "unit": "ops/sec",
            "extra": "Latency: 24.9 ns/op, Bandwidth: 2450.86 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 27735993,
            "unit": "ops/sec",
            "extra": "Latency: 36.1 ns/op, Bandwidth: 6771.48 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 22783866,
            "unit": "ops/sec",
            "extra": "Latency: 43.9 ns/op, Bandwidth: 22249.87 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 33177475,
            "unit": "ops/sec",
            "extra": "Latency: 30.1 ns/op, Bandwidth: 126.56 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 33231253,
            "unit": "ops/sec",
            "extra": "Latency: 30.1 ns/op, Bandwidth: 2028.27 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 23554126,
            "unit": "ops/sec",
            "extra": "Latency: 42.5 ns/op, Bandwidth: 5750.52 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 20527023,
            "unit": "ops/sec",
            "extra": "Latency: 48.7 ns/op, Bandwidth: 20045.92 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 4504402,
            "unit": "ops/sec",
            "extra": "Latency: 222.0 ns/op, Bandwidth: 17.18 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 3845034,
            "unit": "ops/sec",
            "extra": "Latency: 260.1 ns/op, Bandwidth: 234.68 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 3758103,
            "unit": "ops/sec",
            "extra": "Latency: 266.1 ns/op, Bandwidth: 917.51 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 3942083,
            "unit": "ops/sec",
            "extra": "Latency: 253.7 ns/op, Bandwidth: 15.04 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 3874442,
            "unit": "ops/sec",
            "extra": "Latency: 258.1 ns/op, Bandwidth: 236.48 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 2924592,
            "unit": "ops/sec",
            "extra": "Latency: 341.9 ns/op, Bandwidth: 714.01 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 8315790,
            "unit": "ops/sec",
            "extra": "Latency: 120.3 ns/op, Bandwidth: 31.72 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 7836039,
            "unit": "ops/sec",
            "extra": "Latency: 127.6 ns/op, Bandwidth: 478.27 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 7476317,
            "unit": "ops/sec",
            "extra": "Latency: 133.8 ns/op, Bandwidth: 1825.27 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 4749511,
            "unit": "ops/sec",
            "extra": "Latency: 210.5 ns/op, Bandwidth: 4638.19 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "6f0889d0ed3743d16af9df136cc4f74266f25188",
          "message": "feat(build): improve library versioning, visibility, and installation\n\n- Set SOVERSION and VERSION properties for the shared library.\n- Implement symbol visibility using -fvisibility=hidden and UFIFO_API macro.\n- Refactor installation targets and add explicit install commands.\n- Add installation verification to CI workflow.\n- Add API documentation packaging and upload to Release workflow.",
          "timestamp": "2026-04-27T16:21:54Z",
          "tree_id": "3359aff6c210873e6d6975ade2ea2a6b7ad03f45",
          "url": "https://github.com/ShenChen1/ufifo/commit/6f0889d0ed3743d16af9df136cc4f74266f25188"
        },
        "date": 1777307026552,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 29660047,
            "unit": "ops/sec",
            "extra": "Latency: 33.7 ns/op, Bandwidth: 113.14 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 31798492,
            "unit": "ops/sec",
            "extra": "Latency: 31.4 ns/op, Bandwidth: 1940.83 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 27364705,
            "unit": "ops/sec",
            "extra": "Latency: 36.5 ns/op, Bandwidth: 6680.84 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 22607413,
            "unit": "ops/sec",
            "extra": "Latency: 44.2 ns/op, Bandwidth: 22077.55 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 10839699,
            "unit": "ops/sec",
            "extra": "Latency: 92.3 ns/op, Bandwidth: 42342.58 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 26836356,
            "unit": "ops/sec",
            "extra": "Latency: 37.3 ns/op, Bandwidth: 102.37 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 26595705,
            "unit": "ops/sec",
            "extra": "Latency: 37.6 ns/op, Bandwidth: 1623.27 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 22130172,
            "unit": "ops/sec",
            "extra": "Latency: 45.2 ns/op, Bandwidth: 5402.87 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 19839895,
            "unit": "ops/sec",
            "extra": "Latency: 50.4 ns/op, Bandwidth: 19374.90 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 11210528,
            "unit": "ops/sec",
            "extra": "Latency: 89.2 ns/op, Bandwidth: 43791.13 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 10338251,
            "unit": "ops/sec",
            "extra": "Latency: 96.7 ns/op, Bandwidth: 39.44 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 13683170,
            "unit": "ops/sec",
            "extra": "Latency: 73.1 ns/op, Bandwidth: 835.15 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 17335445,
            "unit": "ops/sec",
            "extra": "Latency: 57.7 ns/op, Bandwidth: 4232.29 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 10130223,
            "unit": "ops/sec",
            "extra": "Latency: 98.7 ns/op, Bandwidth: 9892.80 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 4871691,
            "unit": "ops/sec",
            "extra": "Latency: 205.3 ns/op, Bandwidth: 18.58 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 4559096,
            "unit": "ops/sec",
            "extra": "Latency: 219.3 ns/op, Bandwidth: 278.27 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 3780724,
            "unit": "ops/sec",
            "extra": "Latency: 264.5 ns/op, Bandwidth: 923.03 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 2358179,
            "unit": "ops/sec",
            "extra": "Latency: 424.1 ns/op, Bandwidth: 2302.91 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 31285818,
            "unit": "ops/sec",
            "extra": "Latency: 32.0 ns/op, Bandwidth: 119.35 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 31072948,
            "unit": "ops/sec",
            "extra": "Latency: 32.2 ns/op, Bandwidth: 1896.54 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 26682925,
            "unit": "ops/sec",
            "extra": "Latency: 37.5 ns/op, Bandwidth: 6514.39 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 22211724,
            "unit": "ops/sec",
            "extra": "Latency: 45.0 ns/op, Bandwidth: 21691.14 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 25638141,
            "unit": "ops/sec",
            "extra": "Latency: 39.0 ns/op, Bandwidth: 97.80 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 25893760,
            "unit": "ops/sec",
            "extra": "Latency: 38.6 ns/op, Bandwidth: 1580.43 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 22853090,
            "unit": "ops/sec",
            "extra": "Latency: 43.8 ns/op, Bandwidth: 5579.37 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 19375661,
            "unit": "ops/sec",
            "extra": "Latency: 51.6 ns/op, Bandwidth: 18921.54 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 5774481,
            "unit": "ops/sec",
            "extra": "Latency: 173.2 ns/op, Bandwidth: 22.03 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 4563655,
            "unit": "ops/sec",
            "extra": "Latency: 219.1 ns/op, Bandwidth: 278.54 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 3559017,
            "unit": "ops/sec",
            "extra": "Latency: 281.0 ns/op, Bandwidth: 868.90 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 3918528,
            "unit": "ops/sec",
            "extra": "Latency: 255.2 ns/op, Bandwidth: 14.95 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 3931130,
            "unit": "ops/sec",
            "extra": "Latency: 254.4 ns/op, Bandwidth: 239.94 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 3454800,
            "unit": "ops/sec",
            "extra": "Latency: 289.5 ns/op, Bandwidth: 843.46 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 9400567,
            "unit": "ops/sec",
            "extra": "Latency: 106.4 ns/op, Bandwidth: 35.86 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 8578398,
            "unit": "ops/sec",
            "extra": "Latency: 116.6 ns/op, Bandwidth: 523.58 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 8994060,
            "unit": "ops/sec",
            "extra": "Latency: 111.2 ns/op, Bandwidth: 2195.82 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 6524942,
            "unit": "ops/sec",
            "extra": "Latency: 153.3 ns/op, Bandwidth: 6372.01 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "154e81b7314c2cd7e00159436ba7754f834006c0",
          "message": "fix: restrict Doxygen input to ufifo.h",
          "timestamp": "2026-04-27T16:53:03Z",
          "tree_id": "71bfbcb520dbe1831c8a0ab96bb0d5f24f84c036",
          "url": "https://github.com/ShenChen1/ufifo/commit/154e81b7314c2cd7e00159436ba7754f834006c0"
        },
        "date": 1777308836682,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 30899132,
            "unit": "ops/sec",
            "extra": "Latency: 32.4 ns/op, Bandwidth: 117.87 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 30888699,
            "unit": "ops/sec",
            "extra": "Latency: 32.4 ns/op, Bandwidth: 1885.30 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 27466721,
            "unit": "ops/sec",
            "extra": "Latency: 36.4 ns/op, Bandwidth: 6705.74 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 22623887,
            "unit": "ops/sec",
            "extra": "Latency: 44.2 ns/op, Bandwidth: 22093.64 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 11906815,
            "unit": "ops/sec",
            "extra": "Latency: 84.0 ns/op, Bandwidth: 46510.99 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 27123147,
            "unit": "ops/sec",
            "extra": "Latency: 36.9 ns/op, Bandwidth: 103.47 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 27306395,
            "unit": "ops/sec",
            "extra": "Latency: 36.6 ns/op, Bandwidth: 1666.65 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 23910182,
            "unit": "ops/sec",
            "extra": "Latency: 41.8 ns/op, Bandwidth: 5837.45 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 19474734,
            "unit": "ops/sec",
            "extra": "Latency: 51.3 ns/op, Bandwidth: 19018.30 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 11592288,
            "unit": "ops/sec",
            "extra": "Latency: 86.3 ns/op, Bandwidth: 45282.37 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 10229435,
            "unit": "ops/sec",
            "extra": "Latency: 97.8 ns/op, Bandwidth: 39.02 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 18666615,
            "unit": "ops/sec",
            "extra": "Latency: 53.6 ns/op, Bandwidth: 1139.32 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 14357297,
            "unit": "ops/sec",
            "extra": "Latency: 69.7 ns/op, Bandwidth: 3505.20 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 9167798,
            "unit": "ops/sec",
            "extra": "Latency: 109.1 ns/op, Bandwidth: 8952.93 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 3916406,
            "unit": "ops/sec",
            "extra": "Latency: 255.3 ns/op, Bandwidth: 14.94 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 3873067,
            "unit": "ops/sec",
            "extra": "Latency: 258.2 ns/op, Bandwidth: 236.39 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 3841334,
            "unit": "ops/sec",
            "extra": "Latency: 260.3 ns/op, Bandwidth: 937.83 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 2078060,
            "unit": "ops/sec",
            "extra": "Latency: 481.2 ns/op, Bandwidth: 2029.36 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 31026118,
            "unit": "ops/sec",
            "extra": "Latency: 32.2 ns/op, Bandwidth: 118.36 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 31313017,
            "unit": "ops/sec",
            "extra": "Latency: 31.9 ns/op, Bandwidth: 1911.19 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 27000358,
            "unit": "ops/sec",
            "extra": "Latency: 37.0 ns/op, Bandwidth: 6591.88 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 22384712,
            "unit": "ops/sec",
            "extra": "Latency: 44.7 ns/op, Bandwidth: 21860.07 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 25527037,
            "unit": "ops/sec",
            "extra": "Latency: 39.2 ns/op, Bandwidth: 97.38 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 25912230,
            "unit": "ops/sec",
            "extra": "Latency: 38.6 ns/op, Bandwidth: 1581.56 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 22842837,
            "unit": "ops/sec",
            "extra": "Latency: 43.8 ns/op, Bandwidth: 5576.86 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 19473416,
            "unit": "ops/sec",
            "extra": "Latency: 51.4 ns/op, Bandwidth: 19017.01 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 4065000,
            "unit": "ops/sec",
            "extra": "Latency: 246.0 ns/op, Bandwidth: 15.51 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 5125153,
            "unit": "ops/sec",
            "extra": "Latency: 195.1 ns/op, Bandwidth: 312.81 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 3268365,
            "unit": "ops/sec",
            "extra": "Latency: 306.0 ns/op, Bandwidth: 797.94 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 4033410,
            "unit": "ops/sec",
            "extra": "Latency: 247.9 ns/op, Bandwidth: 15.39 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 3854071,
            "unit": "ops/sec",
            "extra": "Latency: 259.5 ns/op, Bandwidth: 235.23 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 3402436,
            "unit": "ops/sec",
            "extra": "Latency: 293.9 ns/op, Bandwidth: 830.67 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 10226173,
            "unit": "ops/sec",
            "extra": "Latency: 97.8 ns/op, Bandwidth: 39.01 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 9264175,
            "unit": "ops/sec",
            "extra": "Latency: 107.9 ns/op, Bandwidth: 565.44 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 9114655,
            "unit": "ops/sec",
            "extra": "Latency: 109.7 ns/op, Bandwidth: 2225.26 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 6234008,
            "unit": "ops/sec",
            "extra": "Latency: 160.4 ns/op, Bandwidth: 6087.90 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "9ed48a106c881c48f794553138032c61a9463801",
          "message": "feat: refactor output to use __ufifo_log",
          "timestamp": "2026-04-27T17:21:54Z",
          "tree_id": "cd5204e766630cd2b9ad6d92d3f4507a08ae6788",
          "url": "https://github.com/ShenChen1/ufifo/commit/9ed48a106c881c48f794553138032c61a9463801"
        },
        "date": 1777310561667,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 29684405,
            "unit": "ops/sec",
            "extra": "Latency: 33.7 ns/op, Bandwidth: 113.24 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 30561366,
            "unit": "ops/sec",
            "extra": "Latency: 32.7 ns/op, Bandwidth: 1865.32 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 26296113,
            "unit": "ops/sec",
            "extra": "Latency: 38.0 ns/op, Bandwidth: 6419.95 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 21520852,
            "unit": "ops/sec",
            "extra": "Latency: 46.5 ns/op, Bandwidth: 21016.46 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 11292773,
            "unit": "ops/sec",
            "extra": "Latency: 88.6 ns/op, Bandwidth: 44112.40 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 25681283,
            "unit": "ops/sec",
            "extra": "Latency: 38.9 ns/op, Bandwidth: 97.97 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 26024875,
            "unit": "ops/sec",
            "extra": "Latency: 38.4 ns/op, Bandwidth: 1588.43 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 22916406,
            "unit": "ops/sec",
            "extra": "Latency: 43.6 ns/op, Bandwidth: 5594.83 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 19463270,
            "unit": "ops/sec",
            "extra": "Latency: 51.4 ns/op, Bandwidth: 19007.10 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 11049725,
            "unit": "ops/sec",
            "extra": "Latency: 90.5 ns/op, Bandwidth: 43162.99 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 10184300,
            "unit": "ops/sec",
            "extra": "Latency: 98.2 ns/op, Bandwidth: 38.85 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 14745253,
            "unit": "ops/sec",
            "extra": "Latency: 67.8 ns/op, Bandwidth: 899.98 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 14595833,
            "unit": "ops/sec",
            "extra": "Latency: 68.5 ns/op, Bandwidth: 3563.44 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 9466859,
            "unit": "ops/sec",
            "extra": "Latency: 105.6 ns/op, Bandwidth: 9244.98 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 5098560,
            "unit": "ops/sec",
            "extra": "Latency: 196.1 ns/op, Bandwidth: 19.45 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 4131960,
            "unit": "ops/sec",
            "extra": "Latency: 242.0 ns/op, Bandwidth: 252.19 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 3429127,
            "unit": "ops/sec",
            "extra": "Latency: 291.6 ns/op, Bandwidth: 837.19 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 2057227,
            "unit": "ops/sec",
            "extra": "Latency: 486.1 ns/op, Bandwidth: 2009.01 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 30217808,
            "unit": "ops/sec",
            "extra": "Latency: 33.1 ns/op, Bandwidth: 115.27 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 30467987,
            "unit": "ops/sec",
            "extra": "Latency: 32.8 ns/op, Bandwidth: 1859.62 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 26191895,
            "unit": "ops/sec",
            "extra": "Latency: 38.2 ns/op, Bandwidth: 6394.51 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 21623010,
            "unit": "ops/sec",
            "extra": "Latency: 46.2 ns/op, Bandwidth: 21116.22 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 26172693,
            "unit": "ops/sec",
            "extra": "Latency: 38.2 ns/op, Bandwidth: 99.84 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 27172193,
            "unit": "ops/sec",
            "extra": "Latency: 36.8 ns/op, Bandwidth: 1658.46 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 23828216,
            "unit": "ops/sec",
            "extra": "Latency: 42.0 ns/op, Bandwidth: 5817.44 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 20213314,
            "unit": "ops/sec",
            "extra": "Latency: 49.5 ns/op, Bandwidth: 19739.56 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 5329478,
            "unit": "ops/sec",
            "extra": "Latency: 187.6 ns/op, Bandwidth: 20.33 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 3994474,
            "unit": "ops/sec",
            "extra": "Latency: 250.3 ns/op, Bandwidth: 243.80 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 3269646,
            "unit": "ops/sec",
            "extra": "Latency: 305.8 ns/op, Bandwidth: 798.25 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 3923074,
            "unit": "ops/sec",
            "extra": "Latency: 254.9 ns/op, Bandwidth: 14.97 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 3979148,
            "unit": "ops/sec",
            "extra": "Latency: 251.3 ns/op, Bandwidth: 242.87 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 3360445,
            "unit": "ops/sec",
            "extra": "Latency: 297.6 ns/op, Bandwidth: 820.42 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 9202561,
            "unit": "ops/sec",
            "extra": "Latency: 108.7 ns/op, Bandwidth: 35.10 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 8912034,
            "unit": "ops/sec",
            "extra": "Latency: 112.2 ns/op, Bandwidth: 543.95 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 8789229,
            "unit": "ops/sec",
            "extra": "Latency: 113.8 ns/op, Bandwidth: 2145.81 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 6396694,
            "unit": "ops/sec",
            "extra": "Latency: 156.3 ns/op, Bandwidth: 6246.77 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "sc",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "3624ecce2f8c1c2c6b7641082f1c76a077d7fa1f",
          "message": "fix: restore fast path for eventfd notifications\n\nIn commit b470f73, the fast path for notifications was removed, causing\nthe system to execute an unconditional write() system call on every\nufifo_put and ufifo_get, leading to a 10x performance regression.\n\nThis commit restores the fast path by:\n1. Adding rx_waiters, tx_waiters, epoll_rx_armed, epoll_tx_armed\n   to track the waiting state and epoll registration state.\n2. Only triggering __ufifo_efd_post() if there are active waiters or\n   if a listener is registered via epoll.\n3. Updating wait/timedwait wrappers to atomically increment/decrement\n   waiters counters before/after poll.\n\nThis avoids unconditional system calls and fully restores benchmark\nthroughput and latency under high load.",
          "timestamp": "2026-04-30T00:19:06+08:00",
          "tree_id": "331526fb221f1fb6756525268c0c04a55c6f5f98",
          "url": "https://github.com/ShenChen1/ufifo/commit/3624ecce2f8c1c2c6b7641082f1c76a077d7fa1f"
        },
        "date": 1777479588682,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 38841960,
            "unit": "ops/sec",
            "extra": "Latency: 25.7 ns/op, Bandwidth: 148.17 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 37959847,
            "unit": "ops/sec",
            "extra": "Latency: 26.3 ns/op, Bandwidth: 2316.89 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 30448489,
            "unit": "ops/sec",
            "extra": "Latency: 32.8 ns/op, Bandwidth: 7433.71 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 25832020,
            "unit": "ops/sec",
            "extra": "Latency: 38.7 ns/op, Bandwidth: 25226.58 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 12558980,
            "unit": "ops/sec",
            "extra": "Latency: 79.6 ns/op, Bandwidth: 49058.51 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 32700411,
            "unit": "ops/sec",
            "extra": "Latency: 30.6 ns/op, Bandwidth: 124.74 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 32283283,
            "unit": "ops/sec",
            "extra": "Latency: 31.0 ns/op, Bandwidth: 1970.42 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 25792913,
            "unit": "ops/sec",
            "extra": "Latency: 38.8 ns/op, Bandwidth: 6297.10 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 23098179,
            "unit": "ops/sec",
            "extra": "Latency: 43.3 ns/op, Bandwidth: 22556.82 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 11838489,
            "unit": "ops/sec",
            "extra": "Latency: 84.5 ns/op, Bandwidth: 46244.10 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 29617940,
            "unit": "ops/sec",
            "extra": "Latency: 33.8 ns/op, Bandwidth: 112.98 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 23506456,
            "unit": "ops/sec",
            "extra": "Latency: 42.5 ns/op, Bandwidth: 1434.72 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 20118835,
            "unit": "ops/sec",
            "extra": "Latency: 49.7 ns/op, Bandwidth: 4911.82 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 14110962,
            "unit": "ops/sec",
            "extra": "Latency: 70.9 ns/op, Bandwidth: 13780.24 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 8412143,
            "unit": "ops/sec",
            "extra": "Latency: 118.9 ns/op, Bandwidth: 32.09 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 9009787,
            "unit": "ops/sec",
            "extra": "Latency: 111.0 ns/op, Bandwidth: 549.91 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 5752501,
            "unit": "ops/sec",
            "extra": "Latency: 173.8 ns/op, Bandwidth: 1404.42 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 3553517,
            "unit": "ops/sec",
            "extra": "Latency: 281.4 ns/op, Bandwidth: 3470.23 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 38477160,
            "unit": "ops/sec",
            "extra": "Latency: 26.0 ns/op, Bandwidth: 146.78 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 38179221,
            "unit": "ops/sec",
            "extra": "Latency: 26.2 ns/op, Bandwidth: 2330.27 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 30295455,
            "unit": "ops/sec",
            "extra": "Latency: 33.0 ns/op, Bandwidth: 7396.35 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 25423568,
            "unit": "ops/sec",
            "extra": "Latency: 39.3 ns/op, Bandwidth: 24827.70 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 32427375,
            "unit": "ops/sec",
            "extra": "Latency: 30.8 ns/op, Bandwidth: 123.70 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 31672659,
            "unit": "ops/sec",
            "extra": "Latency: 31.6 ns/op, Bandwidth: 1933.15 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 26419193,
            "unit": "ops/sec",
            "extra": "Latency: 37.9 ns/op, Bandwidth: 6450.00 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 22251725,
            "unit": "ops/sec",
            "extra": "Latency: 44.9 ns/op, Bandwidth: 21730.20 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 5986054,
            "unit": "ops/sec",
            "extra": "Latency: 167.1 ns/op, Bandwidth: 22.83 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 5977181,
            "unit": "ops/sec",
            "extra": "Latency: 167.3 ns/op, Bandwidth: 364.82 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 4579635,
            "unit": "ops/sec",
            "extra": "Latency: 218.4 ns/op, Bandwidth: 1118.07 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 5485307,
            "unit": "ops/sec",
            "extra": "Latency: 182.3 ns/op, Bandwidth: 20.92 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 5171903,
            "unit": "ops/sec",
            "extra": "Latency: 193.4 ns/op, Bandwidth: 315.67 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 3855074,
            "unit": "ops/sec",
            "extra": "Latency: 259.4 ns/op, Bandwidth: 941.18 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 13139394,
            "unit": "ops/sec",
            "extra": "Latency: 76.1 ns/op, Bandwidth: 50.12 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 12818083,
            "unit": "ops/sec",
            "extra": "Latency: 78.0 ns/op, Bandwidth: 782.35 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 11066326,
            "unit": "ops/sec",
            "extra": "Latency: 90.4 ns/op, Bandwidth: 2701.74 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 7003517,
            "unit": "ops/sec",
            "extra": "Latency: 142.8 ns/op, Bandwidth: 6839.37 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "8a5b62a95094347c1dbb0dc4bbdd601d05d0fb67",
          "message": "docs: update README",
          "timestamp": "2026-04-29T16:35:27Z",
          "tree_id": "2218743e968262b45fde7efefbe8a8a06daeb049",
          "url": "https://github.com/ShenChen1/ufifo/commit/8a5b62a95094347c1dbb0dc4bbdd601d05d0fb67"
        },
        "date": 1777480575954,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 38789382,
            "unit": "ops/sec",
            "extra": "Latency: 25.8 ns/op, Bandwidth: 147.97 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 38276727,
            "unit": "ops/sec",
            "extra": "Latency: 26.1 ns/op, Bandwidth: 2336.23 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 30491535,
            "unit": "ops/sec",
            "extra": "Latency: 32.8 ns/op, Bandwidth: 7444.22 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 26310682,
            "unit": "ops/sec",
            "extra": "Latency: 38.0 ns/op, Bandwidth: 25694.03 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 11469989,
            "unit": "ops/sec",
            "extra": "Latency: 87.2 ns/op, Bandwidth: 44804.65 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 29891183,
            "unit": "ops/sec",
            "extra": "Latency: 33.5 ns/op, Bandwidth: 114.03 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 32202024,
            "unit": "ops/sec",
            "extra": "Latency: 31.1 ns/op, Bandwidth: 1965.46 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 25753687,
            "unit": "ops/sec",
            "extra": "Latency: 38.8 ns/op, Bandwidth: 6287.52 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 22654386,
            "unit": "ops/sec",
            "extra": "Latency: 44.1 ns/op, Bandwidth: 22123.42 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 11262180,
            "unit": "ops/sec",
            "extra": "Latency: 88.8 ns/op, Bandwidth: 43992.89 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 28994079,
            "unit": "ops/sec",
            "extra": "Latency: 34.5 ns/op, Bandwidth: 110.60 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 22798005,
            "unit": "ops/sec",
            "extra": "Latency: 43.9 ns/op, Bandwidth: 1391.48 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 18309516,
            "unit": "ops/sec",
            "extra": "Latency: 54.6 ns/op, Bandwidth: 4470.10 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 14252502,
            "unit": "ops/sec",
            "extra": "Latency: 70.2 ns/op, Bandwidth: 13918.46 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 8373618,
            "unit": "ops/sec",
            "extra": "Latency: 119.4 ns/op, Bandwidth: 31.94 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 8487180,
            "unit": "ops/sec",
            "extra": "Latency: 117.8 ns/op, Bandwidth: 518.02 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 5855388,
            "unit": "ops/sec",
            "extra": "Latency: 170.8 ns/op, Bandwidth: 1429.54 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 3803076,
            "unit": "ops/sec",
            "extra": "Latency: 262.9 ns/op, Bandwidth: 3713.94 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 37516027,
            "unit": "ops/sec",
            "extra": "Latency: 26.7 ns/op, Bandwidth: 143.11 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 33338039,
            "unit": "ops/sec",
            "extra": "Latency: 30.0 ns/op, Bandwidth: 2034.79 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 30341571,
            "unit": "ops/sec",
            "extra": "Latency: 33.0 ns/op, Bandwidth: 7407.61 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 25780554,
            "unit": "ops/sec",
            "extra": "Latency: 38.8 ns/op, Bandwidth: 25176.32 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 32270693,
            "unit": "ops/sec",
            "extra": "Latency: 31.0 ns/op, Bandwidth: 123.10 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 32335470,
            "unit": "ops/sec",
            "extra": "Latency: 30.9 ns/op, Bandwidth: 1973.60 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 26407731,
            "unit": "ops/sec",
            "extra": "Latency: 37.9 ns/op, Bandwidth: 6447.20 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 22875138,
            "unit": "ops/sec",
            "extra": "Latency: 43.7 ns/op, Bandwidth: 22339.00 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 8821392,
            "unit": "ops/sec",
            "extra": "Latency: 113.4 ns/op, Bandwidth: 33.65 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 6521232,
            "unit": "ops/sec",
            "extra": "Latency: 153.3 ns/op, Bandwidth: 398.02 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 4418216,
            "unit": "ops/sec",
            "extra": "Latency: 226.3 ns/op, Bandwidth: 1078.67 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 5279730,
            "unit": "ops/sec",
            "extra": "Latency: 189.4 ns/op, Bandwidth: 20.14 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 5029370,
            "unit": "ops/sec",
            "extra": "Latency: 198.8 ns/op, Bandwidth: 306.97 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 3976581,
            "unit": "ops/sec",
            "extra": "Latency: 251.5 ns/op, Bandwidth: 970.84 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 13912560,
            "unit": "ops/sec",
            "extra": "Latency: 71.9 ns/op, Bandwidth: 53.07 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 13409060,
            "unit": "ops/sec",
            "extra": "Latency: 74.6 ns/op, Bandwidth: 818.42 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 12359212,
            "unit": "ops/sec",
            "extra": "Latency: 80.9 ns/op, Bandwidth: 3017.39 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 8294216,
            "unit": "ops/sec",
            "extra": "Latency: 120.6 ns/op, Bandwidth: 8099.82 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "c05d9e204d1b70d2835e732c836c93072511dfdc",
          "message": "docs: update README",
          "timestamp": "2026-04-29T16:41:19Z",
          "tree_id": "ad3bc25a05ac7af8846b5519711fc461394d4035",
          "url": "https://github.com/ShenChen1/ufifo/commit/c05d9e204d1b70d2835e732c836c93072511dfdc"
        },
        "date": 1777480933286,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 29706075,
            "unit": "ops/sec",
            "extra": "Latency: 33.7 ns/op, Bandwidth: 113.32 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 30088941,
            "unit": "ops/sec",
            "extra": "Latency: 33.2 ns/op, Bandwidth: 1836.48 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 25267588,
            "unit": "ops/sec",
            "extra": "Latency: 39.6 ns/op, Bandwidth: 6168.84 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 22400497,
            "unit": "ops/sec",
            "extra": "Latency: 44.6 ns/op, Bandwidth: 21875.49 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 13337565,
            "unit": "ops/sec",
            "extra": "Latency: 75.0 ns/op, Bandwidth: 52099.86 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 18914091,
            "unit": "ops/sec",
            "extra": "Latency: 52.9 ns/op, Bandwidth: 72.15 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 19724506,
            "unit": "ops/sec",
            "extra": "Latency: 50.7 ns/op, Bandwidth: 1203.89 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 18498991,
            "unit": "ops/sec",
            "extra": "Latency: 54.1 ns/op, Bandwidth: 4516.36 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 16734757,
            "unit": "ops/sec",
            "extra": "Latency: 59.8 ns/op, Bandwidth: 16342.54 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 10297339,
            "unit": "ops/sec",
            "extra": "Latency: 97.1 ns/op, Bandwidth: 40223.98 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 10613592,
            "unit": "ops/sec",
            "extra": "Latency: 94.2 ns/op, Bandwidth: 40.49 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 9493291,
            "unit": "ops/sec",
            "extra": "Latency: 105.3 ns/op, Bandwidth: 579.42 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 12547100,
            "unit": "ops/sec",
            "extra": "Latency: 79.7 ns/op, Bandwidth: 3063.26 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 9267252,
            "unit": "ops/sec",
            "extra": "Latency: 107.9 ns/op, Bandwidth: 9050.05 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 3160792,
            "unit": "ops/sec",
            "extra": "Latency: 316.4 ns/op, Bandwidth: 12.06 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 3259849,
            "unit": "ops/sec",
            "extra": "Latency: 306.8 ns/op, Bandwidth: 198.97 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 3721248,
            "unit": "ops/sec",
            "extra": "Latency: 268.7 ns/op, Bandwidth: 908.51 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 1967854,
            "unit": "ops/sec",
            "extra": "Latency: 508.2 ns/op, Bandwidth: 1921.73 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 29655951,
            "unit": "ops/sec",
            "extra": "Latency: 33.7 ns/op, Bandwidth: 113.13 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 30174965,
            "unit": "ops/sec",
            "extra": "Latency: 33.1 ns/op, Bandwidth: 1841.73 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 25092746,
            "unit": "ops/sec",
            "extra": "Latency: 39.9 ns/op, Bandwidth: 6126.16 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 21422067,
            "unit": "ops/sec",
            "extra": "Latency: 46.7 ns/op, Bandwidth: 20919.99 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 19702661,
            "unit": "ops/sec",
            "extra": "Latency: 50.8 ns/op, Bandwidth: 75.16 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 19788365,
            "unit": "ops/sec",
            "extra": "Latency: 50.5 ns/op, Bandwidth: 1207.79 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 18418137,
            "unit": "ops/sec",
            "extra": "Latency: 54.3 ns/op, Bandwidth: 4496.62 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 16474989,
            "unit": "ops/sec",
            "extra": "Latency: 60.7 ns/op, Bandwidth: 16088.86 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 3885396,
            "unit": "ops/sec",
            "extra": "Latency: 257.4 ns/op, Bandwidth: 14.82 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 2789485,
            "unit": "ops/sec",
            "extra": "Latency: 358.5 ns/op, Bandwidth: 170.26 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 3332504,
            "unit": "ops/sec",
            "extra": "Latency: 300.1 ns/op, Bandwidth: 813.60 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 3110505,
            "unit": "ops/sec",
            "extra": "Latency: 321.5 ns/op, Bandwidth: 11.87 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 2720145,
            "unit": "ops/sec",
            "extra": "Latency: 367.6 ns/op, Bandwidth: 166.02 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 2526910,
            "unit": "ops/sec",
            "extra": "Latency: 395.7 ns/op, Bandwidth: 616.92 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 5940230,
            "unit": "ops/sec",
            "extra": "Latency: 168.3 ns/op, Bandwidth: 22.66 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 7121859,
            "unit": "ops/sec",
            "extra": "Latency: 140.4 ns/op, Bandwidth: 434.68 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 5964152,
            "unit": "ops/sec",
            "extra": "Latency: 167.7 ns/op, Bandwidth: 1456.09 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 3411677,
            "unit": "ops/sec",
            "extra": "Latency: 293.1 ns/op, Bandwidth: 3331.72 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "c05d9e204d1b70d2835e732c836c93072511dfdc",
          "message": "docs: update README",
          "timestamp": "2026-04-29T16:41:19Z",
          "tree_id": "ad3bc25a05ac7af8846b5519711fc461394d4035",
          "url": "https://github.com/ShenChen1/ufifo/commit/c05d9e204d1b70d2835e732c836c93072511dfdc"
        },
        "date": 1777481205312,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 38860805,
            "unit": "ops/sec",
            "extra": "Latency: 25.7 ns/op, Bandwidth: 148.24 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 38764229,
            "unit": "ops/sec",
            "extra": "Latency: 25.8 ns/op, Bandwidth: 2365.98 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 30611687,
            "unit": "ops/sec",
            "extra": "Latency: 32.7 ns/op, Bandwidth: 7473.56 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 26254376,
            "unit": "ops/sec",
            "extra": "Latency: 38.1 ns/op, Bandwidth: 25639.04 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 12584460,
            "unit": "ops/sec",
            "extra": "Latency: 79.5 ns/op, Bandwidth: 49158.05 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 32618200,
            "unit": "ops/sec",
            "extra": "Latency: 30.7 ns/op, Bandwidth: 124.43 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 32625424,
            "unit": "ops/sec",
            "extra": "Latency: 30.7 ns/op, Bandwidth: 1991.30 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 26628888,
            "unit": "ops/sec",
            "extra": "Latency: 37.6 ns/op, Bandwidth: 6501.19 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 23177449,
            "unit": "ops/sec",
            "extra": "Latency: 43.1 ns/op, Bandwidth: 22634.23 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 11839271,
            "unit": "ops/sec",
            "extra": "Latency: 84.5 ns/op, Bandwidth: 46247.15 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 26455012,
            "unit": "ops/sec",
            "extra": "Latency: 37.8 ns/op, Bandwidth: 100.92 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 23201932,
            "unit": "ops/sec",
            "extra": "Latency: 43.1 ns/op, Bandwidth: 1416.13 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 18602993,
            "unit": "ops/sec",
            "extra": "Latency: 53.8 ns/op, Bandwidth: 4541.75 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 13506979,
            "unit": "ops/sec",
            "extra": "Latency: 74.0 ns/op, Bandwidth: 13190.41 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 7531105,
            "unit": "ops/sec",
            "extra": "Latency: 132.8 ns/op, Bandwidth: 28.73 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 8637297,
            "unit": "ops/sec",
            "extra": "Latency: 115.8 ns/op, Bandwidth: 527.18 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 5896053,
            "unit": "ops/sec",
            "extra": "Latency: 169.6 ns/op, Bandwidth: 1439.47 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 3444732,
            "unit": "ops/sec",
            "extra": "Latency: 290.3 ns/op, Bandwidth: 3364.00 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 38436831,
            "unit": "ops/sec",
            "extra": "Latency: 26.0 ns/op, Bandwidth: 146.62 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 38128594,
            "unit": "ops/sec",
            "extra": "Latency: 26.2 ns/op, Bandwidth: 2327.18 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 30320198,
            "unit": "ops/sec",
            "extra": "Latency: 33.0 ns/op, Bandwidth: 7402.39 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 25986392,
            "unit": "ops/sec",
            "extra": "Latency: 38.5 ns/op, Bandwidth: 25377.34 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 32534952,
            "unit": "ops/sec",
            "extra": "Latency: 30.7 ns/op, Bandwidth: 124.11 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 32341771,
            "unit": "ops/sec",
            "extra": "Latency: 30.9 ns/op, Bandwidth: 1973.99 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 26471684,
            "unit": "ops/sec",
            "extra": "Latency: 37.8 ns/op, Bandwidth: 6462.81 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 23085200,
            "unit": "ops/sec",
            "extra": "Latency: 43.3 ns/op, Bandwidth: 22544.14 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 6325096,
            "unit": "ops/sec",
            "extra": "Latency: 158.1 ns/op, Bandwidth: 24.13 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 6549865,
            "unit": "ops/sec",
            "extra": "Latency: 152.7 ns/op, Bandwidth: 399.77 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 4312363,
            "unit": "ops/sec",
            "extra": "Latency: 231.9 ns/op, Bandwidth: 1052.82 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 5505381,
            "unit": "ops/sec",
            "extra": "Latency: 181.6 ns/op, Bandwidth: 21.00 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 5076670,
            "unit": "ops/sec",
            "extra": "Latency: 197.0 ns/op, Bandwidth: 309.86 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 3847785,
            "unit": "ops/sec",
            "extra": "Latency: 259.9 ns/op, Bandwidth: 939.40 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 13819788,
            "unit": "ops/sec",
            "extra": "Latency: 72.4 ns/op, Bandwidth: 52.72 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 12925162,
            "unit": "ops/sec",
            "extra": "Latency: 77.4 ns/op, Bandwidth: 788.89 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 10865998,
            "unit": "ops/sec",
            "extra": "Latency: 92.0 ns/op, Bandwidth: 2652.83 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 7180944,
            "unit": "ops/sec",
            "extra": "Latency: 139.3 ns/op, Bandwidth: 7012.64 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "986c2801f46479044300137eff479edf2ecf4bfd",
          "message": "perf: cache min_out in shared memory for O(1) fast path\n\n- Introduce `cached_min_out` in shared control block to avoid iterating over all readers to calculate `min_out` on every operation in shared mode.\n- Extract eventfd notification logic into `__ufifo_efd_notify` and handle `EAGAIN` correctly in `read()`.\n- Wake up the background broker daemon explicitly using `__ufifo_broker_wake_to_exit` during `ufifo_close` to prevent it from hanging in `accept()`.\n- Fix child processes in `ufifo_test.cpp` to use `_exit()` instead of `exit()` to avoid triggering `atexit` handlers that mess with shared resources.\n- Fix `UfifoTestAdapter::Detach` to correctly identify and `ufifo_destroy` only the last remaining handle.\n- Add `atomic_cmpxchg` macro to `utils.h` for lock-free updates.",
          "timestamp": "2026-05-01T16:10:05Z",
          "tree_id": "cf58aeca3ab9c9d71e8ad69b06fa17469bd6488d",
          "url": "https://github.com/ShenChen1/ufifo/commit/986c2801f46479044300137eff479edf2ecf4bfd"
        },
        "date": 1777652194980,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 36641456,
            "unit": "ops/sec",
            "extra": "Latency: 27.3 ns/op, Bandwidth: 139.78 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 36330242,
            "unit": "ops/sec",
            "extra": "Latency: 27.5 ns/op, Bandwidth: 2217.42 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 29220062,
            "unit": "ops/sec",
            "extra": "Latency: 34.2 ns/op, Bandwidth: 7133.80 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 25132173,
            "unit": "ops/sec",
            "extra": "Latency: 39.8 ns/op, Bandwidth: 24543.14 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 12001411,
            "unit": "ops/sec",
            "extra": "Latency: 83.3 ns/op, Bandwidth: 46880.51 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 30981776,
            "unit": "ops/sec",
            "extra": "Latency: 32.3 ns/op, Bandwidth: 118.19 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 30977409,
            "unit": "ops/sec",
            "extra": "Latency: 32.3 ns/op, Bandwidth: 1890.71 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 25454303,
            "unit": "ops/sec",
            "extra": "Latency: 39.3 ns/op, Bandwidth: 6214.43 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 22342697,
            "unit": "ops/sec",
            "extra": "Latency: 44.8 ns/op, Bandwidth: 21819.04 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 11359450,
            "unit": "ops/sec",
            "extra": "Latency: 88.0 ns/op, Bandwidth: 44372.85 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 29607772,
            "unit": "ops/sec",
            "extra": "Latency: 33.8 ns/op, Bandwidth: 112.94 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 34363329,
            "unit": "ops/sec",
            "extra": "Latency: 29.1 ns/op, Bandwidth: 2097.37 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 21410679,
            "unit": "ops/sec",
            "extra": "Latency: 46.7 ns/op, Bandwidth: 5227.22 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 13640884,
            "unit": "ops/sec",
            "extra": "Latency: 73.3 ns/op, Bandwidth: 13321.18 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 7994766,
            "unit": "ops/sec",
            "extra": "Latency: 125.1 ns/op, Bandwidth: 30.50 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 7356508,
            "unit": "ops/sec",
            "extra": "Latency: 135.9 ns/op, Bandwidth: 449.01 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 5319247,
            "unit": "ops/sec",
            "extra": "Latency: 188.0 ns/op, Bandwidth: 1298.64 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 3199911,
            "unit": "ops/sec",
            "extra": "Latency: 312.5 ns/op, Bandwidth: 3124.91 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 36908295,
            "unit": "ops/sec",
            "extra": "Latency: 27.1 ns/op, Bandwidth: 140.79 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 36133255,
            "unit": "ops/sec",
            "extra": "Latency: 27.7 ns/op, Bandwidth: 2205.40 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 29271108,
            "unit": "ops/sec",
            "extra": "Latency: 34.2 ns/op, Bandwidth: 7146.27 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 24990726,
            "unit": "ops/sec",
            "extra": "Latency: 40.0 ns/op, Bandwidth: 24405.01 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 30626806,
            "unit": "ops/sec",
            "extra": "Latency: 32.7 ns/op, Bandwidth: 116.83 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 30504707,
            "unit": "ops/sec",
            "extra": "Latency: 32.8 ns/op, Bandwidth: 1861.86 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 25273682,
            "unit": "ops/sec",
            "extra": "Latency: 39.6 ns/op, Bandwidth: 6170.33 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 22177514,
            "unit": "ops/sec",
            "extra": "Latency: 45.1 ns/op, Bandwidth: 21657.73 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 5266774,
            "unit": "ops/sec",
            "extra": "Latency: 189.9 ns/op, Bandwidth: 20.09 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 5293688,
            "unit": "ops/sec",
            "extra": "Latency: 188.9 ns/op, Bandwidth: 323.10 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 4136541,
            "unit": "ops/sec",
            "extra": "Latency: 241.7 ns/op, Bandwidth: 1009.90 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 4768403,
            "unit": "ops/sec",
            "extra": "Latency: 209.7 ns/op, Bandwidth: 18.19 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 4708974,
            "unit": "ops/sec",
            "extra": "Latency: 212.4 ns/op, Bandwidth: 287.41 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 3862998,
            "unit": "ops/sec",
            "extra": "Latency: 258.9 ns/op, Bandwidth: 943.11 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 12156157,
            "unit": "ops/sec",
            "extra": "Latency: 82.3 ns/op, Bandwidth: 46.37 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 11735395,
            "unit": "ops/sec",
            "extra": "Latency: 85.2 ns/op, Bandwidth: 716.27 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 10781513,
            "unit": "ops/sec",
            "extra": "Latency: 92.8 ns/op, Bandwidth: 2632.21 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 7222379,
            "unit": "ops/sec",
            "extra": "Latency: 138.5 ns/op, Bandwidth: 7053.10 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "7cae47791394f63ebd0bfc59db1044aa5716eb2d",
          "message": "test: fix double-destroy in ~UfifoTestAdapter causing TSan errors",
          "timestamp": "2026-05-01T16:44:21Z",
          "tree_id": "f6dbdd99a37753d9a3d9fa7abc1cabbe4647d4fc",
          "url": "https://github.com/ShenChen1/ufifo/commit/7cae47791394f63ebd0bfc59db1044aa5716eb2d"
        },
        "date": 1777653922522,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 29072649,
            "unit": "ops/sec",
            "extra": "Latency: 34.4 ns/op, Bandwidth: 110.90 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 28841788,
            "unit": "ops/sec",
            "extra": "Latency: 34.7 ns/op, Bandwidth: 1760.36 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 24715773,
            "unit": "ops/sec",
            "extra": "Latency: 40.5 ns/op, Bandwidth: 6034.12 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 21671011,
            "unit": "ops/sec",
            "extra": "Latency: 46.1 ns/op, Bandwidth: 21163.10 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 13186674,
            "unit": "ops/sec",
            "extra": "Latency: 75.8 ns/op, Bandwidth: 51510.44 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 20766432,
            "unit": "ops/sec",
            "extra": "Latency: 48.2 ns/op, Bandwidth: 79.22 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 20500506,
            "unit": "ops/sec",
            "extra": "Latency: 48.8 ns/op, Bandwidth: 1251.25 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 20145109,
            "unit": "ops/sec",
            "extra": "Latency: 49.6 ns/op, Bandwidth: 4918.24 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 18403538,
            "unit": "ops/sec",
            "extra": "Latency: 54.3 ns/op, Bandwidth: 17972.21 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 10828497,
            "unit": "ops/sec",
            "extra": "Latency: 92.3 ns/op, Bandwidth: 42298.82 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 9898658,
            "unit": "ops/sec",
            "extra": "Latency: 101.0 ns/op, Bandwidth: 37.76 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 9978477,
            "unit": "ops/sec",
            "extra": "Latency: 100.2 ns/op, Bandwidth: 609.04 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 12037615,
            "unit": "ops/sec",
            "extra": "Latency: 83.1 ns/op, Bandwidth: 2938.87 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 9911645,
            "unit": "ops/sec",
            "extra": "Latency: 100.9 ns/op, Bandwidth: 9679.34 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 3285116,
            "unit": "ops/sec",
            "extra": "Latency: 304.4 ns/op, Bandwidth: 12.53 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 3499015,
            "unit": "ops/sec",
            "extra": "Latency: 285.8 ns/op, Bandwidth: 213.56 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 3405224,
            "unit": "ops/sec",
            "extra": "Latency: 293.7 ns/op, Bandwidth: 831.35 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 2098061,
            "unit": "ops/sec",
            "extra": "Latency: 476.6 ns/op, Bandwidth: 2048.89 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 29177393,
            "unit": "ops/sec",
            "extra": "Latency: 34.3 ns/op, Bandwidth: 111.30 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 29606353,
            "unit": "ops/sec",
            "extra": "Latency: 33.8 ns/op, Bandwidth: 1807.03 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 24788457,
            "unit": "ops/sec",
            "extra": "Latency: 40.3 ns/op, Bandwidth: 6051.87 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 21056637,
            "unit": "ops/sec",
            "extra": "Latency: 47.5 ns/op, Bandwidth: 20563.12 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 21102412,
            "unit": "ops/sec",
            "extra": "Latency: 47.4 ns/op, Bandwidth: 80.50 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 21115425,
            "unit": "ops/sec",
            "extra": "Latency: 47.4 ns/op, Bandwidth: 1288.78 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 19944178,
            "unit": "ops/sec",
            "extra": "Latency: 50.1 ns/op, Bandwidth: 4869.18 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 17834989,
            "unit": "ops/sec",
            "extra": "Latency: 56.1 ns/op, Bandwidth: 17416.98 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 3476380,
            "unit": "ops/sec",
            "extra": "Latency: 287.7 ns/op, Bandwidth: 13.26 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 2910862,
            "unit": "ops/sec",
            "extra": "Latency: 343.5 ns/op, Bandwidth: 177.66 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 3247338,
            "unit": "ops/sec",
            "extra": "Latency: 307.9 ns/op, Bandwidth: 792.81 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 2859975,
            "unit": "ops/sec",
            "extra": "Latency: 349.7 ns/op, Bandwidth: 10.91 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 2431560,
            "unit": "ops/sec",
            "extra": "Latency: 411.3 ns/op, Bandwidth: 148.41 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 2714018,
            "unit": "ops/sec",
            "extra": "Latency: 368.5 ns/op, Bandwidth: 662.60 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 6438668,
            "unit": "ops/sec",
            "extra": "Latency: 155.3 ns/op, Bandwidth: 24.56 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 6589042,
            "unit": "ops/sec",
            "extra": "Latency: 151.8 ns/op, Bandwidth: 402.16 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 5480856,
            "unit": "ops/sec",
            "extra": "Latency: 182.5 ns/op, Bandwidth: 1338.10 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 3560717,
            "unit": "ops/sec",
            "extra": "Latency: 280.8 ns/op, Bandwidth: 3477.26 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "7cae47791394f63ebd0bfc59db1044aa5716eb2d",
          "message": "test: fix double-destroy in ~UfifoTestAdapter causing TSan errors",
          "timestamp": "2026-05-01T16:44:21Z",
          "tree_id": "f6dbdd99a37753d9a3d9fa7abc1cabbe4647d4fc",
          "url": "https://github.com/ShenChen1/ufifo/commit/7cae47791394f63ebd0bfc59db1044aa5716eb2d"
        },
        "date": 1777654139902,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 46596021,
            "unit": "ops/sec",
            "extra": "Latency: 21.5 ns/op, Bandwidth: 177.75 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 46824542,
            "unit": "ops/sec",
            "extra": "Latency: 21.4 ns/op, Bandwidth: 2857.94 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 30664757,
            "unit": "ops/sec",
            "extra": "Latency: 32.6 ns/op, Bandwidth: 7486.51 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 25676012,
            "unit": "ops/sec",
            "extra": "Latency: 38.9 ns/op, Bandwidth: 25074.23 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 13347140,
            "unit": "ops/sec",
            "extra": "Latency: 74.9 ns/op, Bandwidth: 52137.27 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 35664905,
            "unit": "ops/sec",
            "extra": "Latency: 28.0 ns/op, Bandwidth: 136.05 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 39237017,
            "unit": "ops/sec",
            "extra": "Latency: 25.5 ns/op, Bandwidth: 2394.84 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 27043940,
            "unit": "ops/sec",
            "extra": "Latency: 37.0 ns/op, Bandwidth: 6602.52 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 22824743,
            "unit": "ops/sec",
            "extra": "Latency: 43.8 ns/op, Bandwidth: 22289.79 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 12674486,
            "unit": "ops/sec",
            "extra": "Latency: 78.9 ns/op, Bandwidth: 49509.71 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 16384918,
            "unit": "ops/sec",
            "extra": "Latency: 61.0 ns/op, Bandwidth: 62.50 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 17936119,
            "unit": "ops/sec",
            "extra": "Latency: 55.8 ns/op, Bandwidth: 1094.73 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 16084868,
            "unit": "ops/sec",
            "extra": "Latency: 62.2 ns/op, Bandwidth: 3926.97 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 8128427,
            "unit": "ops/sec",
            "extra": "Latency: 123.0 ns/op, Bandwidth: 7937.92 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 9828015,
            "unit": "ops/sec",
            "extra": "Latency: 101.7 ns/op, Bandwidth: 37.49 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 7670576,
            "unit": "ops/sec",
            "extra": "Latency: 130.4 ns/op, Bandwidth: 468.17 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 5634319,
            "unit": "ops/sec",
            "extra": "Latency: 177.5 ns/op, Bandwidth: 1375.57 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 2528110,
            "unit": "ops/sec",
            "extra": "Latency: 395.6 ns/op, Bandwidth: 2468.86 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 46440098,
            "unit": "ops/sec",
            "extra": "Latency: 21.5 ns/op, Bandwidth: 177.15 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 46590803,
            "unit": "ops/sec",
            "extra": "Latency: 21.5 ns/op, Bandwidth: 2843.68 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 30643033,
            "unit": "ops/sec",
            "extra": "Latency: 32.6 ns/op, Bandwidth: 7481.21 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 25281713,
            "unit": "ops/sec",
            "extra": "Latency: 39.6 ns/op, Bandwidth: 24689.17 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 38460049,
            "unit": "ops/sec",
            "extra": "Latency: 26.0 ns/op, Bandwidth: 146.71 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 39304122,
            "unit": "ops/sec",
            "extra": "Latency: 25.4 ns/op, Bandwidth: 2398.93 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 26779010,
            "unit": "ops/sec",
            "extra": "Latency: 37.3 ns/op, Bandwidth: 6537.84 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 22088743,
            "unit": "ops/sec",
            "extra": "Latency: 45.3 ns/op, Bandwidth: 21571.04 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 6061253,
            "unit": "ops/sec",
            "extra": "Latency: 165.0 ns/op, Bandwidth: 23.12 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 5227660,
            "unit": "ops/sec",
            "extra": "Latency: 191.3 ns/op, Bandwidth: 319.07 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 4430609,
            "unit": "ops/sec",
            "extra": "Latency: 225.7 ns/op, Bandwidth: 1081.69 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 5128869,
            "unit": "ops/sec",
            "extra": "Latency: 195.0 ns/op, Bandwidth: 19.57 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 4892368,
            "unit": "ops/sec",
            "extra": "Latency: 204.4 ns/op, Bandwidth: 298.61 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 3622179,
            "unit": "ops/sec",
            "extra": "Latency: 276.1 ns/op, Bandwidth: 884.32 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 12309929,
            "unit": "ops/sec",
            "extra": "Latency: 81.2 ns/op, Bandwidth: 46.96 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 11100713,
            "unit": "ops/sec",
            "extra": "Latency: 90.1 ns/op, Bandwidth: 677.53 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 9408521,
            "unit": "ops/sec",
            "extra": "Latency: 106.3 ns/op, Bandwidth: 2297.00 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 5321277,
            "unit": "ops/sec",
            "extra": "Latency: 187.9 ns/op, Bandwidth: 5196.56 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "7cae47791394f63ebd0bfc59db1044aa5716eb2d",
          "message": "test: fix double-destroy in ~UfifoTestAdapter causing TSan errors",
          "timestamp": "2026-05-01T16:44:21Z",
          "tree_id": "f6dbdd99a37753d9a3d9fa7abc1cabbe4647d4fc",
          "url": "https://github.com/ShenChen1/ufifo/commit/7cae47791394f63ebd0bfc59db1044aa5716eb2d"
        },
        "date": 1777654253001,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 36890769,
            "unit": "ops/sec",
            "extra": "Latency: 27.1 ns/op, Bandwidth: 140.73 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 36237047,
            "unit": "ops/sec",
            "extra": "Latency: 27.6 ns/op, Bandwidth: 2211.73 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 29323067,
            "unit": "ops/sec",
            "extra": "Latency: 34.1 ns/op, Bandwidth: 7158.95 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 25233934,
            "unit": "ops/sec",
            "extra": "Latency: 39.6 ns/op, Bandwidth: 24642.51 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 12410093,
            "unit": "ops/sec",
            "extra": "Latency: 80.6 ns/op, Bandwidth: 48476.93 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 30974504,
            "unit": "ops/sec",
            "extra": "Latency: 32.3 ns/op, Bandwidth: 118.16 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 30834369,
            "unit": "ops/sec",
            "extra": "Latency: 32.4 ns/op, Bandwidth: 1881.98 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 25503832,
            "unit": "ops/sec",
            "extra": "Latency: 39.2 ns/op, Bandwidth: 6226.52 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 22450098,
            "unit": "ops/sec",
            "extra": "Latency: 44.5 ns/op, Bandwidth: 21923.92 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 11638325,
            "unit": "ops/sec",
            "extra": "Latency: 85.9 ns/op, Bandwidth: 45462.21 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 31635936,
            "unit": "ops/sec",
            "extra": "Latency: 31.6 ns/op, Bandwidth: 120.68 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 32036819,
            "unit": "ops/sec",
            "extra": "Latency: 31.2 ns/op, Bandwidth: 1955.37 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 22095762,
            "unit": "ops/sec",
            "extra": "Latency: 45.3 ns/op, Bandwidth: 5394.47 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 12951254,
            "unit": "ops/sec",
            "extra": "Latency: 77.2 ns/op, Bandwidth: 12647.71 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 8027952,
            "unit": "ops/sec",
            "extra": "Latency: 124.6 ns/op, Bandwidth: 30.62 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 8179804,
            "unit": "ops/sec",
            "extra": "Latency: 122.3 ns/op, Bandwidth: 499.26 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 5764990,
            "unit": "ops/sec",
            "extra": "Latency: 173.5 ns/op, Bandwidth: 1407.47 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 3791220,
            "unit": "ops/sec",
            "extra": "Latency: 263.8 ns/op, Bandwidth: 3702.36 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 37019124,
            "unit": "ops/sec",
            "extra": "Latency: 27.0 ns/op, Bandwidth: 141.22 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 36025397,
            "unit": "ops/sec",
            "extra": "Latency: 27.8 ns/op, Bandwidth: 2198.82 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 29296882,
            "unit": "ops/sec",
            "extra": "Latency: 34.1 ns/op, Bandwidth: 7152.56 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 25045941,
            "unit": "ops/sec",
            "extra": "Latency: 39.9 ns/op, Bandwidth: 24458.93 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 30541330,
            "unit": "ops/sec",
            "extra": "Latency: 32.7 ns/op, Bandwidth: 116.51 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 30567520,
            "unit": "ops/sec",
            "extra": "Latency: 32.7 ns/op, Bandwidth: 1865.69 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 25317220,
            "unit": "ops/sec",
            "extra": "Latency: 39.5 ns/op, Bandwidth: 6180.96 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 22274305,
            "unit": "ops/sec",
            "extra": "Latency: 44.9 ns/op, Bandwidth: 21752.25 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 5645121,
            "unit": "ops/sec",
            "extra": "Latency: 177.1 ns/op, Bandwidth: 21.53 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 6160956,
            "unit": "ops/sec",
            "extra": "Latency: 162.3 ns/op, Bandwidth: 376.03 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 3876990,
            "unit": "ops/sec",
            "extra": "Latency: 257.9 ns/op, Bandwidth: 946.53 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 4903099,
            "unit": "ops/sec",
            "extra": "Latency: 204.0 ns/op, Bandwidth: 18.70 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 4736423,
            "unit": "ops/sec",
            "extra": "Latency: 211.1 ns/op, Bandwidth: 289.09 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 3711060,
            "unit": "ops/sec",
            "extra": "Latency: 269.5 ns/op, Bandwidth: 906.02 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 13815846,
            "unit": "ops/sec",
            "extra": "Latency: 72.4 ns/op, Bandwidth: 52.70 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 11696622,
            "unit": "ops/sec",
            "extra": "Latency: 85.5 ns/op, Bandwidth: 713.91 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 11140529,
            "unit": "ops/sec",
            "extra": "Latency: 89.8 ns/op, Bandwidth: 2719.86 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 7606749,
            "unit": "ops/sec",
            "extra": "Latency: 131.5 ns/op, Bandwidth: 7428.47 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "a93f94ea6297e5e6cfff9a40834ccf31c998d381",
          "message": "perf: micro-optimize hot paths to improve lockless throughput\n\n- Avoid unconditional atomic_xchg in __ufifo_efd_notify to reduce cache-line bouncing.\n- Inline __ufifo_is_shared to remove call overhead in the fast path.\n- Add and use __builtin_expect (likely/unlikely) hints for hook checks in get/put.",
          "timestamp": "2026-05-02T17:00:05Z",
          "tree_id": "f66f46a80fc233c76f1b84e7fd7c26558f838e46",
          "url": "https://github.com/ShenChen1/ufifo/commit/a93f94ea6297e5e6cfff9a40834ccf31c998d381"
        },
        "date": 1777741307902,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 38419906,
            "unit": "ops/sec",
            "extra": "Latency: 26.0 ns/op, Bandwidth: 146.56 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 38026618,
            "unit": "ops/sec",
            "extra": "Latency: 26.3 ns/op, Bandwidth: 2320.96 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 30060195,
            "unit": "ops/sec",
            "extra": "Latency: 33.3 ns/op, Bandwidth: 7338.91 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 25874438,
            "unit": "ops/sec",
            "extra": "Latency: 38.6 ns/op, Bandwidth: 25268.01 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 11791578,
            "unit": "ops/sec",
            "extra": "Latency: 84.8 ns/op, Bandwidth: 46060.85 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 32072360,
            "unit": "ops/sec",
            "extra": "Latency: 31.2 ns/op, Bandwidth: 122.35 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 31749348,
            "unit": "ops/sec",
            "extra": "Latency: 31.5 ns/op, Bandwidth: 1937.83 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 26246821,
            "unit": "ops/sec",
            "extra": "Latency: 38.1 ns/op, Bandwidth: 6407.92 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 23041061,
            "unit": "ops/sec",
            "extra": "Latency: 43.4 ns/op, Bandwidth: 22501.04 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 10342771,
            "unit": "ops/sec",
            "extra": "Latency: 96.7 ns/op, Bandwidth: 40401.45 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 38273057,
            "unit": "ops/sec",
            "extra": "Latency: 26.1 ns/op, Bandwidth: 146.00 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 37396880,
            "unit": "ops/sec",
            "extra": "Latency: 26.7 ns/op, Bandwidth: 2282.52 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 28384133,
            "unit": "ops/sec",
            "extra": "Latency: 35.2 ns/op, Bandwidth: 6929.72 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 20395728,
            "unit": "ops/sec",
            "extra": "Latency: 49.0 ns/op, Bandwidth: 19917.70 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 8655427,
            "unit": "ops/sec",
            "extra": "Latency: 115.5 ns/op, Bandwidth: 33.02 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 7796103,
            "unit": "ops/sec",
            "extra": "Latency: 128.3 ns/op, Bandwidth: 475.84 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 5745981,
            "unit": "ops/sec",
            "extra": "Latency: 174.0 ns/op, Bandwidth: 1402.83 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 3408091,
            "unit": "ops/sec",
            "extra": "Latency: 293.4 ns/op, Bandwidth: 3328.21 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 38910356,
            "unit": "ops/sec",
            "extra": "Latency: 25.7 ns/op, Bandwidth: 148.43 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 37908084,
            "unit": "ops/sec",
            "extra": "Latency: 26.4 ns/op, Bandwidth: 2313.73 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 30417398,
            "unit": "ops/sec",
            "extra": "Latency: 32.9 ns/op, Bandwidth: 7426.12 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 25832044,
            "unit": "ops/sec",
            "extra": "Latency: 38.7 ns/op, Bandwidth: 25226.61 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 31965107,
            "unit": "ops/sec",
            "extra": "Latency: 31.3 ns/op, Bandwidth: 121.94 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 31847053,
            "unit": "ops/sec",
            "extra": "Latency: 31.4 ns/op, Bandwidth: 1943.79 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 25985901,
            "unit": "ops/sec",
            "extra": "Latency: 38.5 ns/op, Bandwidth: 6344.21 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 22824816,
            "unit": "ops/sec",
            "extra": "Latency: 43.8 ns/op, Bandwidth: 22289.86 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 9481846,
            "unit": "ops/sec",
            "extra": "Latency: 105.5 ns/op, Bandwidth: 36.17 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 6891976,
            "unit": "ops/sec",
            "extra": "Latency: 145.1 ns/op, Bandwidth: 420.65 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 4686046,
            "unit": "ops/sec",
            "extra": "Latency: 213.4 ns/op, Bandwidth: 1144.05 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 5911053,
            "unit": "ops/sec",
            "extra": "Latency: 169.2 ns/op, Bandwidth: 22.55 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 5249501,
            "unit": "ops/sec",
            "extra": "Latency: 190.5 ns/op, Bandwidth: 320.40 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 4149979,
            "unit": "ops/sec",
            "extra": "Latency: 241.0 ns/op, Bandwidth: 1013.18 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 18014473,
            "unit": "ops/sec",
            "extra": "Latency: 55.5 ns/op, Bandwidth: 68.72 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 17920724,
            "unit": "ops/sec",
            "extra": "Latency: 55.8 ns/op, Bandwidth: 1093.79 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 15078455,
            "unit": "ops/sec",
            "extra": "Latency: 66.3 ns/op, Bandwidth: 3681.26 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 10146978,
            "unit": "ops/sec",
            "extra": "Latency: 98.6 ns/op, Bandwidth: 9909.16 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "sc",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "886e10e2130245ee187e7fe2223dc3de9debb90a",
          "message": "perf: cache config in handle and upgrade memory barriers\n\n- Cache `is_shared` and `lock_type` directly in `ufifo_t` to avoid cache-line bouncing and unnecessary pointer dereferences from shared memory on the hot path.\n- Upgrade `READ_ONCE`/`WRITE_ONCE` to `smp_load_acquire`/`smp_store_release` in `ufifo_epoll.c` and `ufifo_opts.c` to enforce strict acquire-release semantics for lock-free operations.\n- Fix `ufifo_reset` in shared mode to correctly iterate and reset all active consumer `out` cursors.\n- Add assertions in `__ufifo_ctrl_lock` and `__ufifo_data_lock` to abort on unexpected mutex lock failures, preventing silent data corruption.\n- Ensure `lock_type` is correctly initialized in both `__ufifo_init_from_shm` and `__ufifo_init_from_user` attach paths to fix a critical concurrency bug where attached consumers defaulted to `UFIFO_LOCK_NONE`.",
          "timestamp": "2026-05-04T00:08:06+08:00",
          "tree_id": "d6a7200c4df3a66fef01079c765e571f3f6d7928",
          "url": "https://github.com/ShenChen1/ufifo/commit/886e10e2130245ee187e7fe2223dc3de9debb90a"
        },
        "date": 1777824523133,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 39117584,
            "unit": "ops/sec",
            "extra": "Latency: 25.6 ns/op, Bandwidth: 149.22 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 39389150,
            "unit": "ops/sec",
            "extra": "Latency: 25.4 ns/op, Bandwidth: 2404.12 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 30451070,
            "unit": "ops/sec",
            "extra": "Latency: 32.8 ns/op, Bandwidth: 7434.34 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 26045069,
            "unit": "ops/sec",
            "extra": "Latency: 38.4 ns/op, Bandwidth: 25434.64 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 13379930,
            "unit": "ops/sec",
            "extra": "Latency: 74.7 ns/op, Bandwidth: 52265.35 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 32672290,
            "unit": "ops/sec",
            "extra": "Latency: 30.6 ns/op, Bandwidth: 124.63 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 33135905,
            "unit": "ops/sec",
            "extra": "Latency: 30.2 ns/op, Bandwidth: 2022.46 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 26399079,
            "unit": "ops/sec",
            "extra": "Latency: 37.9 ns/op, Bandwidth: 6445.09 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 23253788,
            "unit": "ops/sec",
            "extra": "Latency: 43.0 ns/op, Bandwidth: 22708.78 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 12495053,
            "unit": "ops/sec",
            "extra": "Latency: 80.0 ns/op, Bandwidth: 48808.80 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 35350376,
            "unit": "ops/sec",
            "extra": "Latency: 28.3 ns/op, Bandwidth: 134.85 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 34156097,
            "unit": "ops/sec",
            "extra": "Latency: 29.3 ns/op, Bandwidth: 2084.72 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 26284494,
            "unit": "ops/sec",
            "extra": "Latency: 38.0 ns/op, Bandwidth: 6417.11 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 16731696,
            "unit": "ops/sec",
            "extra": "Latency: 59.8 ns/op, Bandwidth: 16339.55 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 9516791,
            "unit": "ops/sec",
            "extra": "Latency: 105.1 ns/op, Bandwidth: 36.30 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 9132248,
            "unit": "ops/sec",
            "extra": "Latency: 109.5 ns/op, Bandwidth: 557.39 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 5688123,
            "unit": "ops/sec",
            "extra": "Latency: 175.8 ns/op, Bandwidth: 1388.70 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 3177491,
            "unit": "ops/sec",
            "extra": "Latency: 314.7 ns/op, Bandwidth: 3103.02 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 38356442,
            "unit": "ops/sec",
            "extra": "Latency: 26.1 ns/op, Bandwidth: 146.32 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 39130242,
            "unit": "ops/sec",
            "extra": "Latency: 25.6 ns/op, Bandwidth: 2388.32 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 30234912,
            "unit": "ops/sec",
            "extra": "Latency: 33.1 ns/op, Bandwidth: 7381.57 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 25991188,
            "unit": "ops/sec",
            "extra": "Latency: 38.5 ns/op, Bandwidth: 25382.02 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 32087096,
            "unit": "ops/sec",
            "extra": "Latency: 31.2 ns/op, Bandwidth: 122.40 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 32555429,
            "unit": "ops/sec",
            "extra": "Latency: 30.7 ns/op, Bandwidth: 1987.03 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 25635789,
            "unit": "ops/sec",
            "extra": "Latency: 39.0 ns/op, Bandwidth: 6258.74 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 22862115,
            "unit": "ops/sec",
            "extra": "Latency: 43.7 ns/op, Bandwidth: 22326.28 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 7969217,
            "unit": "ops/sec",
            "extra": "Latency: 125.5 ns/op, Bandwidth: 30.40 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 6038100,
            "unit": "ops/sec",
            "extra": "Latency: 165.6 ns/op, Bandwidth: 368.54 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 4399464,
            "unit": "ops/sec",
            "extra": "Latency: 227.3 ns/op, Bandwidth: 1074.09 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 5285839,
            "unit": "ops/sec",
            "extra": "Latency: 189.2 ns/op, Bandwidth: 20.16 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 5076149,
            "unit": "ops/sec",
            "extra": "Latency: 197.0 ns/op, Bandwidth: 309.82 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 4015287,
            "unit": "ops/sec",
            "extra": "Latency: 249.0 ns/op, Bandwidth: 980.29 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 15635066,
            "unit": "ops/sec",
            "extra": "Latency: 64.0 ns/op, Bandwidth: 59.64 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 15565756,
            "unit": "ops/sec",
            "extra": "Latency: 64.2 ns/op, Bandwidth: 950.06 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 13548091,
            "unit": "ops/sec",
            "extra": "Latency: 73.8 ns/op, Bandwidth: 3307.64 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 9368832,
            "unit": "ops/sec",
            "extra": "Latency: 106.7 ns/op, Bandwidth: 9149.25 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "44476b6802dd85493dfd9fc18be0b446ce555c36",
          "message": "perf: extreme IPC fast-path via header-only kfifo and inline expansion\n\n- Make `kfifo` header-only with `always_inline` to eliminate cross-file call overhead.\n- Change `kfifo_t.mask` to a value instead of a pointer, removing cross-cache-line dereferencing on the hot path.\n- Refactor `ufifo_put/get/peek` to use a compile-time `wait_type` constant, allowing GCC to aggressively strip dead code (like epoll wait branches) for non-blocking calls.\n- Add `-flto` linker flags in CMake to ensure Link-Time Optimization is applied across API boundaries.\n- Fix minor `strncpy` bound issue in `ufifo_broker.c`.",
          "timestamp": "2026-05-05T17:21:02Z",
          "tree_id": "f59f957a1385e02746033716e0276b5ceeff5e7d",
          "url": "https://github.com/ShenChen1/ufifo/commit/44476b6802dd85493dfd9fc18be0b446ce555c36"
        },
        "date": 1778001726555,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 79990388,
            "unit": "ops/sec",
            "extra": "Latency: 12.5 ns/op, Bandwidth: 305.14 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 85242176,
            "unit": "ops/sec",
            "extra": "Latency: 11.7 ns/op, Bandwidth: 5202.77 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 80786851,
            "unit": "ops/sec",
            "extra": "Latency: 12.4 ns/op, Bandwidth: 19723.35 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 49370475,
            "unit": "ops/sec",
            "extra": "Latency: 20.3 ns/op, Bandwidth: 48213.35 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 13927113,
            "unit": "ops/sec",
            "extra": "Latency: 71.8 ns/op, Bandwidth: 54402.79 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 48608458,
            "unit": "ops/sec",
            "extra": "Latency: 20.6 ns/op, Bandwidth: 185.43 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 43849405,
            "unit": "ops/sec",
            "extra": "Latency: 22.8 ns/op, Bandwidth: 2676.36 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 39417643,
            "unit": "ops/sec",
            "extra": "Latency: 25.4 ns/op, Bandwidth: 9623.45 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 34838430,
            "unit": "ops/sec",
            "extra": "Latency: 28.7 ns/op, Bandwidth: 34021.90 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 12791836,
            "unit": "ops/sec",
            "extra": "Latency: 78.2 ns/op, Bandwidth: 49968.11 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 48299192,
            "unit": "ops/sec",
            "extra": "Latency: 20.7 ns/op, Bandwidth: 184.25 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 36259318,
            "unit": "ops/sec",
            "extra": "Latency: 27.6 ns/op, Bandwidth: 2213.09 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 27756123,
            "unit": "ops/sec",
            "extra": "Latency: 36.0 ns/op, Bandwidth: 6776.40 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 22676386,
            "unit": "ops/sec",
            "extra": "Latency: 44.1 ns/op, Bandwidth: 22144.91 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 13071865,
            "unit": "ops/sec",
            "extra": "Latency: 76.5 ns/op, Bandwidth: 49.87 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 8973882,
            "unit": "ops/sec",
            "extra": "Latency: 111.4 ns/op, Bandwidth: 547.72 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 8473924,
            "unit": "ops/sec",
            "extra": "Latency: 118.0 ns/op, Bandwidth: 2068.83 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 6093112,
            "unit": "ops/sec",
            "extra": "Latency: 164.1 ns/op, Bandwidth: 5950.30 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 76531466,
            "unit": "ops/sec",
            "extra": "Latency: 13.1 ns/op, Bandwidth: 291.94 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 84785799,
            "unit": "ops/sec",
            "extra": "Latency: 11.8 ns/op, Bandwidth: 5174.91 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 79528415,
            "unit": "ops/sec",
            "extra": "Latency: 12.6 ns/op, Bandwidth: 19416.12 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 47517066,
            "unit": "ops/sec",
            "extra": "Latency: 21.0 ns/op, Bandwidth: 46403.38 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 46265909,
            "unit": "ops/sec",
            "extra": "Latency: 21.6 ns/op, Bandwidth: 176.49 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 45639557,
            "unit": "ops/sec",
            "extra": "Latency: 21.9 ns/op, Bandwidth: 2785.62 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 40955063,
            "unit": "ops/sec",
            "extra": "Latency: 24.4 ns/op, Bandwidth: 9998.79 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 33635501,
            "unit": "ops/sec",
            "extra": "Latency: 29.7 ns/op, Bandwidth: 32847.17 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 10104442,
            "unit": "ops/sec",
            "extra": "Latency: 99.0 ns/op, Bandwidth: 38.55 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 10580712,
            "unit": "ops/sec",
            "extra": "Latency: 94.5 ns/op, Bandwidth: 645.80 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 6688607,
            "unit": "ops/sec",
            "extra": "Latency: 149.5 ns/op, Bandwidth: 1632.96 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 6606748,
            "unit": "ops/sec",
            "extra": "Latency: 151.4 ns/op, Bandwidth: 25.20 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 6070774,
            "unit": "ops/sec",
            "extra": "Latency: 164.7 ns/op, Bandwidth: 370.53 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 5936115,
            "unit": "ops/sec",
            "extra": "Latency: 168.5 ns/op, Bandwidth: 1449.25 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 18791792,
            "unit": "ops/sec",
            "extra": "Latency: 53.2 ns/op, Bandwidth: 71.68 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 16985610,
            "unit": "ops/sec",
            "extra": "Latency: 58.9 ns/op, Bandwidth: 1036.72 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 14443042,
            "unit": "ops/sec",
            "extra": "Latency: 69.2 ns/op, Bandwidth: 3526.13 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 9046815,
            "unit": "ops/sec",
            "extra": "Latency: 110.5 ns/op, Bandwidth: 8834.78 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "2aae7fa8a5b1f69c1dcf40785cd8bf741d672cae",
          "message": "perf: extreme IPC fast-path via header-only kfifo and inline expansion\n\n- Make `kfifo` header-only with `always_inline` to eliminate cross-file call overhead.\n- Change `kfifo_t.mask` to a value instead of a pointer, removing cross-cache-line dereferencing on the hot path.\n- Refactor `ufifo_put/get/peek` to use a compile-time `wait_type` constant, allowing GCC to aggressively strip dead code (like epoll wait branches) for non-blocking calls.\n- Add `-flto` linker flags in CMake to ensure Link-Time Optimization is applied across API boundaries.\n- Fix minor `strncpy` bound issue in `ufifo_broker.c`.",
          "timestamp": "2026-05-05T17:54:46Z",
          "tree_id": "ff3506628ad36dbc891d5ad3e2e1f5024115d3b9",
          "url": "https://github.com/ShenChen1/ufifo/commit/2aae7fa8a5b1f69c1dcf40785cd8bf741d672cae"
        },
        "date": 1778003724562,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 75471704,
            "unit": "ops/sec",
            "extra": "Latency: 13.2 ns/op, Bandwidth: 287.90 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 85806307,
            "unit": "ops/sec",
            "extra": "Latency: 11.7 ns/op, Bandwidth: 5237.20 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 80444944,
            "unit": "ops/sec",
            "extra": "Latency: 12.4 ns/op, Bandwidth: 19639.88 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 49686900,
            "unit": "ops/sec",
            "extra": "Latency: 20.1 ns/op, Bandwidth: 48522.36 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 13778528,
            "unit": "ops/sec",
            "extra": "Latency: 72.6 ns/op, Bandwidth: 53822.38 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 49018494,
            "unit": "ops/sec",
            "extra": "Latency: 20.4 ns/op, Bandwidth: 186.99 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 43597823,
            "unit": "ops/sec",
            "extra": "Latency: 22.9 ns/op, Bandwidth: 2661.00 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 42559913,
            "unit": "ops/sec",
            "extra": "Latency: 23.5 ns/op, Bandwidth: 10390.60 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 36207377,
            "unit": "ops/sec",
            "extra": "Latency: 27.6 ns/op, Bandwidth: 35358.77 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 12826626,
            "unit": "ops/sec",
            "extra": "Latency: 78.0 ns/op, Bandwidth: 50104.01 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 41810825,
            "unit": "ops/sec",
            "extra": "Latency: 23.9 ns/op, Bandwidth: 159.50 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 31921190,
            "unit": "ops/sec",
            "extra": "Latency: 31.3 ns/op, Bandwidth: 1948.31 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 27162517,
            "unit": "ops/sec",
            "extra": "Latency: 36.8 ns/op, Bandwidth: 6631.47 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 19916987,
            "unit": "ops/sec",
            "extra": "Latency: 50.2 ns/op, Bandwidth: 19450.18 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 12025790,
            "unit": "ops/sec",
            "extra": "Latency: 83.2 ns/op, Bandwidth: 45.87 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 8715288,
            "unit": "ops/sec",
            "extra": "Latency: 114.7 ns/op, Bandwidth: 531.94 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 8738876,
            "unit": "ops/sec",
            "extra": "Latency: 114.4 ns/op, Bandwidth: 2133.51 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 5005663,
            "unit": "ops/sec",
            "extra": "Latency: 199.8 ns/op, Bandwidth: 4888.34 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 80708769,
            "unit": "ops/sec",
            "extra": "Latency: 12.4 ns/op, Bandwidth: 307.88 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 85411027,
            "unit": "ops/sec",
            "extra": "Latency: 11.7 ns/op, Bandwidth: 5213.08 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 75837476,
            "unit": "ops/sec",
            "extra": "Latency: 13.2 ns/op, Bandwidth: 18515.01 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 47404563,
            "unit": "ops/sec",
            "extra": "Latency: 21.1 ns/op, Bandwidth: 46293.52 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 46234542,
            "unit": "ops/sec",
            "extra": "Latency: 21.6 ns/op, Bandwidth: 176.37 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 45676004,
            "unit": "ops/sec",
            "extra": "Latency: 21.9 ns/op, Bandwidth: 2787.84 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 41027176,
            "unit": "ops/sec",
            "extra": "Latency: 24.4 ns/op, Bandwidth: 10016.40 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 34585828,
            "unit": "ops/sec",
            "extra": "Latency: 28.9 ns/op, Bandwidth: 33775.22 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 8272461,
            "unit": "ops/sec",
            "extra": "Latency: 120.9 ns/op, Bandwidth: 31.56 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 9023493,
            "unit": "ops/sec",
            "extra": "Latency: 110.8 ns/op, Bandwidth: 550.75 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 8280036,
            "unit": "ops/sec",
            "extra": "Latency: 120.8 ns/op, Bandwidth: 2021.49 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 6403529,
            "unit": "ops/sec",
            "extra": "Latency: 156.2 ns/op, Bandwidth: 24.43 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 5650454,
            "unit": "ops/sec",
            "extra": "Latency: 177.0 ns/op, Bandwidth: 344.88 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 5580791,
            "unit": "ops/sec",
            "extra": "Latency: 179.2 ns/op, Bandwidth: 1362.50 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 16504854,
            "unit": "ops/sec",
            "extra": "Latency: 60.6 ns/op, Bandwidth: 62.96 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 14759514,
            "unit": "ops/sec",
            "extra": "Latency: 67.8 ns/op, Bandwidth: 900.85 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 13097615,
            "unit": "ops/sec",
            "extra": "Latency: 76.3 ns/op, Bandwidth: 3197.66 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 6889170,
            "unit": "ops/sec",
            "extra": "Latency: 145.2 ns/op, Bandwidth: 6727.71 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "f2ee3bea450c30ab813bcdce2d3488462ba75460",
          "message": "fix: bound FIFO name length",
          "timestamp": "2026-06-11T16:59:53Z",
          "tree_id": "3c98e4b0e0454bf8758aff8a227904efca10f344",
          "url": "https://github.com/ShenChen1/ufifo/commit/f2ee3bea450c30ab813bcdce2d3488462ba75460"
        },
        "date": 1781197345077,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 77438634,
            "unit": "ops/sec",
            "extra": "Latency: 12.9 ns/op, Bandwidth: 295.40 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 86877886,
            "unit": "ops/sec",
            "extra": "Latency: 11.5 ns/op, Bandwidth: 5302.61 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 74223715,
            "unit": "ops/sec",
            "extra": "Latency: 13.5 ns/op, Bandwidth: 18121.02 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 47315579,
            "unit": "ops/sec",
            "extra": "Latency: 21.1 ns/op, Bandwidth: 46206.62 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 13750395,
            "unit": "ops/sec",
            "extra": "Latency: 72.7 ns/op, Bandwidth: 53712.48 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 52724101,
            "unit": "ops/sec",
            "extra": "Latency: 19.0 ns/op, Bandwidth: 201.13 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 55736117,
            "unit": "ops/sec",
            "extra": "Latency: 17.9 ns/op, Bandwidth: 3401.86 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 51441921,
            "unit": "ops/sec",
            "extra": "Latency: 19.4 ns/op, Bandwidth: 12559.06 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 36573788,
            "unit": "ops/sec",
            "extra": "Latency: 27.3 ns/op, Bandwidth: 35716.59 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 13002095,
            "unit": "ops/sec",
            "extra": "Latency: 76.9 ns/op, Bandwidth: 50789.43 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 45547929,
            "unit": "ops/sec",
            "extra": "Latency: 22.0 ns/op, Bandwidth: 173.75 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 33467315,
            "unit": "ops/sec",
            "extra": "Latency: 29.9 ns/op, Bandwidth: 2042.68 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 27750298,
            "unit": "ops/sec",
            "extra": "Latency: 36.0 ns/op, Bandwidth: 6774.98 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 21578410,
            "unit": "ops/sec",
            "extra": "Latency: 46.3 ns/op, Bandwidth: 21072.67 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 10407928,
            "unit": "ops/sec",
            "extra": "Latency: 96.1 ns/op, Bandwidth: 39.70 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 9910322,
            "unit": "ops/sec",
            "extra": "Latency: 100.9 ns/op, Bandwidth: 604.88 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 8339899,
            "unit": "ops/sec",
            "extra": "Latency: 119.9 ns/op, Bandwidth: 2036.11 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 5784588,
            "unit": "ops/sec",
            "extra": "Latency: 172.9 ns/op, Bandwidth: 5649.01 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 83567135,
            "unit": "ops/sec",
            "extra": "Latency: 12.0 ns/op, Bandwidth: 318.78 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 86747291,
            "unit": "ops/sec",
            "extra": "Latency: 11.5 ns/op, Bandwidth: 5294.63 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 64928601,
            "unit": "ops/sec",
            "extra": "Latency: 15.4 ns/op, Bandwidth: 15851.71 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 44124473,
            "unit": "ops/sec",
            "extra": "Latency: 22.7 ns/op, Bandwidth: 43090.31 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 54714984,
            "unit": "ops/sec",
            "extra": "Latency: 18.3 ns/op, Bandwidth: 208.72 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 56968578,
            "unit": "ops/sec",
            "extra": "Latency: 17.6 ns/op, Bandwidth: 3477.09 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 51685323,
            "unit": "ops/sec",
            "extra": "Latency: 19.3 ns/op, Bandwidth: 12618.49 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 36074408,
            "unit": "ops/sec",
            "extra": "Latency: 27.7 ns/op, Bandwidth: 35228.91 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 7894041,
            "unit": "ops/sec",
            "extra": "Latency: 126.7 ns/op, Bandwidth: 30.11 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 7218273,
            "unit": "ops/sec",
            "extra": "Latency: 138.5 ns/op, Bandwidth: 440.57 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 6694092,
            "unit": "ops/sec",
            "extra": "Latency: 149.4 ns/op, Bandwidth: 1634.30 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 6587160,
            "unit": "ops/sec",
            "extra": "Latency: 151.8 ns/op, Bandwidth: 25.13 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 6199453,
            "unit": "ops/sec",
            "extra": "Latency: 161.3 ns/op, Bandwidth: 378.38 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 5358777,
            "unit": "ops/sec",
            "extra": "Latency: 186.6 ns/op, Bandwidth: 1308.30 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 17428073,
            "unit": "ops/sec",
            "extra": "Latency: 57.4 ns/op, Bandwidth: 66.48 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 15757682,
            "unit": "ops/sec",
            "extra": "Latency: 63.5 ns/op, Bandwidth: 961.77 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 12347353,
            "unit": "ops/sec",
            "extra": "Latency: 81.0 ns/op, Bandwidth: 3014.49 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 8242361,
            "unit": "ops/sec",
            "extra": "Latency: 121.3 ns/op, Bandwidth: 8049.18 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "60db81129e7a3b3aa6b6c0e8bf99a45e177c96b5",
          "message": "fix: bound FIFO name length",
          "timestamp": "2026-06-11T17:04:54Z",
          "tree_id": "4df60d866391084008f63578775af95abf52972a",
          "url": "https://github.com/ShenChen1/ufifo/commit/60db81129e7a3b3aa6b6c0e8bf99a45e177c96b5"
        },
        "date": 1781197651905,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 71493672,
            "unit": "ops/sec",
            "extra": "Latency: 14.0 ns/op, Bandwidth: 272.73 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 92259893,
            "unit": "ops/sec",
            "extra": "Latency: 10.8 ns/op, Bandwidth: 5631.10 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 81956908,
            "unit": "ops/sec",
            "extra": "Latency: 12.2 ns/op, Bandwidth: 20009.01 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 43780959,
            "unit": "ops/sec",
            "extra": "Latency: 22.8 ns/op, Bandwidth: 42754.84 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 13569404,
            "unit": "ops/sec",
            "extra": "Latency: 73.7 ns/op, Bandwidth: 53005.48 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 59017941,
            "unit": "ops/sec",
            "extra": "Latency: 16.9 ns/op, Bandwidth: 225.14 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 60750900,
            "unit": "ops/sec",
            "extra": "Latency: 16.5 ns/op, Bandwidth: 3707.94 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 56593237,
            "unit": "ops/sec",
            "extra": "Latency: 17.7 ns/op, Bandwidth: 13816.71 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 35562998,
            "unit": "ops/sec",
            "extra": "Latency: 28.1 ns/op, Bandwidth: 34729.49 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 6131018,
            "unit": "ops/sec",
            "extra": "Latency: 163.1 ns/op, Bandwidth: 23949.29 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 42451694,
            "unit": "ops/sec",
            "extra": "Latency: 23.6 ns/op, Bandwidth: 161.94 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 31907765,
            "unit": "ops/sec",
            "extra": "Latency: 31.3 ns/op, Bandwidth: 1947.50 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 25054340,
            "unit": "ops/sec",
            "extra": "Latency: 39.9 ns/op, Bandwidth: 6116.78 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 11668346,
            "unit": "ops/sec",
            "extra": "Latency: 85.7 ns/op, Bandwidth: 11394.87 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 15941140,
            "unit": "ops/sec",
            "extra": "Latency: 62.7 ns/op, Bandwidth: 60.81 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 7303339,
            "unit": "ops/sec",
            "extra": "Latency: 136.9 ns/op, Bandwidth: 445.76 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 6358919,
            "unit": "ops/sec",
            "extra": "Latency: 157.3 ns/op, Bandwidth: 1552.47 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 2713254,
            "unit": "ops/sec",
            "extra": "Latency: 368.6 ns/op, Bandwidth: 2649.66 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 88525266,
            "unit": "ops/sec",
            "extra": "Latency: 11.3 ns/op, Bandwidth: 337.70 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 88031926,
            "unit": "ops/sec",
            "extra": "Latency: 11.4 ns/op, Bandwidth: 5373.04 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 81353448,
            "unit": "ops/sec",
            "extra": "Latency: 12.3 ns/op, Bandwidth: 19861.68 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 42420304,
            "unit": "ops/sec",
            "extra": "Latency: 23.6 ns/op, Bandwidth: 41426.08 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 58977825,
            "unit": "ops/sec",
            "extra": "Latency: 17.0 ns/op, Bandwidth: 224.98 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 59675308,
            "unit": "ops/sec",
            "extra": "Latency: 16.8 ns/op, Bandwidth: 3642.29 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 55789157,
            "unit": "ops/sec",
            "extra": "Latency: 17.9 ns/op, Bandwidth: 13620.40 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 33833514,
            "unit": "ops/sec",
            "extra": "Latency: 29.6 ns/op, Bandwidth: 33040.54 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 10564936,
            "unit": "ops/sec",
            "extra": "Latency: 94.7 ns/op, Bandwidth: 40.30 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 6765616,
            "unit": "ops/sec",
            "extra": "Latency: 147.8 ns/op, Bandwidth: 412.94 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 6252826,
            "unit": "ops/sec",
            "extra": "Latency: 159.9 ns/op, Bandwidth: 1526.57 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 7151197,
            "unit": "ops/sec",
            "extra": "Latency: 139.8 ns/op, Bandwidth: 27.28 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 6002743,
            "unit": "ops/sec",
            "extra": "Latency: 166.6 ns/op, Bandwidth: 366.38 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 5520818,
            "unit": "ops/sec",
            "extra": "Latency: 181.1 ns/op, Bandwidth: 1347.86 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 19184695,
            "unit": "ops/sec",
            "extra": "Latency: 52.1 ns/op, Bandwidth: 73.18 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 16271288,
            "unit": "ops/sec",
            "extra": "Latency: 61.5 ns/op, Bandwidth: 993.12 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 12408743,
            "unit": "ops/sec",
            "extra": "Latency: 80.6 ns/op, Bandwidth: 3029.48 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 7060896,
            "unit": "ops/sec",
            "extra": "Latency: 141.6 ns/op, Bandwidth: 6895.41 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "60db81129e7a3b3aa6b6c0e8bf99a45e177c96b5",
          "message": "fix: bound FIFO name length",
          "timestamp": "2026-06-11T17:04:54Z",
          "tree_id": "4df60d866391084008f63578775af95abf52972a",
          "url": "https://github.com/ShenChen1/ufifo/commit/60db81129e7a3b3aa6b6c0e8bf99a45e177c96b5"
        },
        "date": 1781228841647,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 71289831,
            "unit": "ops/sec",
            "extra": "Latency: 14.0 ns/op, Bandwidth: 271.95 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 89304500,
            "unit": "ops/sec",
            "extra": "Latency: 11.2 ns/op, Bandwidth: 5450.71 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 80820986,
            "unit": "ops/sec",
            "extra": "Latency: 12.4 ns/op, Bandwidth: 19731.69 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 43730722,
            "unit": "ops/sec",
            "extra": "Latency: 22.9 ns/op, Bandwidth: 42705.78 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 13584917,
            "unit": "ops/sec",
            "extra": "Latency: 73.6 ns/op, Bandwidth: 53066.08 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 58307137,
            "unit": "ops/sec",
            "extra": "Latency: 17.2 ns/op, Bandwidth: 222.42 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 59369256,
            "unit": "ops/sec",
            "extra": "Latency: 16.8 ns/op, Bandwidth: 3623.61 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 53671982,
            "unit": "ops/sec",
            "extra": "Latency: 18.6 ns/op, Bandwidth: 13103.51 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 35817957,
            "unit": "ops/sec",
            "extra": "Latency: 27.9 ns/op, Bandwidth: 34978.47 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 12631704,
            "unit": "ops/sec",
            "extra": "Latency: 79.2 ns/op, Bandwidth: 49342.59 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 44297931,
            "unit": "ops/sec",
            "extra": "Latency: 22.6 ns/op, Bandwidth: 168.98 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 34333816,
            "unit": "ops/sec",
            "extra": "Latency: 29.1 ns/op, Bandwidth: 2095.57 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 25724774,
            "unit": "ops/sec",
            "extra": "Latency: 38.9 ns/op, Bandwidth: 6280.46 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 12225616,
            "unit": "ops/sec",
            "extra": "Latency: 81.8 ns/op, Bandwidth: 11939.08 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 16519942,
            "unit": "ops/sec",
            "extra": "Latency: 60.5 ns/op, Bandwidth: 63.02 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 7703456,
            "unit": "ops/sec",
            "extra": "Latency: 129.8 ns/op, Bandwidth: 470.18 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 6472817,
            "unit": "ops/sec",
            "extra": "Latency: 154.5 ns/op, Bandwidth: 1580.28 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 3001146,
            "unit": "ops/sec",
            "extra": "Latency: 333.2 ns/op, Bandwidth: 2930.81 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 88391744,
            "unit": "ops/sec",
            "extra": "Latency: 11.3 ns/op, Bandwidth: 337.19 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 84279206,
            "unit": "ops/sec",
            "extra": "Latency: 11.9 ns/op, Bandwidth: 5143.99 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 81867363,
            "unit": "ops/sec",
            "extra": "Latency: 12.2 ns/op, Bandwidth: 19987.15 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 42806737,
            "unit": "ops/sec",
            "extra": "Latency: 23.4 ns/op, Bandwidth: 41803.45 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 58812865,
            "unit": "ops/sec",
            "extra": "Latency: 17.0 ns/op, Bandwidth: 224.35 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 60901512,
            "unit": "ops/sec",
            "extra": "Latency: 16.4 ns/op, Bandwidth: 3717.13 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 57070835,
            "unit": "ops/sec",
            "extra": "Latency: 17.5 ns/op, Bandwidth: 13933.31 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 34205432,
            "unit": "ops/sec",
            "extra": "Latency: 29.2 ns/op, Bandwidth: 33403.74 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 13130697,
            "unit": "ops/sec",
            "extra": "Latency: 76.2 ns/op, Bandwidth: 50.09 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 8173354,
            "unit": "ops/sec",
            "extra": "Latency: 122.3 ns/op, Bandwidth: 498.86 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 5853420,
            "unit": "ops/sec",
            "extra": "Latency: 170.8 ns/op, Bandwidth: 1429.06 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 6674038,
            "unit": "ops/sec",
            "extra": "Latency: 149.8 ns/op, Bandwidth: 25.46 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 6221443,
            "unit": "ops/sec",
            "extra": "Latency: 160.7 ns/op, Bandwidth: 379.73 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 5411687,
            "unit": "ops/sec",
            "extra": "Latency: 184.8 ns/op, Bandwidth: 1321.21 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 19664207,
            "unit": "ops/sec",
            "extra": "Latency: 50.9 ns/op, Bandwidth: 75.01 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 16881602,
            "unit": "ops/sec",
            "extra": "Latency: 59.2 ns/op, Bandwidth: 1030.37 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 12028360,
            "unit": "ops/sec",
            "extra": "Latency: 83.1 ns/op, Bandwidth: 2936.61 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 7100766,
            "unit": "ops/sec",
            "extra": "Latency: 140.8 ns/op, Bandwidth: 6934.34 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "60db81129e7a3b3aa6b6c0e8bf99a45e177c96b5",
          "message": "fix: bound FIFO name length",
          "timestamp": "2026-06-11T17:04:54Z",
          "tree_id": "4df60d866391084008f63578775af95abf52972a",
          "url": "https://github.com/ShenChen1/ufifo/commit/60db81129e7a3b3aa6b6c0e8bf99a45e177c96b5"
        },
        "date": 1781228946141,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 71443319,
            "unit": "ops/sec",
            "extra": "Latency: 14.0 ns/op, Bandwidth: 272.53 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 88026201,
            "unit": "ops/sec",
            "extra": "Latency: 11.4 ns/op, Bandwidth: 5372.69 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 80902673,
            "unit": "ops/sec",
            "extra": "Latency: 12.4 ns/op, Bandwidth: 19751.63 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 42205779,
            "unit": "ops/sec",
            "extra": "Latency: 23.7 ns/op, Bandwidth: 41216.58 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 14299955,
            "unit": "ops/sec",
            "extra": "Latency: 69.9 ns/op, Bandwidth: 55859.20 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 60443048,
            "unit": "ops/sec",
            "extra": "Latency: 16.5 ns/op, Bandwidth: 230.57 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 61573221,
            "unit": "ops/sec",
            "extra": "Latency: 16.2 ns/op, Bandwidth: 3758.13 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 56780246,
            "unit": "ops/sec",
            "extra": "Latency: 17.6 ns/op, Bandwidth: 13862.36 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 35940985,
            "unit": "ops/sec",
            "extra": "Latency: 27.8 ns/op, Bandwidth: 35098.62 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 13522247,
            "unit": "ops/sec",
            "extra": "Latency: 74.0 ns/op, Bandwidth: 52821.28 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 43645089,
            "unit": "ops/sec",
            "extra": "Latency: 22.9 ns/op, Bandwidth: 166.49 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 31398632,
            "unit": "ops/sec",
            "extra": "Latency: 31.8 ns/op, Bandwidth: 1916.42 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 24658181,
            "unit": "ops/sec",
            "extra": "Latency: 40.6 ns/op, Bandwidth: 6020.06 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 12018909,
            "unit": "ops/sec",
            "extra": "Latency: 83.2 ns/op, Bandwidth: 11737.22 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 16166268,
            "unit": "ops/sec",
            "extra": "Latency: 61.9 ns/op, Bandwidth: 61.67 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 7300504,
            "unit": "ops/sec",
            "extra": "Latency: 137.0 ns/op, Bandwidth: 445.59 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 6319188,
            "unit": "ops/sec",
            "extra": "Latency: 158.2 ns/op, Bandwidth: 1542.77 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 2996184,
            "unit": "ops/sec",
            "extra": "Latency: 333.8 ns/op, Bandwidth: 2925.96 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 88682835,
            "unit": "ops/sec",
            "extra": "Latency: 11.3 ns/op, Bandwidth: 338.30 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 87923629,
            "unit": "ops/sec",
            "extra": "Latency: 11.4 ns/op, Bandwidth: 5366.43 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 83721855,
            "unit": "ops/sec",
            "extra": "Latency: 11.9 ns/op, Bandwidth: 20439.91 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 43359104,
            "unit": "ops/sec",
            "extra": "Latency: 23.1 ns/op, Bandwidth: 42342.88 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 59290086,
            "unit": "ops/sec",
            "extra": "Latency: 16.9 ns/op, Bandwidth: 226.17 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 58552575,
            "unit": "ops/sec",
            "extra": "Latency: 17.1 ns/op, Bandwidth: 3573.77 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 55870047,
            "unit": "ops/sec",
            "extra": "Latency: 17.9 ns/op, Bandwidth: 13640.15 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 34817684,
            "unit": "ops/sec",
            "extra": "Latency: 28.7 ns/op, Bandwidth: 34001.64 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 13166923,
            "unit": "ops/sec",
            "extra": "Latency: 75.9 ns/op, Bandwidth: 50.23 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 7411624,
            "unit": "ops/sec",
            "extra": "Latency: 134.9 ns/op, Bandwidth: 452.37 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 6641747,
            "unit": "ops/sec",
            "extra": "Latency: 150.6 ns/op, Bandwidth: 1621.52 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 7332663,
            "unit": "ops/sec",
            "extra": "Latency: 136.4 ns/op, Bandwidth: 27.97 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 5712846,
            "unit": "ops/sec",
            "extra": "Latency: 175.0 ns/op, Bandwidth: 348.68 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 5284309,
            "unit": "ops/sec",
            "extra": "Latency: 189.2 ns/op, Bandwidth: 1290.11 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 18339364,
            "unit": "ops/sec",
            "extra": "Latency: 54.5 ns/op, Bandwidth: 69.96 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 14402860,
            "unit": "ops/sec",
            "extra": "Latency: 69.4 ns/op, Bandwidth: 879.08 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 12591197,
            "unit": "ops/sec",
            "extra": "Latency: 79.4 ns/op, Bandwidth: 3074.02 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 7112249,
            "unit": "ops/sec",
            "extra": "Latency: 140.6 ns/op, Bandwidth: 6945.56 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "60db81129e7a3b3aa6b6c0e8bf99a45e177c96b5",
          "message": "fix: bound FIFO name length",
          "timestamp": "2026-06-11T17:04:54Z",
          "tree_id": "4df60d866391084008f63578775af95abf52972a",
          "url": "https://github.com/ShenChen1/ufifo/commit/60db81129e7a3b3aa6b6c0e8bf99a45e177c96b5"
        },
        "date": 1781229062032,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 71207447,
            "unit": "ops/sec",
            "extra": "Latency: 14.0 ns/op, Bandwidth: 271.63 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 91499060,
            "unit": "ops/sec",
            "extra": "Latency: 10.9 ns/op, Bandwidth: 5584.66 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 79679015,
            "unit": "ops/sec",
            "extra": "Latency: 12.6 ns/op, Bandwidth: 19452.88 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 45030639,
            "unit": "ops/sec",
            "extra": "Latency: 22.2 ns/op, Bandwidth: 43975.23 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 14348234,
            "unit": "ops/sec",
            "extra": "Latency: 69.7 ns/op, Bandwidth: 56047.79 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 60881370,
            "unit": "ops/sec",
            "extra": "Latency: 16.4 ns/op, Bandwidth: 232.24 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 60683897,
            "unit": "ops/sec",
            "extra": "Latency: 16.5 ns/op, Bandwidth: 3703.85 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 50542313,
            "unit": "ops/sec",
            "extra": "Latency: 19.8 ns/op, Bandwidth: 12339.43 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 36566408,
            "unit": "ops/sec",
            "extra": "Latency: 27.3 ns/op, Bandwidth: 35709.38 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 13127953,
            "unit": "ops/sec",
            "extra": "Latency: 76.2 ns/op, Bandwidth: 51281.06 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 45581139,
            "unit": "ops/sec",
            "extra": "Latency: 21.9 ns/op, Bandwidth: 173.88 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 34933935,
            "unit": "ops/sec",
            "extra": "Latency: 28.6 ns/op, Bandwidth: 2132.20 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 26514703,
            "unit": "ops/sec",
            "extra": "Latency: 37.7 ns/op, Bandwidth: 6473.32 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 12345090,
            "unit": "ops/sec",
            "extra": "Latency: 81.0 ns/op, Bandwidth: 12055.75 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 17057700,
            "unit": "ops/sec",
            "extra": "Latency: 58.6 ns/op, Bandwidth: 65.07 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 7844385,
            "unit": "ops/sec",
            "extra": "Latency: 127.5 ns/op, Bandwidth: 478.78 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 7075257,
            "unit": "ops/sec",
            "extra": "Latency: 141.3 ns/op, Bandwidth: 1727.36 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 2991989,
            "unit": "ops/sec",
            "extra": "Latency: 334.2 ns/op, Bandwidth: 2921.86 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 88632838,
            "unit": "ops/sec",
            "extra": "Latency: 11.3 ns/op, Bandwidth: 338.11 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 88241982,
            "unit": "ops/sec",
            "extra": "Latency: 11.3 ns/op, Bandwidth: 5385.86 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 83062266,
            "unit": "ops/sec",
            "extra": "Latency: 12.0 ns/op, Bandwidth: 20278.87 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 42631169,
            "unit": "ops/sec",
            "extra": "Latency: 23.5 ns/op, Bandwidth: 41632.00 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 60266018,
            "unit": "ops/sec",
            "extra": "Latency: 16.6 ns/op, Bandwidth: 229.90 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 61479220,
            "unit": "ops/sec",
            "extra": "Latency: 16.3 ns/op, Bandwidth: 3752.39 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 55542601,
            "unit": "ops/sec",
            "extra": "Latency: 18.0 ns/op, Bandwidth: 13560.21 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 31204056,
            "unit": "ops/sec",
            "extra": "Latency: 32.0 ns/op, Bandwidth: 30472.71 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 11500516,
            "unit": "ops/sec",
            "extra": "Latency: 87.0 ns/op, Bandwidth: 43.87 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 9030178,
            "unit": "ops/sec",
            "extra": "Latency: 110.7 ns/op, Bandwidth: 551.16 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 6443073,
            "unit": "ops/sec",
            "extra": "Latency: 155.2 ns/op, Bandwidth: 1573.02 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 6841264,
            "unit": "ops/sec",
            "extra": "Latency: 146.2 ns/op, Bandwidth: 26.10 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 5915551,
            "unit": "ops/sec",
            "extra": "Latency: 169.0 ns/op, Bandwidth: 361.06 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 5281529,
            "unit": "ops/sec",
            "extra": "Latency: 189.3 ns/op, Bandwidth: 1289.44 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 20180567,
            "unit": "ops/sec",
            "extra": "Latency: 49.6 ns/op, Bandwidth: 76.98 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 16935860,
            "unit": "ops/sec",
            "extra": "Latency: 59.0 ns/op, Bandwidth: 1033.68 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 12370576,
            "unit": "ops/sec",
            "extra": "Latency: 80.8 ns/op, Bandwidth: 3020.16 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 7205155,
            "unit": "ops/sec",
            "extra": "Latency: 138.8 ns/op, Bandwidth: 7036.28 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "60db81129e7a3b3aa6b6c0e8bf99a45e177c96b5",
          "message": "fix: bound FIFO name length",
          "timestamp": "2026-06-11T17:04:54Z",
          "tree_id": "4df60d866391084008f63578775af95abf52972a",
          "url": "https://github.com/ShenChen1/ufifo/commit/60db81129e7a3b3aa6b6c0e8bf99a45e177c96b5"
        },
        "date": 1781277640421,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 83918955,
            "unit": "ops/sec",
            "extra": "Latency: 11.9 ns/op, Bandwidth: 320.13 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 92057576,
            "unit": "ops/sec",
            "extra": "Latency: 10.9 ns/op, Bandwidth: 5618.75 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 80575184,
            "unit": "ops/sec",
            "extra": "Latency: 12.4 ns/op, Bandwidth: 19671.68 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 44005535,
            "unit": "ops/sec",
            "extra": "Latency: 22.7 ns/op, Bandwidth: 42974.16 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 13929794,
            "unit": "ops/sec",
            "extra": "Latency: 71.8 ns/op, Bandwidth: 54413.26 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 58080660,
            "unit": "ops/sec",
            "extra": "Latency: 17.2 ns/op, Bandwidth: 221.56 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 59873139,
            "unit": "ops/sec",
            "extra": "Latency: 16.7 ns/op, Bandwidth: 3654.37 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 48203597,
            "unit": "ops/sec",
            "extra": "Latency: 20.7 ns/op, Bandwidth: 11768.46 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 36307547,
            "unit": "ops/sec",
            "extra": "Latency: 27.5 ns/op, Bandwidth: 35456.59 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 12975441,
            "unit": "ops/sec",
            "extra": "Latency: 77.1 ns/op, Bandwidth: 50685.32 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 45277998,
            "unit": "ops/sec",
            "extra": "Latency: 22.1 ns/op, Bandwidth: 172.72 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 35358567,
            "unit": "ops/sec",
            "extra": "Latency: 28.3 ns/op, Bandwidth: 2158.12 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 28651971,
            "unit": "ops/sec",
            "extra": "Latency: 34.9 ns/op, Bandwidth: 6995.11 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 20132804,
            "unit": "ops/sec",
            "extra": "Latency: 49.7 ns/op, Bandwidth: 19660.94 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 14424660,
            "unit": "ops/sec",
            "extra": "Latency: 69.3 ns/op, Bandwidth: 55.03 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 11197585,
            "unit": "ops/sec",
            "extra": "Latency: 89.3 ns/op, Bandwidth: 683.45 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 9536830,
            "unit": "ops/sec",
            "extra": "Latency: 104.9 ns/op, Bandwidth: 2328.33 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 5626282,
            "unit": "ops/sec",
            "extra": "Latency: 177.7 ns/op, Bandwidth: 5494.42 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 86145068,
            "unit": "ops/sec",
            "extra": "Latency: 11.6 ns/op, Bandwidth: 328.62 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 90492225,
            "unit": "ops/sec",
            "extra": "Latency: 11.1 ns/op, Bandwidth: 5523.21 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 79967963,
            "unit": "ops/sec",
            "extra": "Latency: 12.5 ns/op, Bandwidth: 19523.43 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 46710700,
            "unit": "ops/sec",
            "extra": "Latency: 21.4 ns/op, Bandwidth: 45615.92 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 57769118,
            "unit": "ops/sec",
            "extra": "Latency: 17.3 ns/op, Bandwidth: 220.37 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 58950487,
            "unit": "ops/sec",
            "extra": "Latency: 17.0 ns/op, Bandwidth: 3598.05 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 53999462,
            "unit": "ops/sec",
            "extra": "Latency: 18.5 ns/op, Bandwidth: 13183.46 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 36951884,
            "unit": "ops/sec",
            "extra": "Latency: 27.1 ns/op, Bandwidth: 36085.82 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 9122537,
            "unit": "ops/sec",
            "extra": "Latency: 109.6 ns/op, Bandwidth: 34.80 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 7655366,
            "unit": "ops/sec",
            "extra": "Latency: 130.6 ns/op, Bandwidth: 467.25 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 6994307,
            "unit": "ops/sec",
            "extra": "Latency: 143.0 ns/op, Bandwidth: 1707.59 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 6710073,
            "unit": "ops/sec",
            "extra": "Latency: 149.0 ns/op, Bandwidth: 25.60 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 6445928,
            "unit": "ops/sec",
            "extra": "Latency: 155.1 ns/op, Bandwidth: 393.43 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 6238415,
            "unit": "ops/sec",
            "extra": "Latency: 160.3 ns/op, Bandwidth: 1523.05 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 17198529,
            "unit": "ops/sec",
            "extra": "Latency: 58.1 ns/op, Bandwidth: 65.61 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 15389797,
            "unit": "ops/sec",
            "extra": "Latency: 65.0 ns/op, Bandwidth: 939.32 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 12284697,
            "unit": "ops/sec",
            "extra": "Latency: 81.4 ns/op, Bandwidth: 2999.19 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 8967856,
            "unit": "ops/sec",
            "extra": "Latency: 111.5 ns/op, Bandwidth: 8757.67 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "7b0559d5abed239de65e34321443e6ed355368e1",
          "message": "fix(sync): notify blocked writers when write-space is freed\n\nSHARED mode readers departing (close), dead readers being reaped, and\nufifo_reset() all increase available write-space but did not notify\nwriters blocked on efd_wr. This caused indefinite writer stalls.",
          "timestamp": "2026-06-22T15:59:36Z",
          "tree_id": "74fb13c283feebd4dcf3d97fe82fabf8f24dd612",
          "url": "https://github.com/ShenChen1/ufifo/commit/7b0559d5abed239de65e34321443e6ed355368e1"
        },
        "date": 1782146790501,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 83480607,
            "unit": "ops/sec",
            "extra": "Latency: 12.0 ns/op, Bandwidth: 318.45 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 88548493,
            "unit": "ops/sec",
            "extra": "Latency: 11.3 ns/op, Bandwidth: 5404.57 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 79536329,
            "unit": "ops/sec",
            "extra": "Latency: 12.6 ns/op, Bandwidth: 19418.05 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 47102104,
            "unit": "ops/sec",
            "extra": "Latency: 21.2 ns/op, Bandwidth: 45998.15 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 13945995,
            "unit": "ops/sec",
            "extra": "Latency: 71.7 ns/op, Bandwidth: 54476.54 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 49891765,
            "unit": "ops/sec",
            "extra": "Latency: 20.0 ns/op, Bandwidth: 190.32 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 57752457,
            "unit": "ops/sec",
            "extra": "Latency: 17.3 ns/op, Bandwidth: 3524.93 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 53200316,
            "unit": "ops/sec",
            "extra": "Latency: 18.8 ns/op, Bandwidth: 12988.36 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 35188143,
            "unit": "ops/sec",
            "extra": "Latency: 28.4 ns/op, Bandwidth: 34363.42 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 12964951,
            "unit": "ops/sec",
            "extra": "Latency: 77.1 ns/op, Bandwidth: 50644.34 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 48617002,
            "unit": "ops/sec",
            "extra": "Latency: 20.6 ns/op, Bandwidth: 185.46 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 37363855,
            "unit": "ops/sec",
            "extra": "Latency: 26.8 ns/op, Bandwidth: 2280.51 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 30645296,
            "unit": "ops/sec",
            "extra": "Latency: 32.6 ns/op, Bandwidth: 7481.76 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 21036917,
            "unit": "ops/sec",
            "extra": "Latency: 47.5 ns/op, Bandwidth: 20543.86 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 14572188,
            "unit": "ops/sec",
            "extra": "Latency: 68.6 ns/op, Bandwidth: 55.59 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 10584980,
            "unit": "ops/sec",
            "extra": "Latency: 94.5 ns/op, Bandwidth: 646.06 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 9448316,
            "unit": "ops/sec",
            "extra": "Latency: 105.8 ns/op, Bandwidth: 2306.72 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 5962610,
            "unit": "ops/sec",
            "extra": "Latency: 167.7 ns/op, Bandwidth: 5822.86 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 84147195,
            "unit": "ops/sec",
            "extra": "Latency: 11.9 ns/op, Bandwidth: 321.00 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 88098990,
            "unit": "ops/sec",
            "extra": "Latency: 11.4 ns/op, Bandwidth: 5377.14 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 78927304,
            "unit": "ops/sec",
            "extra": "Latency: 12.7 ns/op, Bandwidth: 19269.36 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 47413255,
            "unit": "ops/sec",
            "extra": "Latency: 21.1 ns/op, Bandwidth: 46302.01 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 56694117,
            "unit": "ops/sec",
            "extra": "Latency: 17.6 ns/op, Bandwidth: 216.27 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 55078724,
            "unit": "ops/sec",
            "extra": "Latency: 18.2 ns/op, Bandwidth: 3361.74 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 46114290,
            "unit": "ops/sec",
            "extra": "Latency: 21.7 ns/op, Bandwidth: 11258.37 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 37280749,
            "unit": "ops/sec",
            "extra": "Latency: 26.8 ns/op, Bandwidth: 36406.98 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 8667881,
            "unit": "ops/sec",
            "extra": "Latency: 115.4 ns/op, Bandwidth: 33.07 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 7572156,
            "unit": "ops/sec",
            "extra": "Latency: 132.1 ns/op, Bandwidth: 462.17 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 7516980,
            "unit": "ops/sec",
            "extra": "Latency: 133.0 ns/op, Bandwidth: 1835.20 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 6697058,
            "unit": "ops/sec",
            "extra": "Latency: 149.3 ns/op, Bandwidth: 25.55 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 6080222,
            "unit": "ops/sec",
            "extra": "Latency: 164.5 ns/op, Bandwidth: 371.11 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 6353008,
            "unit": "ops/sec",
            "extra": "Latency: 157.4 ns/op, Bandwidth: 1551.03 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 19150903,
            "unit": "ops/sec",
            "extra": "Latency: 52.2 ns/op, Bandwidth: 73.05 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 16595945,
            "unit": "ops/sec",
            "extra": "Latency: 60.3 ns/op, Bandwidth: 1012.94 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 14064269,
            "unit": "ops/sec",
            "extra": "Latency: 71.1 ns/op, Bandwidth: 3433.66 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 9450386,
            "unit": "ops/sec",
            "extra": "Latency: 105.8 ns/op, Bandwidth: 9228.89 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "05cb52140a3c003e1d9294da9d4f9fed3fe88f2c",
          "message": "refactor(sync): extract wait logic and optimize lock-free waiter tracking",
          "timestamp": "2026-06-22T16:54:56Z",
          "tree_id": "04911683410163c35364b5c235f91a91ad077675",
          "url": "https://github.com/ShenChen1/ufifo/commit/05cb52140a3c003e1d9294da9d4f9fed3fe88f2c"
        },
        "date": 1782147390192,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 79660614,
            "unit": "ops/sec",
            "extra": "Latency: 12.6 ns/op, Bandwidth: 303.88 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 84770497,
            "unit": "ops/sec",
            "extra": "Latency: 11.8 ns/op, Bandwidth: 5173.98 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 81034191,
            "unit": "ops/sec",
            "extra": "Latency: 12.3 ns/op, Bandwidth: 19783.74 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 47860176,
            "unit": "ops/sec",
            "extra": "Latency: 20.9 ns/op, Bandwidth: 46738.45 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 13928556,
            "unit": "ops/sec",
            "extra": "Latency: 71.8 ns/op, Bandwidth: 54408.42 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 52979148,
            "unit": "ops/sec",
            "extra": "Latency: 18.9 ns/op, Bandwidth: 202.10 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 47932984,
            "unit": "ops/sec",
            "extra": "Latency: 20.9 ns/op, Bandwidth: 2925.60 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 43039955,
            "unit": "ops/sec",
            "extra": "Latency: 23.2 ns/op, Bandwidth: 10507.80 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 36285716,
            "unit": "ops/sec",
            "extra": "Latency: 27.6 ns/op, Bandwidth: 35435.27 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 12887108,
            "unit": "ops/sec",
            "extra": "Latency: 77.6 ns/op, Bandwidth: 50340.27 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 45112130,
            "unit": "ops/sec",
            "extra": "Latency: 22.2 ns/op, Bandwidth: 172.09 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 33945199,
            "unit": "ops/sec",
            "extra": "Latency: 29.5 ns/op, Bandwidth: 2071.85 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 28503396,
            "unit": "ops/sec",
            "extra": "Latency: 35.1 ns/op, Bandwidth: 6958.84 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 20252736,
            "unit": "ops/sec",
            "extra": "Latency: 49.4 ns/op, Bandwidth: 19778.06 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 13897028,
            "unit": "ops/sec",
            "extra": "Latency: 72.0 ns/op, Bandwidth: 53.01 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 10146673,
            "unit": "ops/sec",
            "extra": "Latency: 98.6 ns/op, Bandwidth: 619.30 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 9210454,
            "unit": "ops/sec",
            "extra": "Latency: 108.6 ns/op, Bandwidth: 2248.65 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 5223198,
            "unit": "ops/sec",
            "extra": "Latency: 191.5 ns/op, Bandwidth: 5100.78 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 84134992,
            "unit": "ops/sec",
            "extra": "Latency: 11.9 ns/op, Bandwidth: 320.95 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 78170755,
            "unit": "ops/sec",
            "extra": "Latency: 12.8 ns/op, Bandwidth: 4771.16 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 79188938,
            "unit": "ops/sec",
            "extra": "Latency: 12.6 ns/op, Bandwidth: 19333.24 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 47518883,
            "unit": "ops/sec",
            "extra": "Latency: 21.0 ns/op, Bandwidth: 46405.16 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 52222050,
            "unit": "ops/sec",
            "extra": "Latency: 19.1 ns/op, Bandwidth: 199.21 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 46525300,
            "unit": "ops/sec",
            "extra": "Latency: 21.5 ns/op, Bandwidth: 2839.68 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 46266861,
            "unit": "ops/sec",
            "extra": "Latency: 21.6 ns/op, Bandwidth: 11295.62 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 36097385,
            "unit": "ops/sec",
            "extra": "Latency: 27.7 ns/op, Bandwidth: 35251.35 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 7548486,
            "unit": "ops/sec",
            "extra": "Latency: 132.5 ns/op, Bandwidth: 28.80 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 7987218,
            "unit": "ops/sec",
            "extra": "Latency: 125.2 ns/op, Bandwidth: 487.50 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 6440667,
            "unit": "ops/sec",
            "extra": "Latency: 155.3 ns/op, Bandwidth: 1572.43 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 6448326,
            "unit": "ops/sec",
            "extra": "Latency: 155.1 ns/op, Bandwidth: 24.60 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 5905297,
            "unit": "ops/sec",
            "extra": "Latency: 169.3 ns/op, Bandwidth: 360.43 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 5355799,
            "unit": "ops/sec",
            "extra": "Latency: 186.7 ns/op, Bandwidth: 1307.57 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 17048870,
            "unit": "ops/sec",
            "extra": "Latency: 58.7 ns/op, Bandwidth: 65.04 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 15339290,
            "unit": "ops/sec",
            "extra": "Latency: 65.2 ns/op, Bandwidth: 936.24 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 13198391,
            "unit": "ops/sec",
            "extra": "Latency: 75.8 ns/op, Bandwidth: 3222.26 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 8653674,
            "unit": "ops/sec",
            "extra": "Latency: 115.6 ns/op, Bandwidth: 8450.85 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "a56494407a0e0efc550504ebbe1d84a89890427b",
          "message": "fix: prevent lost wakeup in lock-free mode\n\nRefactored synchronization loops by extracting logic into __ufifo_wait_for_space and\n__ufifo_wait_for_data. Re-checking wait condition explicitly for UFIFO_LOCK_NONE\nafter incrementing rx/tx waiters entirely closes the lost wakeup race window.",
          "timestamp": "2026-06-22T17:00:39Z",
          "tree_id": "3de7f6e6c1f6640c33d6e1cd43b8b34d640b6e4c",
          "url": "https://github.com/ShenChen1/ufifo/commit/a56494407a0e0efc550504ebbe1d84a89890427b"
        },
        "date": 1782147711095,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 93677693,
            "unit": "ops/sec",
            "extra": "Latency: 10.7 ns/op, Bandwidth: 357.35 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 104771164,
            "unit": "ops/sec",
            "extra": "Latency: 9.5 ns/op, Bandwidth: 6394.72 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 87705481,
            "unit": "ops/sec",
            "extra": "Latency: 11.4 ns/op, Bandwidth: 21412.47 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 47634561,
            "unit": "ops/sec",
            "extra": "Latency: 21.0 ns/op, Bandwidth: 46518.13 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 19928659,
            "unit": "ops/sec",
            "extra": "Latency: 50.2 ns/op, Bandwidth: 77846.33 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 46721786,
            "unit": "ops/sec",
            "extra": "Latency: 21.4 ns/op, Bandwidth: 178.23 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 46209393,
            "unit": "ops/sec",
            "extra": "Latency: 21.6 ns/op, Bandwidth: 2820.40 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 42722315,
            "unit": "ops/sec",
            "extra": "Latency: 23.4 ns/op, Bandwidth: 10430.25 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 31686368,
            "unit": "ops/sec",
            "extra": "Latency: 31.6 ns/op, Bandwidth: 30943.72 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 13943846,
            "unit": "ops/sec",
            "extra": "Latency: 71.7 ns/op, Bandwidth: 54468.15 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 44267167,
            "unit": "ops/sec",
            "extra": "Latency: 22.6 ns/op, Bandwidth: 168.87 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 16615847,
            "unit": "ops/sec",
            "extra": "Latency: 60.2 ns/op, Bandwidth: 1014.15 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 17586639,
            "unit": "ops/sec",
            "extra": "Latency: 56.9 ns/op, Bandwidth: 4293.61 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 14844260,
            "unit": "ops/sec",
            "extra": "Latency: 67.4 ns/op, Bandwidth: 14496.35 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 2455889,
            "unit": "ops/sec",
            "extra": "Latency: 407.2 ns/op, Bandwidth: 9.37 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 2265052,
            "unit": "ops/sec",
            "extra": "Latency: 441.5 ns/op, Bandwidth: 138.25 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 2133300,
            "unit": "ops/sec",
            "extra": "Latency: 468.8 ns/op, Bandwidth: 520.83 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 3176120,
            "unit": "ops/sec",
            "extra": "Latency: 314.8 ns/op, Bandwidth: 3101.68 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 102026473,
            "unit": "ops/sec",
            "extra": "Latency: 9.8 ns/op, Bandwidth: 389.20 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 106452453,
            "unit": "ops/sec",
            "extra": "Latency: 9.4 ns/op, Bandwidth: 6497.34 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 92273517,
            "unit": "ops/sec",
            "extra": "Latency: 10.8 ns/op, Bandwidth: 22527.71 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 43111585,
            "unit": "ops/sec",
            "extra": "Latency: 23.2 ns/op, Bandwidth: 42101.16 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 46167689,
            "unit": "ops/sec",
            "extra": "Latency: 21.7 ns/op, Bandwidth: 176.12 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 46184210,
            "unit": "ops/sec",
            "extra": "Latency: 21.7 ns/op, Bandwidth: 2818.86 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 42038268,
            "unit": "ops/sec",
            "extra": "Latency: 23.8 ns/op, Bandwidth: 10263.25 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 30449653,
            "unit": "ops/sec",
            "extra": "Latency: 32.8 ns/op, Bandwidth: 29735.99 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 5898235,
            "unit": "ops/sec",
            "extra": "Latency: 169.5 ns/op, Bandwidth: 22.50 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 3438964,
            "unit": "ops/sec",
            "extra": "Latency: 290.8 ns/op, Bandwidth: 209.90 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 3837645,
            "unit": "ops/sec",
            "extra": "Latency: 260.6 ns/op, Bandwidth: 936.93 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 3511157,
            "unit": "ops/sec",
            "extra": "Latency: 284.8 ns/op, Bandwidth: 13.39 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 3868807,
            "unit": "ops/sec",
            "extra": "Latency: 258.5 ns/op, Bandwidth: 236.13 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 3829238,
            "unit": "ops/sec",
            "extra": "Latency: 261.1 ns/op, Bandwidth: 934.87 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 19471954,
            "unit": "ops/sec",
            "extra": "Latency: 51.4 ns/op, Bandwidth: 74.28 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 8493768,
            "unit": "ops/sec",
            "extra": "Latency: 117.7 ns/op, Bandwidth: 518.42 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 6782697,
            "unit": "ops/sec",
            "extra": "Latency: 147.4 ns/op, Bandwidth: 1655.93 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 3983274,
            "unit": "ops/sec",
            "extra": "Latency: 251.0 ns/op, Bandwidth: 3889.92 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "a56494407a0e0efc550504ebbe1d84a89890427b",
          "message": "fix: prevent lost wakeup in lock-free mode\n\nRefactored synchronization loops by extracting logic into __ufifo_wait_for_space and\n__ufifo_wait_for_data. Re-checking wait condition explicitly for UFIFO_LOCK_NONE\nafter incrementing rx/tx waiters entirely closes the lost wakeup race window.",
          "timestamp": "2026-06-22T17:00:39Z",
          "tree_id": "3de7f6e6c1f6640c33d6e1cd43b8b34d640b6e4c",
          "url": "https://github.com/ShenChen1/ufifo/commit/a56494407a0e0efc550504ebbe1d84a89890427b"
        },
        "date": 1782148629598,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 80215497,
            "unit": "ops/sec",
            "extra": "Latency: 12.5 ns/op, Bandwidth: 306.00 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 88580008,
            "unit": "ops/sec",
            "extra": "Latency: 11.3 ns/op, Bandwidth: 5406.49 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 81527758,
            "unit": "ops/sec",
            "extra": "Latency: 12.3 ns/op, Bandwidth: 19904.24 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 47313074,
            "unit": "ops/sec",
            "extra": "Latency: 21.1 ns/op, Bandwidth: 46204.17 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 13859995,
            "unit": "ops/sec",
            "extra": "Latency: 72.2 ns/op, Bandwidth: 54140.60 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 53627557,
            "unit": "ops/sec",
            "extra": "Latency: 18.6 ns/op, Bandwidth: 204.57 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 46959719,
            "unit": "ops/sec",
            "extra": "Latency: 21.3 ns/op, Bandwidth: 2866.19 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 42290538,
            "unit": "ops/sec",
            "extra": "Latency: 23.6 ns/op, Bandwidth: 10324.84 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 36105616,
            "unit": "ops/sec",
            "extra": "Latency: 27.7 ns/op, Bandwidth: 35259.39 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 12918581,
            "unit": "ops/sec",
            "extra": "Latency: 77.4 ns/op, Bandwidth: 50463.21 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 49417833,
            "unit": "ops/sec",
            "extra": "Latency: 20.2 ns/op, Bandwidth: 188.51 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 37012669,
            "unit": "ops/sec",
            "extra": "Latency: 27.0 ns/op, Bandwidth: 2259.07 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 31124848,
            "unit": "ops/sec",
            "extra": "Latency: 32.1 ns/op, Bandwidth: 7598.84 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 22396956,
            "unit": "ops/sec",
            "extra": "Latency: 44.6 ns/op, Bandwidth: 21872.03 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 13268300,
            "unit": "ops/sec",
            "extra": "Latency: 75.4 ns/op, Bandwidth: 50.61 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 9998919,
            "unit": "ops/sec",
            "extra": "Latency: 100.0 ns/op, Bandwidth: 610.29 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 9523266,
            "unit": "ops/sec",
            "extra": "Latency: 105.0 ns/op, Bandwidth: 2325.02 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 5324858,
            "unit": "ops/sec",
            "extra": "Latency: 187.8 ns/op, Bandwidth: 5200.06 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 80940703,
            "unit": "ops/sec",
            "extra": "Latency: 12.4 ns/op, Bandwidth: 308.76 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 87277462,
            "unit": "ops/sec",
            "extra": "Latency: 11.5 ns/op, Bandwidth: 5326.99 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 78846173,
            "unit": "ops/sec",
            "extra": "Latency: 12.7 ns/op, Bandwidth: 19249.55 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 44159882,
            "unit": "ops/sec",
            "extra": "Latency: 22.6 ns/op, Bandwidth: 43124.88 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 52011460,
            "unit": "ops/sec",
            "extra": "Latency: 19.2 ns/op, Bandwidth: 198.41 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 45491623,
            "unit": "ops/sec",
            "extra": "Latency: 22.0 ns/op, Bandwidth: 2776.59 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 45240127,
            "unit": "ops/sec",
            "extra": "Latency: 22.1 ns/op, Bandwidth: 11044.95 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 34810649,
            "unit": "ops/sec",
            "extra": "Latency: 28.7 ns/op, Bandwidth: 33994.77 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 13438669,
            "unit": "ops/sec",
            "extra": "Latency: 74.4 ns/op, Bandwidth: 51.26 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 7205906,
            "unit": "ops/sec",
            "extra": "Latency: 138.8 ns/op, Bandwidth: 439.81 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 6756181,
            "unit": "ops/sec",
            "extra": "Latency: 148.0 ns/op, Bandwidth: 1649.46 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 6389271,
            "unit": "ops/sec",
            "extra": "Latency: 156.5 ns/op, Bandwidth: 24.37 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 6097228,
            "unit": "ops/sec",
            "extra": "Latency: 164.0 ns/op, Bandwidth: 372.15 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 5395846,
            "unit": "ops/sec",
            "extra": "Latency: 185.3 ns/op, Bandwidth: 1317.35 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 18965588,
            "unit": "ops/sec",
            "extra": "Latency: 52.7 ns/op, Bandwidth: 72.35 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 16447811,
            "unit": "ops/sec",
            "extra": "Latency: 60.8 ns/op, Bandwidth: 1003.89 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 13815926,
            "unit": "ops/sec",
            "extra": "Latency: 72.4 ns/op, Bandwidth: 3373.03 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 8879155,
            "unit": "ops/sec",
            "extra": "Latency: 112.6 ns/op, Bandwidth: 8671.05 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "f154bb40105ec373e924b20bf2c9ff4254b27edf",
          "message": "feat(api): unify errno reporting for data interfaces\n\n- Rejected oversized writes early across all put variants with EMSGSIZE.\n- Mapped empty/full queues to EAGAIN in non-blocking mode.\n- Passed through timeout errors (ETIMEDOUT) and epoll wait errors correctly.\n- Mapped buffer too small on read in record mode to ENOBUFS.\n- Set EIO when custom serialization hooks (recput/recget) fail.\n- Updated UFIFO_CHECK_HANDLE to consistently return EINVAL.\n- Added comprehensive unit tests and documented errno returns in public API.",
          "timestamp": "2026-06-22T17:15:52Z",
          "tree_id": "36c33adc177738a1e732bdc3f9158e684f56e250",
          "url": "https://github.com/ShenChen1/ufifo/commit/f154bb40105ec373e924b20bf2c9ff4254b27edf"
        },
        "date": 1782148775065,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 80269900,
            "unit": "ops/sec",
            "extra": "Latency: 12.5 ns/op, Bandwidth: 306.21 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 89409019,
            "unit": "ops/sec",
            "extra": "Latency: 11.2 ns/op, Bandwidth: 5457.09 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 77259202,
            "unit": "ops/sec",
            "extra": "Latency: 12.9 ns/op, Bandwidth: 18862.11 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 46308375,
            "unit": "ops/sec",
            "extra": "Latency: 21.6 ns/op, Bandwidth: 45223.02 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 13971986,
            "unit": "ops/sec",
            "extra": "Latency: 71.6 ns/op, Bandwidth: 54578.07 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 56915328,
            "unit": "ops/sec",
            "extra": "Latency: 17.6 ns/op, Bandwidth: 217.11 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 58373109,
            "unit": "ops/sec",
            "extra": "Latency: 17.1 ns/op, Bandwidth: 3562.81 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 53083755,
            "unit": "ops/sec",
            "extra": "Latency: 18.8 ns/op, Bandwidth: 12959.90 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 36197430,
            "unit": "ops/sec",
            "extra": "Latency: 27.6 ns/op, Bandwidth: 35349.05 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 12855499,
            "unit": "ops/sec",
            "extra": "Latency: 77.8 ns/op, Bandwidth: 50216.79 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 45473283,
            "unit": "ops/sec",
            "extra": "Latency: 22.0 ns/op, Bandwidth: 173.47 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 31899995,
            "unit": "ops/sec",
            "extra": "Latency: 31.3 ns/op, Bandwidth: 1947.02 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 26600681,
            "unit": "ops/sec",
            "extra": "Latency: 37.6 ns/op, Bandwidth: 6494.31 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 19671365,
            "unit": "ops/sec",
            "extra": "Latency: 50.8 ns/op, Bandwidth: 19210.32 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 14281991,
            "unit": "ops/sec",
            "extra": "Latency: 70.0 ns/op, Bandwidth: 54.48 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 10920890,
            "unit": "ops/sec",
            "extra": "Latency: 91.6 ns/op, Bandwidth: 666.56 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 9436870,
            "unit": "ops/sec",
            "extra": "Latency: 106.0 ns/op, Bandwidth: 2303.92 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 4799532,
            "unit": "ops/sec",
            "extra": "Latency: 208.4 ns/op, Bandwidth: 4687.04 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 84162600,
            "unit": "ops/sec",
            "extra": "Latency: 11.9 ns/op, Bandwidth: 321.05 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 86921090,
            "unit": "ops/sec",
            "extra": "Latency: 11.5 ns/op, Bandwidth: 5305.24 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 76439336,
            "unit": "ops/sec",
            "extra": "Latency: 13.1 ns/op, Bandwidth: 18661.95 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 46357739,
            "unit": "ops/sec",
            "extra": "Latency: 21.6 ns/op, Bandwidth: 45271.23 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 57302354,
            "unit": "ops/sec",
            "extra": "Latency: 17.5 ns/op, Bandwidth: 218.59 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 57192085,
            "unit": "ops/sec",
            "extra": "Latency: 17.5 ns/op, Bandwidth: 3490.73 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 51958799,
            "unit": "ops/sec",
            "extra": "Latency: 19.2 ns/op, Bandwidth: 12685.25 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 29979220,
            "unit": "ops/sec",
            "extra": "Latency: 33.4 ns/op, Bandwidth: 29276.58 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 8413059,
            "unit": "ops/sec",
            "extra": "Latency: 118.9 ns/op, Bandwidth: 32.09 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 7556423,
            "unit": "ops/sec",
            "extra": "Latency: 132.3 ns/op, Bandwidth: 461.21 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 6939605,
            "unit": "ops/sec",
            "extra": "Latency: 144.1 ns/op, Bandwidth: 1694.24 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 6916738,
            "unit": "ops/sec",
            "extra": "Latency: 144.6 ns/op, Bandwidth: 26.39 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 6306018,
            "unit": "ops/sec",
            "extra": "Latency: 158.6 ns/op, Bandwidth: 384.89 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 6007051,
            "unit": "ops/sec",
            "extra": "Latency: 166.5 ns/op, Bandwidth: 1466.57 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 17224773,
            "unit": "ops/sec",
            "extra": "Latency: 58.1 ns/op, Bandwidth: 65.71 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 15056114,
            "unit": "ops/sec",
            "extra": "Latency: 66.4 ns/op, Bandwidth: 918.95 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 12572699,
            "unit": "ops/sec",
            "extra": "Latency: 79.5 ns/op, Bandwidth: 3069.51 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 8030683,
            "unit": "ops/sec",
            "extra": "Latency: 124.5 ns/op, Bandwidth: 7842.46 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "f154bb40105ec373e924b20bf2c9ff4254b27edf",
          "message": "feat(api): unify errno reporting for data interfaces\n\n- Rejected oversized writes early across all put variants with EMSGSIZE.\n- Mapped empty/full queues to EAGAIN in non-blocking mode.\n- Passed through timeout errors (ETIMEDOUT) and epoll wait errors correctly.\n- Mapped buffer too small on read in record mode to ENOBUFS.\n- Set EIO when custom serialization hooks (recput/recget) fail.\n- Updated UFIFO_CHECK_HANDLE to consistently return EINVAL.\n- Added comprehensive unit tests and documented errno returns in public API.",
          "timestamp": "2026-06-22T17:15:52Z",
          "tree_id": "36c33adc177738a1e732bdc3f9158e684f56e250",
          "url": "https://github.com/ShenChen1/ufifo/commit/f154bb40105ec373e924b20bf2c9ff4254b27edf"
        },
        "date": 1782148871871,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 69272351,
            "unit": "ops/sec",
            "extra": "Latency: 14.4 ns/op, Bandwidth: 264.25 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 88197071,
            "unit": "ops/sec",
            "extra": "Latency: 11.3 ns/op, Bandwidth: 5383.12 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 81532119,
            "unit": "ops/sec",
            "extra": "Latency: 12.3 ns/op, Bandwidth: 19905.30 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 42602674,
            "unit": "ops/sec",
            "extra": "Latency: 23.5 ns/op, Bandwidth: 41604.17 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 13854053,
            "unit": "ops/sec",
            "extra": "Latency: 72.2 ns/op, Bandwidth: 54117.39 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 61235100,
            "unit": "ops/sec",
            "extra": "Latency: 16.3 ns/op, Bandwidth: 233.59 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 60740334,
            "unit": "ops/sec",
            "extra": "Latency: 16.5 ns/op, Bandwidth: 3707.30 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 57135525,
            "unit": "ops/sec",
            "extra": "Latency: 17.5 ns/op, Bandwidth: 13949.10 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 35398958,
            "unit": "ops/sec",
            "extra": "Latency: 28.2 ns/op, Bandwidth: 34569.30 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 13400939,
            "unit": "ops/sec",
            "extra": "Latency: 74.6 ns/op, Bandwidth: 52347.42 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 42313583,
            "unit": "ops/sec",
            "extra": "Latency: 23.6 ns/op, Bandwidth: 161.41 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 33138647,
            "unit": "ops/sec",
            "extra": "Latency: 30.2 ns/op, Bandwidth: 2022.62 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 25145384,
            "unit": "ops/sec",
            "extra": "Latency: 39.8 ns/op, Bandwidth: 6139.01 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 12196285,
            "unit": "ops/sec",
            "extra": "Latency: 82.0 ns/op, Bandwidth: 11910.43 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 16153303,
            "unit": "ops/sec",
            "extra": "Latency: 61.9 ns/op, Bandwidth: 61.62 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 7762104,
            "unit": "ops/sec",
            "extra": "Latency: 128.8 ns/op, Bandwidth: 473.76 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 6536804,
            "unit": "ops/sec",
            "extra": "Latency: 153.0 ns/op, Bandwidth: 1595.90 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 3009972,
            "unit": "ops/sec",
            "extra": "Latency: 332.2 ns/op, Bandwidth: 2939.43 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 89778472,
            "unit": "ops/sec",
            "extra": "Latency: 11.1 ns/op, Bandwidth: 342.48 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 83914270,
            "unit": "ops/sec",
            "extra": "Latency: 11.9 ns/op, Bandwidth: 5121.72 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 77495497,
            "unit": "ops/sec",
            "extra": "Latency: 12.9 ns/op, Bandwidth: 18919.80 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 43227340,
            "unit": "ops/sec",
            "extra": "Latency: 23.1 ns/op, Bandwidth: 42214.20 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 60287526,
            "unit": "ops/sec",
            "extra": "Latency: 16.6 ns/op, Bandwidth: 229.98 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 61337164,
            "unit": "ops/sec",
            "extra": "Latency: 16.3 ns/op, Bandwidth: 3743.72 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 55697474,
            "unit": "ops/sec",
            "extra": "Latency: 18.0 ns/op, Bandwidth: 13598.02 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 34927033,
            "unit": "ops/sec",
            "extra": "Latency: 28.6 ns/op, Bandwidth: 34108.43 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 12888339,
            "unit": "ops/sec",
            "extra": "Latency: 77.6 ns/op, Bandwidth: 49.17 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 6507181,
            "unit": "ops/sec",
            "extra": "Latency: 153.7 ns/op, Bandwidth: 397.17 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 5932188,
            "unit": "ops/sec",
            "extra": "Latency: 168.6 ns/op, Bandwidth: 1448.29 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 7386938,
            "unit": "ops/sec",
            "extra": "Latency: 135.4 ns/op, Bandwidth: 28.18 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 5381964,
            "unit": "ops/sec",
            "extra": "Latency: 185.8 ns/op, Bandwidth: 328.49 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 5505979,
            "unit": "ops/sec",
            "extra": "Latency: 181.6 ns/op, Bandwidth: 1344.23 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 19800787,
            "unit": "ops/sec",
            "extra": "Latency: 50.5 ns/op, Bandwidth: 75.53 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 16673671,
            "unit": "ops/sec",
            "extra": "Latency: 60.0 ns/op, Bandwidth: 1017.68 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 12060438,
            "unit": "ops/sec",
            "extra": "Latency: 82.9 ns/op, Bandwidth: 2944.44 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 7119659,
            "unit": "ops/sec",
            "extra": "Latency: 140.5 ns/op, Bandwidth: 6952.79 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "f154bb40105ec373e924b20bf2c9ff4254b27edf",
          "message": "feat(api): unify errno reporting for data interfaces\n\n- Rejected oversized writes early across all put variants with EMSGSIZE.\n- Mapped empty/full queues to EAGAIN in non-blocking mode.\n- Passed through timeout errors (ETIMEDOUT) and epoll wait errors correctly.\n- Mapped buffer too small on read in record mode to ENOBUFS.\n- Set EIO when custom serialization hooks (recput/recget) fail.\n- Updated UFIFO_CHECK_HANDLE to consistently return EINVAL.\n- Added comprehensive unit tests and documented errno returns in public API.",
          "timestamp": "2026-06-22T17:15:52Z",
          "tree_id": "36c33adc177738a1e732bdc3f9158e684f56e250",
          "url": "https://github.com/ShenChen1/ufifo/commit/f154bb40105ec373e924b20bf2c9ff4254b27edf"
        },
        "date": 1782148923868,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 70158591,
            "unit": "ops/sec",
            "extra": "Latency: 14.3 ns/op, Bandwidth: 267.63 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 88133052,
            "unit": "ops/sec",
            "extra": "Latency: 11.3 ns/op, Bandwidth: 5379.21 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 82436833,
            "unit": "ops/sec",
            "extra": "Latency: 12.1 ns/op, Bandwidth: 20126.18 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 42560925,
            "unit": "ops/sec",
            "extra": "Latency: 23.5 ns/op, Bandwidth: 41563.40 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 14288451,
            "unit": "ops/sec",
            "extra": "Latency: 70.0 ns/op, Bandwidth: 55814.26 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 56254310,
            "unit": "ops/sec",
            "extra": "Latency: 17.8 ns/op, Bandwidth: 214.59 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 58766468,
            "unit": "ops/sec",
            "extra": "Latency: 17.0 ns/op, Bandwidth: 3586.82 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 55185027,
            "unit": "ops/sec",
            "extra": "Latency: 18.1 ns/op, Bandwidth: 13472.91 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 33390392,
            "unit": "ops/sec",
            "extra": "Latency: 29.9 ns/op, Bandwidth: 32607.80 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 13388168,
            "unit": "ops/sec",
            "extra": "Latency: 74.7 ns/op, Bandwidth: 52297.53 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 43833284,
            "unit": "ops/sec",
            "extra": "Latency: 22.8 ns/op, Bandwidth: 167.21 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 31402614,
            "unit": "ops/sec",
            "extra": "Latency: 31.8 ns/op, Bandwidth: 1916.66 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 24627360,
            "unit": "ops/sec",
            "extra": "Latency: 40.6 ns/op, Bandwidth: 6012.54 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 11919371,
            "unit": "ops/sec",
            "extra": "Latency: 83.9 ns/op, Bandwidth: 11640.01 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 15216579,
            "unit": "ops/sec",
            "extra": "Latency: 65.7 ns/op, Bandwidth: 58.05 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 6983985,
            "unit": "ops/sec",
            "extra": "Latency: 143.2 ns/op, Bandwidth: 426.27 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 5865999,
            "unit": "ops/sec",
            "extra": "Latency: 170.5 ns/op, Bandwidth: 1432.13 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 2901798,
            "unit": "ops/sec",
            "extra": "Latency: 344.6 ns/op, Bandwidth: 2833.79 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 87156724,
            "unit": "ops/sec",
            "extra": "Latency: 11.5 ns/op, Bandwidth: 332.48 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 88243693,
            "unit": "ops/sec",
            "extra": "Latency: 11.3 ns/op, Bandwidth: 5385.97 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 80617441,
            "unit": "ops/sec",
            "extra": "Latency: 12.4 ns/op, Bandwidth: 19681.99 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 43894272,
            "unit": "ops/sec",
            "extra": "Latency: 22.8 ns/op, Bandwidth: 42865.50 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 60533151,
            "unit": "ops/sec",
            "extra": "Latency: 16.5 ns/op, Bandwidth: 230.92 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 61200912,
            "unit": "ops/sec",
            "extra": "Latency: 16.3 ns/op, Bandwidth: 3735.41 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 56209047,
            "unit": "ops/sec",
            "extra": "Latency: 17.8 ns/op, Bandwidth: 13722.91 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 34460221,
            "unit": "ops/sec",
            "extra": "Latency: 29.0 ns/op, Bandwidth: 33652.56 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 8530341,
            "unit": "ops/sec",
            "extra": "Latency: 117.2 ns/op, Bandwidth: 32.54 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 5903689,
            "unit": "ops/sec",
            "extra": "Latency: 169.4 ns/op, Bandwidth: 360.33 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 5963060,
            "unit": "ops/sec",
            "extra": "Latency: 167.7 ns/op, Bandwidth: 1455.83 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 7208201,
            "unit": "ops/sec",
            "extra": "Latency: 138.7 ns/op, Bandwidth: 27.50 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 5519482,
            "unit": "ops/sec",
            "extra": "Latency: 181.2 ns/op, Bandwidth: 336.88 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 5243423,
            "unit": "ops/sec",
            "extra": "Latency: 190.7 ns/op, Bandwidth: 1280.13 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 18395569,
            "unit": "ops/sec",
            "extra": "Latency: 54.4 ns/op, Bandwidth: 70.17 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 16198155,
            "unit": "ops/sec",
            "extra": "Latency: 61.7 ns/op, Bandwidth: 988.66 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 12486951,
            "unit": "ops/sec",
            "extra": "Latency: 80.1 ns/op, Bandwidth: 3048.57 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 7019231,
            "unit": "ops/sec",
            "extra": "Latency: 142.5 ns/op, Bandwidth: 6854.72 MB/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "committer": {
            "email": "peterchenshen@gmail.com",
            "name": "Peter Shen",
            "username": "ShenChen1"
          },
          "distinct": true,
          "id": "f154bb40105ec373e924b20bf2c9ff4254b27edf",
          "message": "feat(api): unify errno reporting for data interfaces\n\n- Rejected oversized writes early across all put variants with EMSGSIZE.\n- Mapped empty/full queues to EAGAIN in non-blocking mode.\n- Passed through timeout errors (ETIMEDOUT) and epoll wait errors correctly.\n- Mapped buffer too small on read in record mode to ENOBUFS.\n- Set EIO when custom serialization hooks (recput/recget) fail.\n- Updated UFIFO_CHECK_HANDLE to consistently return EINVAL.\n- Added comprehensive unit tests and documented errno returns in public API.",
          "timestamp": "2026-06-22T17:15:52Z",
          "tree_id": "36c33adc177738a1e732bdc3f9158e684f56e250",
          "url": "https://github.com/ShenChen1/ufifo/commit/f154bb40105ec373e924b20bf2c9ff4254b27edf"
        },
        "date": 1782149026314,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "PingPong/nolock/4B",
            "value": 70510743,
            "unit": "ops/sec",
            "extra": "Latency: 14.2 ns/op, Bandwidth: 268.98 MB/s"
          },
          {
            "name": "PingPong/nolock/64B",
            "value": 86913541,
            "unit": "ops/sec",
            "extra": "Latency: 11.5 ns/op, Bandwidth: 5304.78 MB/s"
          },
          {
            "name": "PingPong/nolock/256B",
            "value": 79369331,
            "unit": "ops/sec",
            "extra": "Latency: 12.6 ns/op, Bandwidth: 19377.28 MB/s"
          },
          {
            "name": "PingPong/nolock/1024B",
            "value": 41900508,
            "unit": "ops/sec",
            "extra": "Latency: 23.9 ns/op, Bandwidth: 40918.47 MB/s"
          },
          {
            "name": "PingPong/nolock/4096B",
            "value": 14328900,
            "unit": "ops/sec",
            "extra": "Latency: 69.8 ns/op, Bandwidth: 55972.27 MB/s"
          },
          {
            "name": "PingPong/locked/4B",
            "value": 59650469,
            "unit": "ops/sec",
            "extra": "Latency: 16.8 ns/op, Bandwidth: 227.55 MB/s"
          },
          {
            "name": "PingPong/locked/64B",
            "value": 62199997,
            "unit": "ops/sec",
            "extra": "Latency: 16.1 ns/op, Bandwidth: 3796.39 MB/s"
          },
          {
            "name": "PingPong/locked/256B",
            "value": 56237904,
            "unit": "ops/sec",
            "extra": "Latency: 17.8 ns/op, Bandwidth: 13729.96 MB/s"
          },
          {
            "name": "PingPong/locked/1024B",
            "value": 34417604,
            "unit": "ops/sec",
            "extra": "Latency: 29.1 ns/op, Bandwidth: 33610.94 MB/s"
          },
          {
            "name": "PingPong/locked/4096B",
            "value": 13413300,
            "unit": "ops/sec",
            "extra": "Latency: 74.6 ns/op, Bandwidth: 52395.70 MB/s"
          },
          {
            "name": "SPSC/nolock/4B",
            "value": 49843849,
            "unit": "ops/sec",
            "extra": "Latency: 20.1 ns/op, Bandwidth: 190.14 MB/s"
          },
          {
            "name": "SPSC/nolock/64B",
            "value": 52509952,
            "unit": "ops/sec",
            "extra": "Latency: 19.0 ns/op, Bandwidth: 3204.95 MB/s"
          },
          {
            "name": "SPSC/nolock/256B",
            "value": 35052482,
            "unit": "ops/sec",
            "extra": "Latency: 28.5 ns/op, Bandwidth: 8557.73 MB/s"
          },
          {
            "name": "SPSC/nolock/1024B",
            "value": 11444337,
            "unit": "ops/sec",
            "extra": "Latency: 87.4 ns/op, Bandwidth: 11176.11 MB/s"
          },
          {
            "name": "SPSC/locked/4B",
            "value": 15586338,
            "unit": "ops/sec",
            "extra": "Latency: 64.2 ns/op, Bandwidth: 59.46 MB/s"
          },
          {
            "name": "SPSC/locked/64B",
            "value": 7607661,
            "unit": "ops/sec",
            "extra": "Latency: 131.4 ns/op, Bandwidth: 464.33 MB/s"
          },
          {
            "name": "SPSC/locked/256B",
            "value": 6997221,
            "unit": "ops/sec",
            "extra": "Latency: 142.9 ns/op, Bandwidth: 1708.31 MB/s"
          },
          {
            "name": "SPSC/locked/1024B",
            "value": 3047294,
            "unit": "ops/sec",
            "extra": "Latency: 328.2 ns/op, Bandwidth: 2975.87 MB/s"
          },
          {
            "name": "Burst/nolock/4B",
            "value": 86967799,
            "unit": "ops/sec",
            "extra": "Latency: 11.5 ns/op, Bandwidth: 331.76 MB/s"
          },
          {
            "name": "Burst/nolock/64B",
            "value": 86835817,
            "unit": "ops/sec",
            "extra": "Latency: 11.5 ns/op, Bandwidth: 5300.04 MB/s"
          },
          {
            "name": "Burst/nolock/256B",
            "value": 79613359,
            "unit": "ops/sec",
            "extra": "Latency: 12.6 ns/op, Bandwidth: 19436.86 MB/s"
          },
          {
            "name": "Burst/nolock/1024B",
            "value": 43509666,
            "unit": "ops/sec",
            "extra": "Latency: 23.0 ns/op, Bandwidth: 42489.91 MB/s"
          },
          {
            "name": "Burst/locked/4B",
            "value": 59663517,
            "unit": "ops/sec",
            "extra": "Latency: 16.8 ns/op, Bandwidth: 227.60 MB/s"
          },
          {
            "name": "Burst/locked/64B",
            "value": 60940161,
            "unit": "ops/sec",
            "extra": "Latency: 16.4 ns/op, Bandwidth: 3719.49 MB/s"
          },
          {
            "name": "Burst/locked/256B",
            "value": 49394002,
            "unit": "ops/sec",
            "extra": "Latency: 20.2 ns/op, Bandwidth: 12059.08 MB/s"
          },
          {
            "name": "Burst/locked/1024B",
            "value": 34742039,
            "unit": "ops/sec",
            "extra": "Latency: 28.8 ns/op, Bandwidth: 33927.77 MB/s"
          },
          {
            "name": "MPSC/2P/4B",
            "value": 11818658,
            "unit": "ops/sec",
            "extra": "Latency: 84.6 ns/op, Bandwidth: 45.08 MB/s"
          },
          {
            "name": "MPSC/2P/64B",
            "value": 6336955,
            "unit": "ops/sec",
            "extra": "Latency: 157.8 ns/op, Bandwidth: 386.78 MB/s"
          },
          {
            "name": "MPSC/2P/256B",
            "value": 5606473,
            "unit": "ops/sec",
            "extra": "Latency: 178.4 ns/op, Bandwidth: 1368.77 MB/s"
          },
          {
            "name": "MPSC/4P/4B",
            "value": 7825121,
            "unit": "ops/sec",
            "extra": "Latency: 127.8 ns/op, Bandwidth: 29.85 MB/s"
          },
          {
            "name": "MPSC/4P/64B",
            "value": 6216318,
            "unit": "ops/sec",
            "extra": "Latency: 160.9 ns/op, Bandwidth: 379.41 MB/s"
          },
          {
            "name": "MPSC/4P/256B",
            "value": 5462669,
            "unit": "ops/sec",
            "extra": "Latency: 183.1 ns/op, Bandwidth: 1333.66 MB/s"
          },
          {
            "name": "SharedSPSC/4B",
            "value": 19550567,
            "unit": "ops/sec",
            "extra": "Latency: 51.1 ns/op, Bandwidth: 74.58 MB/s"
          },
          {
            "name": "SharedSPSC/64B",
            "value": 16674985,
            "unit": "ops/sec",
            "extra": "Latency: 60.0 ns/op, Bandwidth: 1017.76 MB/s"
          },
          {
            "name": "SharedSPSC/256B",
            "value": 12585842,
            "unit": "ops/sec",
            "extra": "Latency: 79.5 ns/op, Bandwidth: 3072.72 MB/s"
          },
          {
            "name": "SharedSPSC/1024B",
            "value": 7139135,
            "unit": "ops/sec",
            "extra": "Latency: 140.1 ns/op, Bandwidth: 6971.81 MB/s"
          }
        ]
      }
    ]
  }
}