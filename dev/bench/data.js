window.BENCHMARK_DATA = {
  "lastUpdate": 1777307027027,
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
      }
    ]
  }
}