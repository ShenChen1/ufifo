window.BENCHMARK_DATA = {
  "lastUpdate": 1776104014663,
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
      }
    ]
  }
}