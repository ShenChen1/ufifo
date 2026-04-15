window.BENCHMARK_DATA = {
  "lastUpdate": 1776274664905,
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
      }
    ]
  }
}