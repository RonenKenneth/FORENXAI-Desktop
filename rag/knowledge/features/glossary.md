# Flow feature glossary

Plain-English definitions for every feature `artifacts/mc_random/XGBoost.pkl` was trained on.

**Generated from `config/feature_glossary.py` — edit there, not here.** That file is checked against `features.pkl`, so a definition cannot drift away from the model without the check failing.

**Direction.** *Forward* (Fwd) is client → server, the direction that opened the connection. *Backward* (Bwd) is server → client. Reversing this inverts about half these definitions.

**Units.** Times are microseconds, lengths are bytes. `Flow Duration` of 4,200,000 is 4.2 seconds.

## Identity

| Feature | Plain English |
|---|---|
| `Dst Port` | destination port -- effectively which service was contacted (22 SSH, 80 HTTP, 443 HTTPS, 53 DNS) |
| `Protocol` | transport protocol number (6 TCP, 17 UDP, 1 ICMP) |

## Duration and rate

| Feature | Plain English |
|---|---|
| `Down/Up Ratio` | downloaded bytes over uploaded bytes -- high means the server sent far more than it received, low is what exfiltration looks like |
| `Flow Bytes/s` | throughput -- bytes per second across the whole conversation |
| `Flow Duration` | how long the conversation lasted |
| `Flow Packets/s` | packets per second across the whole conversation |

## Volume

| Feature | Plain English |
|---|---|
| `Subflow Bwd Bytes` | average bytes per inbound burst |
| `Subflow Bwd Packets` | average packets per inbound burst |
| `Subflow Fwd Bytes` | average bytes per outbound burst -- the client's typical burst size |
| `Subflow Fwd Packets` | average packets per outbound burst |
| `Total Bwd packets` | number of packets the server sent |
| `Total Fwd Packet` | number of packets the client sent |
| `Total Length of Bwd Packet` | total bytes the server sent |
| `Total Length of Fwd Packet` | total bytes the client sent |

## Packet size

| Feature | Plain English |
|---|---|
| `Average Packet Size` | mean size of every packet in the conversation |
| `Bwd Packet Length Max` | largest inbound packet -- a large value means the server returned something substantial |
| `Bwd Packet Length Mean` | average inbound packet size |
| `Bwd Packet Length Min` | smallest inbound packet |
| `Bwd Packet Length Std` | how much inbound packet sizes varied |
| `Fwd Packet Length Max` | largest outbound packet |
| `Fwd Packet Length Mean` | average outbound packet size |
| `Fwd Packet Length Min` | smallest outbound packet |
| `Fwd Packet Length Std` | how much outbound packet sizes varied |
| `Packet Length Max` | largest packet in either direction |
| `Packet Length Mean` | average packet size in either direction (computed slightly differently from Average Packet Size, which is why both exist) |
| `Packet Length Min` | smallest packet in either direction |
| `Packet Length Std` | how much packet sizes varied -- low means uniform, machine-generated traffic |
| `Packet Length Variance` | spread of packet sizes across the connection |

## Timing between packets

| Feature | Plain English |
|---|---|
| `Bwd IAT Max` | longest pause between inbound packets |
| `Bwd IAT Mean` | average gap between inbound packets |
| `Bwd IAT Min` | shortest gap between inbound packets |
| `Bwd IAT Std` | how irregular the gaps between inbound packets were -- very low is a hallmark of beaconing, a machine answering on a schedule |
| `Bwd IAT Total` | total idle time in the inbound direction |
| `Flow IAT Max` | longest gap between any two packets -- a large value means the connection sat idle, characteristic of one held open deliberately |
| `Flow IAT Mean` | average gap between packets in either direction |
| `Flow IAT Min` | shortest gap between any two packets |
| `Flow IAT Std` | how irregular the packet gaps were |
| `Fwd IAT Max` | longest pause between outbound packets |
| `Fwd IAT Mean` | average gap between outbound packets |
| `Fwd IAT Min` | shortest gap between outbound packets -- near zero means packets sent back to back, typically automated |
| `Fwd IAT Std` | how irregular the gaps between outbound packets were |
| `Fwd IAT Total` | total time spanned by the client's packets |

## Active and idle periods

| Feature | Plain English |
|---|---|
| `Active Max` | longest continuous burst of transmission |
| `Active Mean` | average length of a continuous burst of transmission |
| `Active Min` | shortest burst of transmission |
| `Active Std` | how much burst lengths varied |
| `Idle Max` | longest period the connection sat idle |
| `Idle Mean` | average length of a quiet period |
| `Idle Min` | shortest idle period |
| `Idle Std` | how much idle period lengths varied |

## TCP flags

| Feature | Plain English |
|---|---|
| `ACK Flag Count` | acknowledgements |
| `Bwd PSH Flags` | server pushes requesting immediate delivery |
| `Bwd URG Flags` | urgent markers set by the server |
| `CWR Flag Count` | congestion window reduced -- the sender slowing down after congestion (spelled CWE in some source files; folded to CWR here) |
| `ECE Flag Count` | network congestion notifications |
| `FIN Flag Count` | orderly connection closes |
| `Fwd PSH Flags` | client pushes requesting immediate delivery |
| `Fwd URG Flags` | urgent markers set by the client |
| `PSH Flag Count` | pushes requesting immediate delivery rather than buffering |
| `RST Flag Count` | abrupt resets -- high counts mean connections refused or dropped, typical of scanning a closed port |
| `SYN Flag Count` | connection-open requests -- many with few completions indicates scanning or SYN flooding |
| `URG Flag Count` | urgent-data markers -- rare in normal traffic |

## Headers and windows

| Feature | Plain English |
|---|---|
| `Bwd Header Length` | total header bytes in inbound packets |
| `Bwd Init Win Bytes` | TCP receive window the server advertised at connection open |
| `Bwd Segment Size Avg` | average inbound payload segment size |
| `FWD Init Win Bytes` | TCP receive window the client advertised at connection open -- partly an operating-system fingerprint |
| `Fwd Header Length` | total header bytes in outbound packets -- large relative to payload suggests many small packets |
| `Fwd Segment Size Avg` | average outbound payload segment size |

## Bulk transfer

| Feature | Plain English |
|---|---|
| `Bwd Bulk Rate Avg` | how fast the server moved data during sustained bursts |
| `Bwd Bytes/Bulk Avg` | average bytes per inbound burst |
| `Bwd Packet/Bulk Avg` | average packets per inbound burst |
| `Fwd Bulk Rate Avg` | how fast the client moved data during sustained bursts |
| `Fwd Bytes/Bulk Avg` | average bytes per outbound burst |
| `Fwd Packet/Bulk Avg` | average packets per outbound burst |

## Features that need a warning shown with them

- **`Dst Port`** — Often the strongest single signal, and worth suspicion for that reason: a model leaning on port number may have learned the lab's service layout rather than the attack.
- **`FWD Init Win Bytes`** — Partly an OS fingerprint. Phase 11 ablated it to test whether the model was recognising the capture host; removing it changed macro F1 by 0.0002, so it is not carrying the result.
- **`Bwd Init Win Bytes`** — See FWD Init Win Bytes.
- **`Bwd PSH Flags`** — Constant zero throughout the binary training data but non-zero in TRUSTLab, so it enters those models unscaled. See knowledge/datasets/scope.md.
- **`Bwd URG Flags`** — Constant zero in the binary training data. See Bwd PSH Flags.
- **`Fwd Bulk Rate Avg`** — Constant zero in the binary training data. See Bwd PSH Flags.
- **`Fwd Bytes/Bulk Avg`** — Constant zero in the binary training data. See Bwd PSH Flags.
- **`Fwd Packet/Bulk Avg`** — Constant zero in the binary training data. See Bwd PSH Flags.
- **`Flow Duration`** — Capped by the extractor's flow timeout. Training data stops at 120 s; TRUSTLab runs to 15,717 s. A mismatch here invalidates every timing feature -- see deploy/README.md section 3.

---

## Reading these honestly

A high attribution means the model weighted the feature, not that the feature caused the behaviour. Several of these move together — `Packet Length Mean`, `Max` and `Std` are not independent — so credit is shared between them in ways that look arbitrary. See `interpretability/caveats.md`.

Covers 74 of 74 features.
