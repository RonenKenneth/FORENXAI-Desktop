"""
Schema reconciliation across three datasets.

THE PROBLEM
CICFlowMeter has changed its column names between versions, and the three
datasets were extracted at different times with different builds. Worse,
TRUSTLab is internally inconsistent -- its sixteen files use three different
layouts.

    CICIDS2018    V3 abbreviated ("Tot Fwd Pkts"), carries the CWE typo
    TII-SSRC-23   V4 full-length ("Total Fwd Packet")
    TRUSTLab      V3 abbreviated despite its paper claiming v4.0, with three
                  internal variants:
                    A (79 cols)  most attack files, uses "CWR Flag Cnt"
                    B (79 cols)  DDoS/DoS/PortScan/Slowloris, uses "CWE Flag
                                 Count" and orders bulk/header columns
                                 differently
                    C (81 cols)  Benign only -- has BOTH "CWE Flag Count" and
                                 an appended duplicate "CWR Flag Cnt", plus a
                                 "Source File" column

Everything is normalised to V4 full-length names, because that is what a
current CICFlowMeter emits and therefore what the deployed model will receive.

WHY COLUMN ORDER MATTERS
TRUSTLab schemas A and B contain the same column NAMES but in different
positions -- specifically positions 57 to 64, where the bulk-transfer and
header-length columns are interleaved differently. Loading by position would
place backward bulk-byte values into a forward bulk-packet column and raise
no error at all. Every load in this pipeline selects by name.
"""

# --------------------------------------------------------------------------
# Abbreviated (V3) -> full-length (V4)
#
# Note the two CWE/CWR entries: the actual TCP flag is CWR (Congestion Window
# Reduced). "CWE" is an unrelated acronym and is a long-standing CICFlowMeter
# typo. Both spellings fold to the correct one.
# --------------------------------------------------------------------------
V3_TO_V4 = {
    "Tot Fwd Pkts":       "Total Fwd Packet",
    "Tot Bwd Pkts":       "Total Bwd packets",
    "TotLen Fwd Pkts":    "Total Length of Fwd Packet",
    "TotLen Bwd Pkts":    "Total Length of Bwd Packet",
    "Fwd Pkt Len Max":    "Fwd Packet Length Max",
    "Fwd Pkt Len Min":    "Fwd Packet Length Min",
    "Fwd Pkt Len Mean":   "Fwd Packet Length Mean",
    "Fwd Pkt Len Std":    "Fwd Packet Length Std",
    "Bwd Pkt Len Max":    "Bwd Packet Length Max",
    "Bwd Pkt Len Min":    "Bwd Packet Length Min",
    "Bwd Pkt Len Mean":   "Bwd Packet Length Mean",
    "Bwd Pkt Len Std":    "Bwd Packet Length Std",
    "Pkt Len Min":        "Packet Length Min",
    "Pkt Len Max":        "Packet Length Max",
    "Pkt Len Mean":       "Packet Length Mean",
    "Pkt Len Std":        "Packet Length Std",
    "Pkt Len Var":        "Packet Length Variance",
    "Flow Byts/s":        "Flow Bytes/s",
    "Flow Pkts/s":        "Flow Packets/s",
    "Fwd Pkts/s":         "Fwd Packets/s",
    "Bwd Pkts/s":         "Bwd Packets/s",
    "Fwd IAT Tot":        "Fwd IAT Total",
    "Bwd IAT Tot":        "Bwd IAT Total",
    "FIN Flag Cnt":       "FIN Flag Count",
    "SYN Flag Cnt":       "SYN Flag Count",
    "RST Flag Cnt":       "RST Flag Count",
    "PSH Flag Cnt":       "PSH Flag Count",
    "ACK Flag Cnt":       "ACK Flag Count",
    "URG Flag Cnt":       "URG Flag Count",
    "CWR Flag Cnt":       "CWR Flag Count",
    "CWE Flag Count":     "CWR Flag Count",     # CICFlowMeter typo
    "ECE Flag Cnt":       "ECE Flag Count",
    "Pkt Size Avg":       "Average Packet Size",
    "Fwd Seg Size Avg":   "Fwd Segment Size Avg",
    "Bwd Seg Size Avg":   "Bwd Segment Size Avg",
    "Fwd Header Len":     "Fwd Header Length",
    "Bwd Header Len":     "Bwd Header Length",
    "Fwd Byts/b Avg":     "Fwd Bytes/Bulk Avg",
    "Bwd Byts/b Avg":     "Bwd Bytes/Bulk Avg",
    "Fwd Pkts/b Avg":     "Fwd Packet/Bulk Avg",
    "Bwd Pkts/b Avg":     "Bwd Packet/Bulk Avg",
    "Fwd Blk Rate Avg":   "Fwd Bulk Rate Avg",
    "Bwd Blk Rate Avg":   "Bwd Bulk Rate Avg",
    "Subflow Fwd Pkts":   "Subflow Fwd Packets",
    "Subflow Fwd Byts":   "Subflow Fwd Bytes",
    "Subflow Bwd Pkts":   "Subflow Bwd Packets",
    "Subflow Bwd Byts":   "Subflow Bwd Bytes",
    "Init Fwd Win Byts":  "FWD Init Win Bytes",
    "Init Bwd Win Byts":  "Bwd Init Win Bytes",
}

# --------------------------------------------------------------------------
# Columns that are identifiers or labels, never features.
#
# Src IP and Dst IP would let a model memorise which machines were attackers
# in a particular testbed -- useless on any other network. Timestamp would let
# it memorise capture dates. Src Port is usually an ephemeral random value.
#
# Dst Port and Protocol ARE kept: destination port identifies the targeted
# service, and protocol is genuinely discriminative.
# --------------------------------------------------------------------------
NON_FEATURES = {
    "Flow ID", "Src IP", "Src Port", "Dst IP", "Timestamp",
    "Label", "Traffic Type", "Traffic Subtype",
    "Source File", "folder_class", "binary_label", "source_dataset",
}

# TRUSTLab does not export these four. CICIDS2018 and TII-SSRC-23 both do, so
# they are lost to the intersection. Two of them survived Boruta selection in
# earlier work on this data, so the loss is real -- record it in limitations.
ABSENT_FROM_TRUSTLAB = [
    "Fwd Packets/s", "Bwd Packets/s", "Fwd Act Data Pkts", "Fwd Seg Size Min",
]

# Present in TRUSTLab's files by name, but not populated with a measurement.
# Verified over all 1,400,000 interim rows and all sixteen class files:
#
#   Active Min, Active Std, Idle Min, Idle Std   identically 0 in every row
#   Active Max == Idle Max                       in 100% of rows
#   Active Mean == Idle Mean                     in 100% of rows
#   Active Mean * 2 == Active Max                in 100% of rows
#   Active Max == Flow Duration / 1e6            to float32 precision
#
# A flow cannot have its longest active burst equal its longest idle gap, so
# these are not measurements at a different scale -- they are deterministic
# functions of Flow Duration, which is itself a feature. Four carry no
# variance at all and the other four carry nothing Flow Duration does not
# already carry.
#
# Why this matters rather than being harmless: both training sources DO
# populate these columns with real active/idle statistics, so a model trained
# on CICIDS2018 or TII-SSRC-23 learns a genuine response to them and then
# meets a copy of Flow Duration at test time on TRUSTLab. That is a silent
# corruption of the cross-dataset comparison, and it survives any rescaling --
# multiplying by 1e6 would only make the duplication exact.
#
# They are dropped from the shared feature set for that reason. Script 04
# excludes them when computing the intersection, so the contract is 66
# features rather than 74. Dropping is the conservative repair: it costs the
# source datasets four real features, but it cannot manufacture agreement
# between the corpora the way imputing or rescaling would.
DEGENERATE_IN_TRUSTLAB = [
    "Active Max", "Active Mean", "Active Min", "Active Std",
    "Idle Max", "Idle Mean", "Idle Min", "Idle Std",
]


def to_v4(columns):
    """Map any list of column names to V4 convention."""
    return [V3_TO_V4.get(str(c).strip(), str(c).strip()) for c in columns]


def normalise(df):
    """
    Rename a dataframe's columns to V4 and drop duplicates.

    The duplicate drop matters for TRUSTLab's Benign file, which contains both
    "CWE Flag Count" and "CWR Flag Cnt". After renaming, both become
    "CWR Flag Count" and the second is discarded. The first is kept because it
    sits in its original position; the appended one appears to be a later
    patch and its provenance is less certain.
    """
    df = df.copy()
    df.columns = to_v4(df.columns)
    return df.loc[:, ~df.columns.duplicated(keep="first")]


def feature_columns(columns):
    """Features only, sorted so the order is deterministic across runs."""
    return sorted(set(str(c).strip() for c in columns) - NON_FEATURES)
