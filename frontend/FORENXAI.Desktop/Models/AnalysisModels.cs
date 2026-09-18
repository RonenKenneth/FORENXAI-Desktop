using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace FORENXAI.Desktop.Models;


// ============================================================
// ROOT ANALYSIS DOCUMENT
// ============================================================

public class AnalysisDocument
{
    [JsonPropertyName("case_id")]
    public string CaseId { get; set; } = string.Empty;

    [JsonPropertyName("file_name")]
    public string FileName { get; set; } = string.Empty;

    [JsonPropertyName("sha256")]
    public string Sha256 { get; set; } = string.Empty;

    [JsonPropertyName("file_size")]
    public long FileSize { get; set; }

    [JsonPropertyName("traffic_summary")]
    public TrafficSummary? TrafficSummary { get; set; }

    [JsonPropertyName("flow_summary")]
    public FlowSummary? FlowSummary { get; set; }

    [JsonPropertyName("ml_analysis")]
    public MlAnalysis? MlAnalysis { get; set; }

    [JsonPropertyName("shap_analysis")]
    public ShapAnalysis? ShapAnalysis { get; set; }
}


// ============================================================
// TRAFFIC SUMMARY
// ============================================================

public class TrafficSummary
{
    [JsonPropertyName("total_packets")]
    public int TotalPackets { get; set; }

    [JsonPropertyName("total_bytes")]
    public long TotalBytes { get; set; }

    [JsonPropertyName("protocols")]
    public Dictionary<string, int> Protocols { get; set; } = new();
}


// ============================================================
// FLOW SUMMARY
// ============================================================

public class FlowSummary
{
    [JsonPropertyName("total_flows")]
    public int TotalFlows { get; set; }
}


// ============================================================
// MACHINE LEARNING ANALYSIS
// ============================================================

public class MlAnalysis
{
    [JsonPropertyName("flow_csv")]
    public string FlowCsv { get; set; } = string.Empty;

    [JsonPropertyName("summary")]
    public MlSummary? Summary { get; set; }

    [JsonPropertyName("findings")]
    public List<MlFinding> Findings { get; set; } = new();
}


// ============================================================
// MACHINE LEARNING SUMMARY
// ============================================================

public class MlSummary
{
    [JsonPropertyName("total_flows")]
    public int TotalFlows { get; set; }

    [JsonPropertyName("benign_flows")]
    public int BenignFlows { get; set; }

    [JsonPropertyName("threat_flows")]
    public int ThreatFlows { get; set; }

    [JsonPropertyName("threat_percentage")]
    public double ThreatPercentage { get; set; }

    [JsonPropertyName("class_counts")]
    public Dictionary<string, int> ClassCounts { get; set; } = new();
}


// ============================================================
// INDIVIDUAL MACHINE LEARNING FINDING
// ============================================================

public class MlFinding
{
    [JsonPropertyName("flow_index")]
    public int FlowIndex { get; set; }

    [JsonPropertyName("predicted_class")]
    public string PredictedClass { get; set; } = string.Empty;

    [JsonPropertyName("confidence")]
    public double Confidence { get; set; }

    [JsonPropertyName("is_threat")]
    public bool IsThreat { get; set; }

    [JsonPropertyName("probabilities")]
    public Dictionary<string, double> Probabilities { get; set; } = new();

    [JsonPropertyName("metadata")]
    public FlowMetadata Metadata { get; set; } = new();


    // ========================================================
    // PHASE 15.3 - RECOMMENDATION
    // ========================================================

    [JsonPropertyName("recommendation")]
    public RecommendationData? Recommendation { get; set; }
}


// ============================================================
// FLOW METADATA
// ============================================================

public class FlowMetadata
{
    [JsonPropertyName("Flow ID")]
    public string FlowId { get; set; } = string.Empty;

    [JsonPropertyName("Src IP")]
    public string SrcIp { get; set; } = string.Empty;

    [JsonPropertyName("Src Port")]
    public int SrcPort { get; set; }

    [JsonPropertyName("Dst IP")]
    public string DstIp { get; set; } = string.Empty;

    [JsonPropertyName("Dst Port")]
    public int DstPort { get; set; }

    [JsonPropertyName("Protocol")]
    public int Protocol { get; set; }

    [JsonPropertyName("Timestamp")]
    public string Timestamp { get; set; } = string.Empty;
}


// ============================================================
// PHASE 15.3 - RECOMMENDATION DATA
// ============================================================

public class RecommendationData
{
    [JsonPropertyName("predicted_class")]
    public string PredictedClass { get; set; } = string.Empty;

    [JsonPropertyName("summary")]
    public string Summary { get; set; } = string.Empty;

    [JsonPropertyName("actions")]
    public List<string> Actions { get; set; } = new();
}


// ============================================================
// SHAP ANALYSIS
// ============================================================

public class ShapAnalysis
{
    [JsonPropertyName("total_flows")]
    public int TotalFlows { get; set; }

    [JsonPropertyName("top_features_per_flow")]
    public Dictionary<string, List<ShapContributor>>
        TopFeaturesPerFlow { get; set; } = new();

    [JsonPropertyName("explanations")]
    public List<ShapExplanation> Explanations { get; set; } = new();
}


// ============================================================
// SHAP EXPLANATION
// ============================================================

public class ShapExplanation
{
    [JsonPropertyName("flow_index")]
    public int FlowIndex { get; set; }

    [JsonPropertyName("flow_id")]
    public string FlowId { get; set; } = string.Empty;

    [JsonPropertyName("predicted_class")]
    public string PredictedClass { get; set; } = string.Empty;

    [JsonPropertyName("confidence")]
    public double Confidence { get; set; }

    [JsonPropertyName("base_value")]
    public double? BaseValue { get; set; }

    [JsonPropertyName("contributors")]
    public List<ShapContributor> Contributors { get; set; } = new();
}


// ============================================================
// SHAP CONTRIBUTOR
// ============================================================

public class ShapContributor
{
    [JsonPropertyName("rank")]
    public int Rank { get; set; }

    [JsonPropertyName("feature")]
    public string Feature { get; set; } = string.Empty;

    [JsonPropertyName("raw_value")]
    public double RawValue { get; set; }

    [JsonPropertyName("shap_value")]
    public double ShapValue { get; set; }

    [JsonPropertyName("direction")]
    public string Direction { get; set; } = string.Empty;
}