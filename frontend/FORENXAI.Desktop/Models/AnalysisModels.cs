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

    // ----------------------------------------------------------
    // Provenance. Every action is traced back to one retrieved
    // passage before the backend returns it; these carry that
    // evidence so the panel can show where an action came from
    // rather than asking the analyst to take it on trust.
    // ----------------------------------------------------------

    [JsonPropertyName("generator")]
    public string Generator { get; set; } = string.Empty;

    [JsonPropertyName("verified")]
    public bool Verified { get; set; }

    [JsonPropertyName("action_evidence")]
    public List<ActionEvidence> ActionEvidence { get; set; } = new();

    [JsonPropertyName("citations")]
    public List<string> Citations { get; set; } = new();

    [JsonPropertyName("standards_used")]
    public List<string> StandardsUsed { get; set; } = new();

    [JsonPropertyName("sources")]
    public List<SourceCitation> Sources { get; set; } = new();

    [JsonPropertyName("mitre")]
    public List<string> Mitre { get; set; } = new();

    [JsonPropertyName("controls")]
    public List<string> Controls { get; set; } = new();

    [JsonPropertyName("rejected_ungrounded")]
    public List<string> RejectedUngrounded { get; set; } = new();

    [JsonPropertyName("low_confidence_f1")]
    public double? LowConfidenceF1 { get; set; }

    /// <summary>
    /// Each action with its in-text citation appended, ACM style:
    /// "Apply rate limiting at the perimeter [1, SC-5]."
    /// </summary>
    [JsonPropertyName("actions_cited")]
    public List<string> ActionsCited { get; set; } = new();

    /// <summary>
    /// The numbered reference list, in ACM Reference Format. Only
    /// documents an action was actually traced to appear here.
    /// </summary>
    [JsonPropertyName("references")]
    public List<ReferenceEntry> References { get; set; } = new();

    /// <summary>
    /// False when every action traces to the internal corpus rather
    /// than to a published standard.
    /// </summary>
    [JsonPropertyName("standards_grounded")]
    public bool StandardsGrounded { get; set; }

    /// <summary>
    /// What the evaluation measured about this prediction: the class's
    /// test F1, and what this flow might be instead. Read from the
    /// model's own results rather than written into a document, so a
    /// retrain updates it.
    /// </summary>
    [JsonPropertyName("measured")]
    public MeasuredContext? Measured { get; set; }
}


public class MeasuredContext
{
    [JsonPropertyName("available")]
    public bool Available { get; set; }

    [JsonPropertyName("class_f1")]
    public double? ClassF1 { get; set; }

    [JsonPropertyName("low_confidence_class")]
    public bool LowConfidenceClass { get; set; }

    [JsonPropertyName("confidence")]
    public double? Confidence { get; set; }

    [JsonPropertyName("alternatives")]
    public List<AlternativeClass> Alternatives { get; set; } = new();

    /// <summary>Measured statements, ready to show verbatim.</summary>
    [JsonPropertyName("notes")]
    public List<string> Notes { get; set; } = new();
}


public class AlternativeClass
{
    [JsonPropertyName("class")]
    public string ClassName { get; set; } = string.Empty;

    /// <summary>The model's probability for this flow, when available.</summary>
    [JsonPropertyName("probability")]
    public double? Probability { get; set; }

    [JsonPropertyName("basis")]
    public string Basis { get; set; } = string.Empty;

    /// <summary>Share of the predicted class misread as this one.</summary>
    [JsonPropertyName("confusion")]
    public double? Confusion { get; set; }
}


public class ReferenceEntry
{
    [JsonPropertyName("number")]
    public int Number { get; set; }

    [JsonPropertyName("doc_id")]
    public string DocId { get; set; } = string.Empty;

    /// <summary>ACM Reference Format.</summary>
    [JsonPropertyName("acm")]
    public string Acm { get; set; } = string.Empty;
}


public class ActionEvidence
{
    /// <summary>The document or control the action was traced to.</summary>
    [JsonPropertyName("source")]
    public string Source { get; set; } = string.Empty;

    /// <summary>"span", "terms" or "quoted".</summary>
    [JsonPropertyName("match")]
    public string Match { get; set; } = string.Empty;

    [JsonPropertyName("span")]
    public string Span { get; set; } = string.Empty;

    [JsonPropertyName("coverage")]
    public double Coverage { get; set; }
}


public class SourceCitation
{
    [JsonPropertyName("doc_id")]
    public string DocId { get; set; } = string.Empty;

    [JsonPropertyName("citation")]
    public string Citation { get; set; } = string.Empty;
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