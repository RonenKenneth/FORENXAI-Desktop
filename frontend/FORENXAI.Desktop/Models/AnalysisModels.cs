using System.Collections.Generic;
using System.Text.Json;
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

    /// <summary>Rule-based detection summary (Tier 1 flow rules, Tier 2
    /// packet rules, hybrid verdicts). Absent in older cases.</summary>
    [JsonPropertyName("rule_analysis")]
    public RuleAnalysis? RuleAnalysis { get; set; }

    /// <summary>Packets in the capture. The packets themselves are served
    /// a page at a time (GET /analysis/{case_id}/packets).</summary>
    [JsonPropertyName("packet_count")]
    public int PacketCount { get; set; }

    /// <summary>How much of the capture the flow records cover.</summary>
    [JsonPropertyName("capture_coverage")]
    public CaptureCoverage? CaptureCoverage { get; set; }
}


// ============================================================
// RULE-BASED DETECTION SUMMARY
// ============================================================

public class RuleAnalysis
{
    [JsonPropertyName("rules_version")]
    public string? RulesVersion { get; set; }

    [JsonPropertyName("sensitivity")]
    public string? Sensitivity { get; set; }

    [JsonPropertyName("tier1_evaluated")]
    public bool Tier1Evaluated { get; set; }

    [JsonPropertyName("tier1_chart")]
    public RuleChart? Tier1Chart { get; set; }

    [JsonPropertyName("tier2_chart")]
    public RuleChart? Tier2Chart { get; set; }

    [JsonPropertyName("tier2")]
    public Tier2Summary? Tier2 { get; set; }

    [JsonPropertyName("verdict_sources")]
    public Dictionary<string, int> VerdictSources { get; set; } = new();

    /// <summary>Every Tier 1 rule as the case applied it (absent in
    /// cases analysed before it was saved).</summary>
    [JsonPropertyName("tier1_rules")]
    public List<Tier1RuleInfo> Tier1Rules { get; set; } = new();
}

public class Tier1RuleInfo
{
    [JsonPropertyName("rule_id")] public string RuleId { get; set; } = string.Empty;
    [JsonPropertyName("class")] public string ClassName { get; set; } = string.Empty;
    [JsonPropertyName("role")] public string Role { get; set; } = string.Empty;
    [JsonPropertyName("description")] public string Description { get; set; } = string.Empty;
    [JsonPropertyName("settings")] public Dictionary<string, JsonElement> Settings { get; set; } = new();
    [JsonPropertyName("basis")] public string Basis { get; set; } = string.Empty;
    [JsonPropertyName("disabled_reason")] public string DisabledReason { get; set; } = string.Empty;
    [JsonPropertyName("flows_flagged")] public int FlowsFlagged { get; set; }
}

public class RuleChart
{
    [JsonPropertyName("flows_flagged")]
    public int FlowsFlagged { get; set; }

    [JsonPropertyName("by_class")]
    public Dictionary<string, int> ByClass { get; set; } = new();

    [JsonPropertyName("by_rule")]
    public Dictionary<string, int> ByRule { get; set; } = new();

    [JsonPropertyName("by_source")]
    public Dictionary<string, int> BySource { get; set; } = new();
}

public class Tier2Summary
{
    [JsonPropertyName("error")]
    public string? Error { get; set; }

    [JsonPropertyName("packets_inspected")]
    public long? PacketsInspected { get; set; }

    [JsonPropertyName("encrypted_flows")]
    public int? EncryptedFlows { get; set; }

    [JsonPropertyName("inspectable_share")]
    public double? InspectableShare { get; set; }

    [JsonPropertyName("suricata")]
    public SuricataStatus? Suricata { get; set; }

    [JsonPropertyName("capture_level_hits")]
    public List<RuleHit>? CaptureLevelHits { get; set; }
}

public class SuricataStatus
{
    [JsonPropertyName("ran")]
    public bool Ran { get; set; }

    [JsonPropertyName("reason")]
    public string? Reason { get; set; }

    [JsonPropertyName("alerts")]
    public int Alerts { get; set; }

    [JsonPropertyName("mapped")]
    public int Mapped { get; set; }

    [JsonPropertyName("ignored")]
    public int Ignored { get; set; }

    [JsonPropertyName("home_net")]
    public string? HomeNet { get; set; }

    [JsonPropertyName("unmapped_signatures")]
    public List<string> UnmappedSignatures { get; set; } = new();
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

    /// <summary>
    /// Rule-based detector hits for this flow. Null when no rule engine
    /// ran; an empty list when it ran and nothing fired.
    /// </summary>
    [JsonPropertyName("rule_findings")]
    public List<RuleHit>? RuleFindings { get; set; }

    /// <summary>Totals of the connection this flow belongs to, from the
    /// packets (both directions). Absent in older cases.</summary>
    [JsonPropertyName("connection")]
    public FlowConnection? Connection { get; set; }

    /// <summary>True for CICFlowMeter's non-IP (ARP) pseudo-flow: neither
    /// address occurs in the capture.</summary>
    [JsonPropertyName("pseudo_flow")]
    public bool PseudoFlow { get; set; }

    /// <summary>
    /// Final hybrid verdict from the model and both rule tiers, and which
    /// side decided it: agree, rule, ml, conflict or abstain. Absent in
    /// cases analysed before the hybrid decision existed.
    /// </summary>
    [JsonPropertyName("verdict")]
    public string? Verdict { get; set; }

    [JsonPropertyName("verdict_source")]
    public string? VerdictSource { get; set; }

    /// <summary>True when the model abstained: below its class's
    /// confidence threshold or outside the training distribution.</summary>
    [JsonPropertyName("abstained")]
    public bool Abstained { get; set; }

    [JsonPropertyName("abstain_reason")]
    public string? AbstainReason { get; set; }

    /// <summary>True when the flow's payload is encrypted, so the Tier 2
    /// content rules were not applied to it; null when not determined.</summary>
    [JsonPropertyName("payload_encrypted")]
    public bool? PayloadEncrypted { get; set; }
}


// ============================================================
// FLOW METADATA
// ============================================================

public class CaptureCoverage
{
    [JsonPropertyName("packet_conversations")] public int PacketConversations { get; set; }
    [JsonPropertyName("in_flow_records")] public int InFlowRecords { get; set; }
    [JsonPropertyName("not_in_flow_records")] public int NotInFlowRecords { get; set; }
    [JsonPropertyName("single_packet_not_exported")] public int SinglePacketNotExported { get; set; }
    [JsonPropertyName("packets_without_ports")] public int PacketsWithoutPorts { get; set; }
    [JsonPropertyName("unanswered_syn_probes")] public List<UnansweredProbes> UnansweredSynProbes { get; set; } = new();
    [JsonPropertyName("reason")] public string Reason { get; set; } = string.Empty;
}

public class UnansweredProbes
{
    [JsonPropertyName("source")] public string Source { get; set; } = string.Empty;
    [JsonPropertyName("destination")] public string Destination { get; set; } = string.Empty;
    [JsonPropertyName("ports")] public int Ports { get; set; }
}

public class FlowConnection
{
    [JsonPropertyName("bytes")]
    public long Bytes { get; set; }

    [JsonPropertyName("packets")]
    public int Packets { get; set; }

    [JsonPropertyName("flags")]
    public List<string> Flags { get; set; } = new();

    [JsonPropertyName("first_time")]
    public double FirstTime { get; set; }
}

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

    /// <summary>
    /// What the recommendation was built from: the XGBoost prediction,
    /// the SHAP drivers and the rule-based result, with whether the rules
    /// agree with the model. Absent in cases analysed before this field.
    /// </summary>
    [JsonPropertyName("inputs")]
    public RecommendationInputs? Inputs { get; set; }

    /// <summary>Generated / verified / dropped counts and drop reasons.</summary>
    [JsonPropertyName("verification_summary")]
    public VerificationSummary? VerificationSummary { get; set; }

    [JsonPropertyName("dropped_actions")]
    public List<DroppedAction> DroppedActions { get; set; } = new();
}


public class RecommendationInputs
{
    [JsonPropertyName("model")]
    public ModelInput? Model { get; set; }

    [JsonPropertyName("shap")]
    public List<ShapInput> Shap { get; set; } = new();

    [JsonPropertyName("rules")]
    public RuleInput? Rules { get; set; }
}


public class ModelInput
{
    [JsonPropertyName("predicted_class")]
    public string PredictedClass { get; set; } = string.Empty;

    [JsonPropertyName("confidence_band")]
    public double? ConfidenceBand { get; set; }

    [JsonPropertyName("class_f1")]
    public double? ClassF1 { get; set; }
}


public class ShapInput
{
    [JsonPropertyName("feature")]
    public string Feature { get; set; } = string.Empty;

    // A number for numeric features, but kept loose: a string must not
    // break deserialisation of the whole case.
    [JsonPropertyName("raw_value")]
    public JsonElement? RawValue { get; set; }

    [JsonPropertyName("shap_value")]
    public double ShapValue { get; set; }

    [JsonPropertyName("toward_prediction")]
    public bool TowardPrediction { get; set; }
}


public class RuleInput
{
    /// <summary>"evaluated" or "not_evaluated".</summary>
    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;

    /// <summary>agree, conflict, no_rule_fired or not_evaluated.</summary>
    [JsonPropertyName("agreement")]
    public string Agreement { get; set; } = string.Empty;

    [JsonPropertyName("agreement_note")]
    public string AgreementNote { get; set; } = string.Empty;

    [JsonPropertyName("hits")]
    public List<RuleHit> Hits { get; set; } = new();
}


public class RuleHit
{
    [JsonPropertyName("rule_id")]
    public string RuleId { get; set; } = string.Empty;

    [JsonPropertyName("class")]
    public string ClassName { get; set; } = string.Empty;

    [JsonPropertyName("tier")]
    public int? Tier { get; set; }

    [JsonPropertyName("evidence")]
    public string Evidence { get; set; } = string.Empty;

    [JsonPropertyName("measured")]
    public JsonElement? Measured { get; set; }

    [JsonPropertyName("threshold")]
    public JsonElement? Threshold { get; set; }

    [JsonPropertyName("severity")]
    public string Severity { get; set; } = string.Empty;

    /// <summary>Where the rule's threshold comes from (rules.json).</summary>
    [JsonPropertyName("basis")]
    public string Basis { get; set; } = string.Empty;
}


public class VerificationSummary
{
    [JsonPropertyName("generated")]
    public int Generated { get; set; }

    [JsonPropertyName("verified")]
    public int Verified { get; set; }

    [JsonPropertyName("dropped")]
    public int Dropped { get; set; }

    /// <summary>Actions kept after their citation was corrected to the one source that supports them.</summary>
    [JsonPropertyName("citation_corrected")]
    public int CitationCorrected { get; set; }

    [JsonPropertyName("reasons")]
    public Dictionary<string, int> Reasons { get; set; } = new();
}


public class DroppedAction
{
    [JsonPropertyName("action_id")]
    public string ActionId { get; set; } = string.Empty;

    [JsonPropertyName("text")]
    public string Text { get; set; } = string.Empty;

    // Usually an id string; a list when the model cited several, which is
    // exactly why the action was dropped.
    [JsonPropertyName("source_id")]
    public JsonElement? SourceId { get; set; }

    [JsonPropertyName("reason")]
    public string Reason { get; set; } = string.Empty;
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

    /// <summary>Features outside the top list and their summed SHAP;
    /// margin = base + all contributions (absent in older cases).</summary>
    [JsonPropertyName("rest_count")]
    public int? RestCount { get; set; }

    [JsonPropertyName("rest_shap_sum")]
    public double? RestShapSum { get; set; }

    [JsonPropertyName("margin")]
    public double? Margin { get; set; }
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

// ============================================================
// PHASE 22 - CASE MANAGEMENT
// ============================================================

public class CaseListResponse
{
    [JsonPropertyName("total_cases")]
    public int TotalCases { get; set; }

    [JsonPropertyName("cases")]
    public List<CaseSummary> Cases { get; set; } = new();
}


public class CaseSummary
{
    [JsonPropertyName("case_id")]
    public string CaseId { get; set; } = string.Empty;

    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;

    [JsonPropertyName("evidence_file")]
    public string? EvidenceFile { get; set; }

    [JsonPropertyName("total_packets")]
    public int? TotalPackets { get; set; }

    [JsonPropertyName("total_flows")]
    public int? TotalFlows { get; set; }

    [JsonPropertyName("ml_total_flows")]
    public int? MlTotalFlows { get; set; }

    [JsonPropertyName("benign_flows")]
    public int? BenignFlows { get; set; }

    [JsonPropertyName("threat_flows")]
    public int? ThreatFlows { get; set; }

    [JsonPropertyName("threat_percentage")]
    public double? ThreatPercentage { get; set; }

    [JsonPropertyName("has_reviews")]
    public bool HasReviews { get; set; }

    [JsonPropertyName("analysis_exists")]
    public bool AnalysisExists { get; set; }

    /// <summary>Scheduled automatic deletion (ISO 8601), null when none.</summary>
    [JsonPropertyName("delete_after")]
    public string? DeleteAfter { get; set; }

    [JsonIgnore]
    public DateTimeOffset? DeleteAfterTime =>
        DateTimeOffset.TryParse(DeleteAfter, out DateTimeOffset when) ? when : null;

    [JsonIgnore]
    public string DeleteAfterDisplay =>
        DeleteAfterTime is DateTimeOffset when ? when.LocalDateTime.ToString("yyyy-MM-dd HH:mm") : "—";
}


public class CaseDetailsResponse
{
    [JsonPropertyName("case_id")]
    public string CaseId { get; set; } = string.Empty;

    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;

    [JsonPropertyName("evidence_file")]
    public string? EvidenceFile { get; set; }

    [JsonPropertyName("analysis_exists")]
    public bool AnalysisExists { get; set; }

    [JsonPropertyName("has_reviews")]
    public bool HasReviews { get; set; }

    [JsonPropertyName("total_reviews")]
    public int TotalReviews { get; set; }

    [JsonPropertyName("analysis")]
    public AnalysisDocument? Analysis { get; set; }
}

