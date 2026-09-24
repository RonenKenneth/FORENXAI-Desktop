using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

using FORENXAI.Desktop.Models;

namespace FORENXAI.Desktop.Services;


// ============================================================
// BACKEND API SERVICE
// ============================================================

public class BackendApiService
{
    private readonly HttpClient _httpClient;


    // ========================================================
    // CONSTRUCTOR
    // ========================================================

    public BackendApiService()
    {
        _httpClient = new HttpClient
        {
            BaseAddress = new Uri(
                "http://127.0.0.1:8000"
            ),

            // A capture with several attack classes needs one language-model
            // generation per class. On a CPU-only llama-cpp build that is
            // ~136 s each, so a five-class capture runs past five minutes
            // and the client abandoned a request the backend was still
            // serving. Sized for the worst case, not the common one; the
            // real fix is a CUDA build of llama-cpp-python, which takes
            // generation to single-digit seconds.
            Timeout = TimeSpan.FromMinutes(45)
        };
    }


    // ========================================================
    // HEALTH CHECK
    // ========================================================

    public async Task<string> GetHealthAsync()
    {
        return await _httpClient
            .GetStringAsync(
                "/health"
            );
    }


    // ========================================================
    // START FORENSIC ANALYSIS
    // ========================================================

    public async Task<AnalysisResponse?> StartAnalysisAsync(
        string caseId,
        string fileName)
    {
        if (
            string.IsNullOrWhiteSpace(
                caseId
            )
        )
        {
            throw new ArgumentException(
                "Case ID cannot be empty."
            );
        }


        if (
            string.IsNullOrWhiteSpace(
                fileName
            )
        )
        {
            throw new ArgumentException(
                "Evidence filename cannot be empty."
            );
        }


        AnalysisRequest request =
            new AnalysisRequest
            {
                CaseId = caseId,
                FileName = fileName
            };


        HttpResponseMessage response =
            await _httpClient
                .PostAsJsonAsync(
                    "/analysis/start",
                    request
                );


        string responseBody =
            await response.Content
                .ReadAsStringAsync();


        if (
            !response.IsSuccessStatusCode
        )
        {
            throw new Exception(
                $"Python backend returned " +
                $"{(int)response.StatusCode} " +
                $"{response.StatusCode}\n\n" +
                responseBody
            );
        }


        AnalysisResponse? result =
            await response.Content
                .ReadFromJsonAsync<
                    AnalysisResponse
                >();


        if (result == null)
        {
            throw new Exception(
                "Python backend returned an empty " +
                "or invalid analysis response."
            );
        }


        return result;
    }


    // ========================================================
    // GET EXISTING ANALYSIS
    // ========================================================

    public async Task<AnalysisDocument?> GetAnalysisAsync(
        string caseId)
    {
        if (
            string.IsNullOrWhiteSpace(
                caseId
            )
        )
        {
            throw new ArgumentException(
                "Case ID cannot be empty."
            );
        }


        HttpResponseMessage response =
            await _httpClient
                .GetAsync(
                    $"/analysis/{caseId}"
                );


        string responseBody =
            await response.Content
                .ReadAsStringAsync();


        if (
            !response.IsSuccessStatusCode
        )
        {
            throw new Exception(
                $"Python backend returned " +
                $"{(int)response.StatusCode} " +
                $"{response.StatusCode}\n\n" +
                responseBody
            );
        }


        AnalysisDocument? result =
            await response.Content
                .ReadFromJsonAsync<
                    AnalysisDocument
                >();


        if (result == null)
        {
            throw new Exception(
                "Python backend returned an empty " +
                "or invalid analysis document."
            );
        }


        return result;
    }


    // ========================================================
    // PHASE 16
    // SAVE INVESTIGATOR REVIEW
    // ========================================================

    public async Task<InvestigatorReviewResponse?>
        SaveInvestigatorReviewAsync(
            string caseId,
            int flowIndex,
            string decision,
            string notes)
    {
        if (
            string.IsNullOrWhiteSpace(
                caseId
            )
        )
        {
            throw new ArgumentException(
                "Case ID cannot be empty."
            );
        }


        if (flowIndex < 0)
        {
            throw new ArgumentException(
                "Flow index cannot be negative."
            );
        }


        if (
            string.IsNullOrWhiteSpace(
                decision
            )
        )
        {
            throw new ArgumentException(
                "Decision cannot be empty."
            );
        }


        InvestigatorReviewRequest request =
            new InvestigatorReviewRequest
            {
                FlowIndex = flowIndex,

                Decision = decision,

                Notes =
                    notes
                    ?? string.Empty
            };


        HttpResponseMessage response =
            await _httpClient
                .PostAsJsonAsync(
                    $"/analysis/{caseId}/review",
                    request
                );


        string responseBody =
            await response.Content
                .ReadAsStringAsync();


        if (
            !response.IsSuccessStatusCode
        )
        {
            throw new Exception(
                $"Python backend returned " +
                $"{(int)response.StatusCode} " +
                $"{response.StatusCode}\n\n" +
                responseBody
            );
        }


        InvestigatorReviewResponse? result =
            await response.Content
                .ReadFromJsonAsync<
                    InvestigatorReviewResponse
                >();


        if (result == null)
        {
            throw new Exception(
                "Python backend returned an empty " +
                "or invalid review response."
            );
        }


        return result;
    }


    // ========================================================
    // PHASE 16
    // GET INVESTIGATOR REVIEWS
    // ========================================================

    public async Task<InvestigatorReviewsResponse?>
        GetInvestigatorReviewsAsync(
            string caseId)
    {
        if (
            string.IsNullOrWhiteSpace(
                caseId
            )
        )
        {
            throw new ArgumentException(
                "Case ID cannot be empty."
            );
        }


        HttpResponseMessage response =
            await _httpClient
                .GetAsync(
                    $"/analysis/{caseId}/reviews"
                );


        string responseBody =
            await response.Content
                .ReadAsStringAsync();


        if (
            !response.IsSuccessStatusCode
        )
        {
            throw new Exception(
                $"Python backend returned " +
                $"{(int)response.StatusCode} " +
                $"{response.StatusCode}\n\n" +
                responseBody
            );
        }


        InvestigatorReviewsResponse? result =
            await response.Content
                .ReadFromJsonAsync<
                    InvestigatorReviewsResponse
                >();


        if (result == null)
        {
            throw new Exception(
                "Python backend returned an empty " +
                "or invalid investigator review response."
            );
        }


        return result;
    }


    // ========================================================
    // PHASE 17
    // GET FORENSIC REPORT
    // ========================================================

    public async Task<CaseReportResponse?>
        GetCaseReportAsync(
            string caseId)
    {
        if (
            string.IsNullOrWhiteSpace(
                caseId
            )
        )
        {
            throw new ArgumentException(
                "Case ID cannot be empty."
            );
        }


        HttpResponseMessage response =
            await _httpClient
                .GetAsync(
                    $"/analysis/{caseId}/report"
                );


        string responseBody =
            await response.Content
                .ReadAsStringAsync();


        if (
            !response.IsSuccessStatusCode
        )
        {
            throw new Exception(
                $"Python backend returned " +
                $"{(int)response.StatusCode} " +
                $"{response.StatusCode}\n\n" +
                responseBody
            );
        }


        CaseReportResponse? result =
            await response.Content
                .ReadFromJsonAsync<
                    CaseReportResponse
                >();


        if (result == null)
        {
            throw new Exception(
                "Python backend returned an empty " +
                "or invalid forensic report response."
            );
        }


        return result;
    }

    // ========================================================
    // PHASE 18A
    // GET QWEN XAI NARRATION
    // ========================================================

    public async Task<NarrationResponse?>
        GetNarrationAsync(
            string caseId,
            int flowIndex)
    {
        if (
            string.IsNullOrWhiteSpace(
                caseId
            )
        )
        {
            throw new ArgumentException(
                "Case ID cannot be empty."
            );
        }


        if (flowIndex < 0)
        {
            throw new ArgumentException(
                "Flow index cannot be negative."
            );
        }


        HttpResponseMessage response =
            await _httpClient
                .GetAsync(
                    $"/analysis/{caseId}/narration/{flowIndex}"
                );


        string responseBody =
            await response.Content
                .ReadAsStringAsync();


        if (
            !response.IsSuccessStatusCode
        )
        {
            throw new Exception(
                $"Python backend returned " +
                $"{(int)response.StatusCode} " +
                $"{response.StatusCode}\n\n" +
                responseBody
            );
        }


        NarrationResponse? result =
            await response.Content
                .ReadFromJsonAsync<
                    NarrationResponse
                >();


        if (result == null)
        {
            throw new Exception(
                "Python backend returned an empty " +
                "or invalid narration response."
            );
        }


        return result;
    }

}


// ============================================================
// PHASE 18A
// QWEN NARRATION RESPONSE
// ============================================================

public class NarrationResponse
{
    [JsonPropertyName("case_id")]
    public string CaseId { get; set; }
        = string.Empty;


    [JsonPropertyName("flow_index")]
    public int FlowIndex { get; set; }


    [JsonPropertyName("predicted_class")]
    public string PredictedClass { get; set; }
        = string.Empty;


    [JsonPropertyName("narration")]
    public NarrationResult Narration { get; set; }
        = new();
}


// ============================================================
// PHASE 18A
// QWEN NARRATION RESULT
// ============================================================

public class NarrationResult
{
    [JsonPropertyName("available")]
    public bool Available { get; set; }


    [JsonPropertyName("provider")]
    public string Provider { get; set; }
        = string.Empty;


    [JsonPropertyName("model")]
    public string Model { get; set; }
        = string.Empty;


    [JsonPropertyName("predicted_class")]
    public string PredictedClass { get; set; }
        = string.Empty;


    [JsonPropertyName("text")]
    public string Text { get; set; }
        = string.Empty;


    [JsonPropertyName("fallback_used")]
    public bool FallbackUsed { get; set; }


    [JsonPropertyName("features_used")]
    public List<NarrationFeature>
        FeaturesUsed { get; set; }
            = new();


    [JsonPropertyName("error")]
    public string? Error { get; set; }
}


// ============================================================
// PHASE 18A
// NARRATION FEATURE
// ============================================================

public class NarrationFeature
{
    [JsonPropertyName("feature")]
    public string Feature { get; set; }
        = string.Empty;


    [JsonPropertyName("feature_value")]
    public object? FeatureValue { get; set; }


    [JsonPropertyName("shap_value")]
    public double ShapValue { get; set; }


    [JsonPropertyName("direction")]
    public string Direction { get; set; }
        = string.Empty;
}


// ============================================================
// ANALYSIS REQUEST
// ============================================================

public class AnalysisRequest
{
    [JsonPropertyName("case_id")]
    public string CaseId { get; set; }
        = string.Empty;


    [JsonPropertyName("file_name")]
    public string FileName { get; set; }
        = string.Empty;
}


// ============================================================
// ANALYSIS RESPONSE
// ============================================================

public class AnalysisResponse
{
    [JsonPropertyName("status")]
    public string Status { get; set; }
        = string.Empty;


    [JsonPropertyName("case_id")]
    public string CaseId { get; set; }
        = string.Empty;


    [JsonPropertyName("file_name")]
    public string FileName { get; set; }
        = string.Empty;


    [JsonPropertyName("file_size")]
    public long FileSize { get; set; }


    [JsonPropertyName("sha256")]
    public string Sha256 { get; set; }
        = string.Empty;


    [JsonPropertyName("total_packets")]
    public int TotalPackets { get; set; }


    [JsonPropertyName("total_flows")]
    public int TotalFlows { get; set; }


    [JsonPropertyName("ml_total_flows")]
    public int MlTotalFlows { get; set; }


    [JsonPropertyName("benign_flows")]
    public int BenignFlows { get; set; }


    [JsonPropertyName("threat_flows")]
    public int ThreatFlows { get; set; }


    [JsonPropertyName("threat_percentage")]
    public double ThreatPercentage { get; set; }


    [JsonPropertyName("class_counts")]
    public Dictionary<string, int>
        ClassCounts { get; set; }
            = new();


    [JsonPropertyName("shap_explanations")]
    public int ShapExplanations { get; set; }


    [JsonPropertyName("recommendations")]
    public int Recommendations { get; set; }


    [JsonPropertyName("total_bytes")]
    public long TotalBytes { get; set; }


    [JsonPropertyName("protocols")]
    public Dictionary<string, int>
        Protocols { get; set; }
            = new();


    [JsonPropertyName("message")]
    public string Message { get; set; }
        = string.Empty;
}


// ============================================================
// INVESTIGATOR REVIEW REQUEST
// ============================================================

public class InvestigatorReviewRequest
{
    [JsonPropertyName("flow_index")]
    public int FlowIndex { get; set; }


    [JsonPropertyName("decision")]
    public string Decision { get; set; }
        = string.Empty;


    [JsonPropertyName("notes")]
    public string Notes { get; set; }
        = string.Empty;
}


// ============================================================
// INVESTIGATOR REVIEW RESPONSE
// ============================================================

public class InvestigatorReviewResponse
{
    [JsonPropertyName("status")]
    public string Status { get; set; }
        = string.Empty;


    [JsonPropertyName("review")]
    public InvestigatorReviewData? Review { get; set; }
}


// ============================================================
// INVESTIGATOR REVIEW DATA
// ============================================================

public class InvestigatorReviewData
{
    [JsonPropertyName("case_id")]
    public string CaseId { get; set; }
        = string.Empty;


    [JsonPropertyName("flow_index")]
    public int FlowIndex { get; set; }


    [JsonPropertyName("predicted_class")]
    public string PredictedClass { get; set; }
        = string.Empty;


    [JsonPropertyName("decision")]
    public string Decision { get; set; }
        = string.Empty;


    [JsonPropertyName("notes")]
    public string Notes { get; set; }
        = string.Empty;


    [JsonPropertyName("review_timestamp")]
    public string ReviewTimestamp { get; set; }
        = string.Empty;
}


// ============================================================
// INVESTIGATOR REVIEWS RESPONSE
// ============================================================

public class InvestigatorReviewsResponse
{
    [JsonPropertyName("case_id")]
    public string CaseId { get; set; }
        = string.Empty;


    [JsonPropertyName("total_reviews")]
    public int TotalReviews { get; set; }


    [JsonPropertyName("reviews")]
    public List<InvestigatorReviewData>
        Reviews { get; set; }
            = new();
}


// ============================================================
// PHASE 17
// FORENSIC REPORT ROOT
// ============================================================

public class CaseReportResponse
{
    [JsonPropertyName("report_type")]
    public string ReportType { get; set; }
        = string.Empty;


    [JsonPropertyName("case")]
    public ReportCaseInfo Case { get; set; }
        = new();


    [JsonPropertyName("traffic_summary")]
    public ReportTrafficSummary TrafficSummary { get; set; }
        = new();


    [JsonPropertyName("flow_summary")]
    public ReportFlowSummary FlowSummary { get; set; }
        = new();


    [JsonPropertyName("ml_summary")]
    public ReportMlSummary MlSummary { get; set; }
        = new();


    [JsonPropertyName("review_summary")]
    public ReportReviewSummary ReviewSummary { get; set; }
        = new();


    [JsonPropertyName("threat_findings")]
    public List<ReportThreatFinding>
        ThreatFindings { get; set; }
            = new();


    [JsonPropertyName("investigator_reviews")]
    public List<InvestigatorReviewData>
        InvestigatorReviews { get; set; }
            = new();
}


// ============================================================
// PHASE 17
// REPORT CASE INFORMATION
// ============================================================

public class ReportCaseInfo
{
    [JsonPropertyName("case_id")]
    public string CaseId { get; set; }
        = string.Empty;


    [JsonPropertyName("evidence_file")]
    public string EvidenceFile { get; set; }
        = string.Empty;


    [JsonPropertyName("sha256")]
    public string Sha256 { get; set; }
        = string.Empty;


    [JsonPropertyName("file_size")]
    public long FileSize { get; set; }
}


// ============================================================
// PHASE 17
// REPORT TRAFFIC SUMMARY
// ============================================================

public class ReportTrafficSummary
{
    [JsonPropertyName("total_packets")]
    public int TotalPackets { get; set; }


    [JsonPropertyName("total_bytes")]
    public long TotalBytes { get; set; }


    [JsonPropertyName("protocols")]
    public Dictionary<string, int>
        Protocols { get; set; }
            = new();
}


// ============================================================
// PHASE 17
// REPORT FLOW SUMMARY
// ============================================================

public class ReportFlowSummary
{
    [JsonPropertyName("total_flows")]
    public int TotalFlows { get; set; }
}


// ============================================================
// PHASE 17
// REPORT ML SUMMARY
// ============================================================

public class ReportMlSummary
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
    public Dictionary<string, int>
        ClassCounts { get; set; }
            = new();
}


// ============================================================
// PHASE 17
// REPORT REVIEW SUMMARY
// ============================================================

public class ReportReviewSummary
{
    [JsonPropertyName("total_reviews")]
    public int TotalReviews { get; set; }


    [JsonPropertyName("confirmed")]
    public int Confirmed { get; set; }


    [JsonPropertyName("rejected")]
    public int Rejected { get; set; }


    [JsonPropertyName("inconclusive")]
    public int Inconclusive { get; set; }
}


// ============================================================
// PHASE 17
// REPORT THREAT FINDING
// ============================================================

public class ReportThreatFinding
{
    [JsonPropertyName("flow_index")]
    public int FlowIndex { get; set; }


    [JsonPropertyName("predicted_class")]
    public string PredictedClass { get; set; }
        = string.Empty;


    [JsonPropertyName("confidence")]
    public double Confidence { get; set; }


    /*
     * Metadata comes from CICFlowMeter and may contain
     * a mixture of strings and numeric values.
     *
     * Using object? here avoids depending on a specific
     * metadata model class.
     */
    [JsonPropertyName("metadata")]
    public Dictionary<string, object?>
        Metadata { get; set; }
            = new();


    [JsonPropertyName("recommendation")]
    public RecommendationData?
        Recommendation { get; set; }


    [JsonPropertyName("shap_explanation")]
    public ShapExplanation?
        ShapExplanation { get; set; }


    [JsonPropertyName("investigator_review")]
    public InvestigatorReviewData?
        InvestigatorReview { get; set; }
}