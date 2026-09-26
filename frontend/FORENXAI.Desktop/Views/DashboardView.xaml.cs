using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

using FORENXAI.Desktop.Models;
using FORENXAI.Desktop.Services;

namespace FORENXAI.Desktop.Views;

public partial class DashboardView : UserControl
{
    // =========================================================
    // SERVICES / STATE
    // =========================================================

    private readonly BackendApiService backendApi;

    private AnalysisDocument? currentAnalysis;

    private readonly ObservableCollection<ThreatRow> threats;
    private readonly ObservableCollection<ShapRow> shapRows;

    private readonly ObservableCollection<BarRow> tier1Bars = new();
    private readonly ObservableCollection<BarRow> tier2Bars = new();
    private readonly ObservableCollection<BarRow> verdictLegend = new();


    // =========================================================
    // DEFAULT CONSTRUCTOR
    // =========================================================

    public DashboardView()
    {
        InitializeComponent();

        backendApi = new BackendApiService();

        threats = new ObservableCollection<ThreatRow>();
        shapRows = new ObservableCollection<ShapRow>();

        ThreatDataGrid.ItemsSource = threats;
        ShapDataGrid.ItemsSource = shapRows;

        Tier1Bars.ItemsSource = tier1Bars;
        Tier2Bars.ItemsSource = tier2Bars;
        VerdictLegend.ItemsSource = verdictLegend;

        OpenXaiButton.IsEnabled = false;

        ResetDashboard();
    }


    // =========================================================
    // CONSTRUCTOR WITH CASE ID
    // =========================================================

    public DashboardView(string caseId)
        : this()
    {
        CaseIdTextBox.Text = caseId;

        Loaded += async (_, _) =>
        {
            await LoadCaseAsync(caseId);
        };
    }


    // =========================================================
    // LOAD CASE BUTTON
    // =========================================================

    private async void LoadCase_Click(
        object sender,
        RoutedEventArgs e)
    {
        string caseId =
            CaseIdTextBox.Text.Trim();

        if (string.IsNullOrWhiteSpace(caseId))
        {
            MessageBox.Show(
                "Please enter a Case ID.",
                "FORENXAI",
                MessageBoxButton.OK,
                MessageBoxImage.Information
            );

            return;
        }

        await LoadCaseAsync(caseId);
    }


    // =========================================================
    // LOAD CASE
    // =========================================================

    private async Task LoadCaseAsync(
        string caseId)
    {
        try
        {
            StatusText.Text =
                "Loading case...";

            OpenXaiButton.IsEnabled = false;

            threats.Clear();
            shapRows.Clear();

            currentAnalysis =
                await backendApi.GetAnalysisAsync(
                    caseId
                );

            if (currentAnalysis == null)
            {
                throw new InvalidOperationException(
                    "The backend returned no analysis data."
                );
            }


            CaseIdTextBox.Text = caseId;


            LoadSummary();
            LoadRulePanel();
            LoadThreats();


            StatusText.Text =
                $"Loaded: {caseId}";
        }
        catch (Exception ex)
        {
            ResetDashboard();

            StatusText.Text =
                "Could not load case";

            MessageBox.Show(
                "Could not load the forensic case.\n\n" +
                ex.Message,
                "FORENXAI Dashboard Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error
            );
        }
    }


    // =========================================================
    // SUMMARY
    // =========================================================

    private void LoadSummary()
    {
        if (
            currentAnalysis?.MlAnalysis?.Summary
            == null
        )
        {
            TotalFlowsText.Text = "0";
            BenignFlowsText.Text = "0";
            ThreatFlowsText.Text = "0";
            ThreatPercentageText.Text = "0.00%";

            return;
        }


        MlSummary summary =
            currentAnalysis.MlAnalysis.Summary;


        TotalFlowsText.Text =
            summary.TotalFlows.ToString();


        BenignFlowsText.Text =
            summary.BenignFlows.ToString();


        ThreatFlowsText.Text =
            summary.ThreatFlows.ToString();


        ThreatPercentageText.Text =
            $"{summary.ThreatPercentage:F2}%";
    }



    // =========================================================
    // RULE-BASED DETECTION PANEL
    //
    // Bar charts of flows flagged per class for Tier 1 (flow
    // rules) and Tier 2 (packet rules + Suricata), and a stacked
    // bar of who decided each flow's final verdict.
    // =========================================================

    private static readonly Dictionary<string, string> ClassColours = new()
    {
        ["PortScan"] = "#F59E0B", ["DDoS"] = "#EF4444", ["DoS"] = "#F97316",
        ["Slowloris"] = "#FB923C", ["Bruteforce"] = "#EAB308", ["C2Beaconing"] = "#A855F7",
        ["Exfiltration"] = "#EC4899", ["DNS"] = "#06B6D4", ["TLSSSL"] = "#14B8A6",
        ["MITM"] = "#8B5CF6", ["WebBased"] = "#3B82F6", ["API"] = "#6366F1",
        ["Exploitation"] = "#DC2626", ["BufferOverflow"] = "#BE123C", ["Evasion"] = "#84CC16",
        ["Benign"] = "#22C55E",
    };

    private static readonly (string Key, string Label, string Colour, string Meaning)[] VerdictSources =
    {
        ("agree", "agree", "#22C55E", "Model and rules name the same class"),
        ("rule", "rule", "#F59E0B", "A trusted rule decided (or stood in for an abstaining model)"),
        ("ml", "model", "#3B82F6", "No rule fired; the model decided"),
        ("conflict", "conflict", "#EF4444", "Rules and model disagree; model class shown, analyst review"),
        ("abstain", "uncertain", "#64748B", "Model below its confidence threshold or out of distribution, and no rule fired"),
    };

    private static Brush ToBrush(string colour) =>
        (Brush)new BrushConverter().ConvertFromString(colour)!;

    private static RuleHit? TopRuleHit(MlFinding finding) =>
        finding.RuleFindings?.FirstOrDefault(
            hit => hit.RuleId != "ALLOWLIST");

    private void ClearRulePanel()
    {
        tier1Bars.Clear();
        tier2Bars.Clear();
        verdictLegend.Clear();
        VerdictBar.Children.Clear();
        VerdictBar.ColumnDefinitions.Clear();
        Tier1SummaryText.Text = "--";
        Tier2SummaryText.Text = "--";
        Tier2StatusText.Text = string.Empty;
        VerdictSummaryText.Text = "--";
        RulesVersionText.Text = string.Empty;
    }

    private static void FillBars(
        ObservableCollection<BarRow> rows,
        RuleChart? chart,
        int totalFlows)
    {
        rows.Clear();

        if (chart == null)
        {
            return;
        }

        int max = Math.Max(1, chart.ByClass.Values.DefaultIfEmpty(0).Max());

        foreach (var (name, count) in chart.ByClass.OrderByDescending(pair => pair.Value))
        {
            rows.Add(new BarRow
            {
                Label = name,
                Count = count,
                Max = max,
                Brush = ToBrush(ClassColours.GetValueOrDefault(name, "#94A3B8")),
                Tooltip = $"{name}: {count:N0} of {totalFlows:N0} flows "
                          + $"({(totalFlows > 0 ? (double)count / totalFlows : 0):P1})",
            });
        }
    }

    private void LoadRulePanel()
    {
        ClearRulePanel();

        RuleAnalysis? rules = currentAnalysis?.RuleAnalysis;
        int total = currentAnalysis?.MlAnalysis?.Findings?.Count ?? 0;

        if (rules == null)
        {
            Tier1SummaryText.Text =
                "Not in this case: it was analysed before the rule layer existed.";
            return;
        }

        RulesVersionText.Text =
            $"rules {rules.RulesVersion} · sensitivity {rules.Sensitivity}";

        // Tier 1
        if (!rules.Tier1Evaluated)
        {
            Tier1SummaryText.Text = "Not evaluated for this capture.";
        }
        else
        {
            int flagged = rules.Tier1Chart?.FlowsFlagged ?? 0;
            Tier1SummaryText.Text = flagged == 0
                ? $"No flow rule fired on {total:N0} flows."
                : $"{flagged:N0} of {total:N0} flows flagged";
            FillBars(tier1Bars, rules.Tier1Chart, total);
        }

        // Tier 2
        Tier2Summary? tier2 = rules.Tier2;
        if (tier2 == null || !string.IsNullOrEmpty(tier2.Error))
        {
            Tier2SummaryText.Text =
                "Not evaluated" + (tier2?.Error != null ? $": {tier2.Error}" : ".");
        }
        else
        {
            int flagged = rules.Tier2Chart?.FlowsFlagged ?? 0;
            int captureLevel = tier2.CaptureLevelHits?.Count ?? 0;
            Tier2SummaryText.Text = (flagged == 0
                    ? $"No packet rule fired on {total:N0} flows."
                    : $"{flagged:N0} of {total:N0} flows flagged")
                + (captureLevel > 0 ? $"; {captureLevel} capture-level hit(s)" : string.Empty);
            FillBars(tier2Bars, rules.Tier2Chart, total);

            string suricata = tier2.Suricata == null
                ? "Suricata: unknown"
                : tier2.Suricata.Ran
                    ? $"Suricata ran: {tier2.Suricata.Alerts:N0} alerts, "
                      + $"{tier2.Suricata.Mapped:N0} mapped to classes"
                      + (tier2.Suricata.Ignored > 0 ? $", {tier2.Suricata.Ignored:N0} ignored (checksum offload)" : string.Empty)
                    : $"Suricata not run: {tier2.Suricata.Reason}";
            string coverage = tier2.InspectableShare == null
                ? string.Empty
                : $"\nPayload inspectable: {tier2.InspectableShare:P1} of flows"
                  + $" ({tier2.EncryptedFlows ?? 0:N0} encrypted: content rules not applied)";
            // Hits that belong to the capture rather than one flow (for
            // example ARP spoofing with no matching flow), with evidence.
            string captureHits = (tier2.CaptureLevelHits?.Count ?? 0) == 0
                ? string.Empty
                : "\nCapture-level:\n" + string.Join("\n",
                    tier2.CaptureLevelHits!.Take(5).Select(
                        hit => $"• {hit.ClassName}: {hit.Evidence}"));
            string unmapped = (tier2.Suricata?.UnmappedSignatures.Count ?? 0) == 0
                ? string.Empty
                : "\nSuricata alerts with no class: "
                  + string.Join("; ", tier2.Suricata!.UnmappedSignatures.Take(3));
            Tier2StatusText.Text = suricata + coverage + captureHits + unmapped;
        }

        // Hybrid verdict source
        int decided = rules.VerdictSources.Values.Sum();
        VerdictSummaryText.Text = decided == 0
            ? "No verdicts in this case."
            : $"{decided:N0} flows";

        foreach (var (key, label, colour, meaning) in VerdictSources)
        {
            int count = rules.VerdictSources.GetValueOrDefault(key);
            if (count == 0)
            {
                continue;
            }

            VerdictBar.ColumnDefinitions.Add(
                new ColumnDefinition { Width = new GridLength(count, GridUnitType.Star) });
            var segment = new Border
            {
                Background = ToBrush(colour),
                ToolTip = $"{label}: {count:N0} flows ({(double)count / decided:P1}). {meaning}.",
            };
            Grid.SetColumn(segment, VerdictBar.ColumnDefinitions.Count - 1);
            VerdictBar.Children.Add(segment);

            verdictLegend.Add(new BarRow
            {
                Label = label,
                Count = count,
                Brush = ToBrush(colour),
                Tooltip = meaning,
            });
        }
    }

    // =========================================================
    // LOAD THREATS
    // =========================================================

    private void LoadThreats()
    {
        threats.Clear();
        shapRows.Clear();

        ClearSelectedThreat();


        if (
            currentAnalysis?.MlAnalysis?.Findings
            == null
        )
        {
            ThreatCountText.Text =
                "0 threat flows";

            return;
        }


        foreach (
            MlFinding finding
            in currentAnalysis.MlAnalysis.Findings
        )
        {
            RuleHit? topHit = TopRuleHit(finding);

            if (!finding.IsThreat && topHit == null)
            {
                continue;
            }


            threats.Add(
                new ThreatRow
                {
                    FlowIndex =
                        finding.FlowIndex,

                    Source =
                        BuildSourceText(
                            finding.Metadata
                        ),

                    Destination =
                        BuildDestinationText(
                            finding.Metadata
                        ),

                    PredictedClass =
                        finding.PredictedClass,

                    Confidence =
                        finding.Confidence,

                    RuleDisplay =
                        topHit == null
                            ? (finding.RuleFindings == null ? "not run" : "--")
                            : $"{topHit.ClassName} (T{topHit.Tier})",

                    VerdictDisplay =
                        string.IsNullOrEmpty(finding.VerdictSource)
                            ? "--"
                            : $"{finding.Verdict} · {finding.VerdictSource}"
                }
            );
        }


        int byModel = threats.Count(
            row => row.PredictedClass != "Benign");

        ThreatCountText.Text =
            $"{threats.Count} flagged flow" +
            (threats.Count == 1 ? "" : "s") +
            $" ({byModel} by the model, " +
            $"{threats.Count - byModel} by rules only)";


        // Automatically select the first threat
        // so the Dashboard is immediately useful.
        if (threats.Count > 0)
        {
            ThreatDataGrid.SelectedIndex = 0;
        }
    }


    // =========================================================
    // THREAT SELECTION CHANGED
    // =========================================================

    private void ThreatDataGrid_SelectionChanged(
        object sender,
        SelectionChangedEventArgs e)
    {
        if (
            ThreatDataGrid.SelectedItem
            is not ThreatRow selectedThreat
        )
        {
            OpenXaiButton.IsEnabled = false;

            ClearSelectedThreat();

            return;
        }


        OpenXaiButton.IsEnabled = true;


        SelectedThreatClassText.Text =
            selectedThreat.PredictedClass;


        SelectedFlowIndexText.Text =
            selectedThreat.FlowIndex.ToString();


        SelectedConfidenceText.Text =
            selectedThreat.ConfidenceDisplay;


        LoadShapExplanation(
            selectedThreat.FlowIndex
        );
    }


    // =========================================================
    // LOAD SHAP EXPLANATION
    // =========================================================

    private void LoadShapExplanation(
        int flowIndex)
    {
        shapRows.Clear();


        if (
            currentAnalysis?.ShapAnalysis?.Explanations
            == null
        )
        {
            SelectedExplanationText.Text =
                "SHAP unavailable";

            return;
        }


        ShapExplanation? explanation =
            currentAnalysis
            .ShapAnalysis
            .Explanations
            .FirstOrDefault(
                item =>
                    item.FlowIndex == flowIndex
            );


        if (explanation == null)
        {
            SelectedExplanationText.Text =
                "No explanation found";

            return;
        }


        if (
            explanation.Contributors == null
            ||
            explanation.Contributors.Count == 0
        )
        {
            SelectedExplanationText.Text =
                "No contributors";

            return;
        }


        foreach (
            ShapContributor contributor
            in explanation.Contributors
        )
        {
            shapRows.Add(
                new ShapRow
                {
                    Rank =
                        contributor.Rank,

                    Feature =
                        contributor.Feature,

                    RawValue =
                        contributor.RawValue,

                    ShapValue =
                        contributor.ShapValue,

                    Direction =
                        contributor.Direction
                }
            );
        }


        ShapContributor? strongest =
            explanation
            .Contributors
            .OrderByDescending(
                contributor =>
                    Math.Abs(
                        contributor.ShapValue
                    )
            )
            .FirstOrDefault();


        if (strongest == null)
        {
            SelectedExplanationText.Text =
                "Explanation available";

            return;
        }


        SelectedExplanationText.Text =
            strongest.Direction switch
            {
                "supports_prediction" =>
                    "Top feature supports prediction",

                "opposes_prediction" =>
                    "Top feature opposes prediction",

                "neutral" =>
                    "Top feature is neutral",

                _ =>
                    "SHAP explanation available"
            };
    }


    // =========================================================
    // PHASE 15.2
    // OPEN SELECTED THREAT IN XAI
    // =========================================================

    private void OpenXai_Click(
        object sender,
        RoutedEventArgs e)
    {
        // ---------------------------------------------
        // Make sure a threat is selected
        // ---------------------------------------------

        if (
            ThreatDataGrid.SelectedItem
            is not ThreatRow selectedThreat
        )
        {
            MessageBox.Show(
                "Please select a threat flow first.",
                "FORENXAI",
                MessageBoxButton.OK,
                MessageBoxImage.Information
            );

            return;
        }


        // ---------------------------------------------
        // Get current Case ID
        // ---------------------------------------------

        string caseId =
            CaseIdTextBox.Text.Trim();


        if (string.IsNullOrWhiteSpace(caseId))
        {
            MessageBox.Show(
                "The current Case ID is unavailable.",
                "FORENXAI",
                MessageBoxButton.OK,
                MessageBoxImage.Warning
            );

            return;
        }


        // ---------------------------------------------
        // Locate MainWindow
        // ---------------------------------------------

        Window? parentWindow =
            Window.GetWindow(this);


        if (
            parentWindow
            is not FORENXAI.Desktop.MainWindow mainWindow
        )
        {
            MessageBox.Show(
                "FORENXAI could not open the XAI view.",
                "Navigation Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error
            );

            return;
        }


        // ---------------------------------------------
        // Dashboard -> XAI
        //
        // Pass:
        //   1. Case ID
        //   2. selected Flow Index
        // ---------------------------------------------

        mainWindow.ShowXai(
            caseId,
            selectedThreat.FlowIndex
        );
    }


    // =========================================================
    // CLEAR SELECTED THREAT
    // =========================================================

    private void ClearSelectedThreat()
    {
        SelectedThreatClassText.Text =
            "Select a threat flow";


        SelectedFlowIndexText.Text =
            "--";


        SelectedConfidenceText.Text =
            "--";


        SelectedExplanationText.Text =
            "Select a row below";


        shapRows.Clear();
    }


    // =========================================================
    // RESET DASHBOARD
    // =========================================================

    private void ResetDashboard()
    {
        currentAnalysis = null;

        ClearRulePanel();

        threats.Clear();
        shapRows.Clear();


        TotalFlowsText.Text =
            "0";


        BenignFlowsText.Text =
            "0";


        ThreatFlowsText.Text =
            "0";


        ThreatPercentageText.Text =
            "0.00%";


        ThreatCountText.Text =
            "0 threat flows";


        SelectedThreatClassText.Text =
            "Select a threat flow";


        SelectedFlowIndexText.Text =
            "--";


        SelectedConfidenceText.Text =
            "--";


        SelectedExplanationText.Text =
            "Select a row below";


        OpenXaiButton.IsEnabled =
            false;
    }


    // =========================================================
    // SOURCE DISPLAY
    // =========================================================

    private static string BuildSourceText(
        object? metadata)
    {
        if (metadata == null)
        {
            return "Unknown";
        }


        string ip =
            GetMetadataValue(
                metadata,
                "SrcIp",
                "SrcIP",
                "SourceIp",
                "SourceIP"
            );


        string port =
            GetMetadataValue(
                metadata,
                "SrcPort",
                "SourcePort"
            );


        if (
            string.IsNullOrWhiteSpace(ip)
            &&
            string.IsNullOrWhiteSpace(port)
        )
        {
            return "Unknown";
        }


        if (string.IsNullOrWhiteSpace(port))
        {
            return ip;
        }


        if (string.IsNullOrWhiteSpace(ip))
        {
            return port;
        }


        return $"{ip}:{port}";
    }


    // =========================================================
    // DESTINATION DISPLAY
    // =========================================================

    private static string BuildDestinationText(
        object? metadata)
    {
        if (metadata == null)
        {
            return "Unknown";
        }


        string ip =
            GetMetadataValue(
                metadata,
                "DstIp",
                "DstIP",
                "DestinationIp",
                "DestinationIP"
            );


        string port =
            GetMetadataValue(
                metadata,
                "DstPort",
                "DestinationPort"
            );


        if (
            string.IsNullOrWhiteSpace(ip)
            &&
            string.IsNullOrWhiteSpace(port)
        )
        {
            return "Unknown";
        }


        if (string.IsNullOrWhiteSpace(port))
        {
            return ip;
        }


        if (string.IsNullOrWhiteSpace(ip))
        {
            return port;
        }


        return $"{ip}:{port}";
    }


    // =========================================================
    // SAFE METADATA PROPERTY READER
    // =========================================================

    private static string GetMetadataValue(
        object metadata,
        params string[] propertyNames)
    {
        Type metadataType =
            metadata.GetType();


        foreach (
            string propertyName
            in propertyNames
        )
        {
            PropertyInfo? property =
                metadataType.GetProperty(
                    propertyName,
                    BindingFlags.Public
                    |
                    BindingFlags.Instance
                    |
                    BindingFlags.IgnoreCase
                );


            if (property == null)
            {
                continue;
            }


            object? value =
                property.GetValue(
                    metadata
                );


            if (value == null)
            {
                continue;
            }


            string text =
                value.ToString()
                ?? string.Empty;


            if (!string.IsNullOrWhiteSpace(text))
            {
                return text;
            }
        }


        return string.Empty;
    }


    // =========================================================
    // THREAT DISPLAY ROW
    // =========================================================

    private sealed class ThreatRow
    {
        public int FlowIndex { get; set; }


        public string Source { get; set; }
            = string.Empty;


        public string Destination { get; set; }
            = string.Empty;


        public string PredictedClass { get; set; }
            = string.Empty;


        public double Confidence { get; set; }


        public string ConfidenceDisplay =>
            $"{Confidence:P2}";


        public string RuleDisplay { get; set; }
            = "--";


        public string VerdictDisplay { get; set; }
            = "--";
    }


    // =========================================================
    // RULE CHART ROW (one bar, or one legend entry)
    // =========================================================

    private sealed class BarRow
    {
        public string Label { get; set; } = string.Empty;

        public int Count { get; set; }

        public int Max { get; set; } = 1;

        public Brush Brush { get; set; } = Brushes.Gray;

        public string Tooltip { get; set; } = string.Empty;

        public string CountDisplay => Count.ToString("N0");

        public string LegendDisplay => $"{Label} {Count:N0}";
    }


    // =========================================================
    // SHAP DISPLAY ROW
    // =========================================================

    private sealed class ShapRow
    {
        public int Rank { get; set; }


        public string Feature { get; set; }
            = string.Empty;


        public double RawValue { get; set; }


        public double ShapValue { get; set; }


        public string Direction { get; set; }
            = string.Empty;


        public string DirectionDisplay =>
            Direction switch
            {
                "supports_prediction" =>
                    "Supports prediction",

                "opposes_prediction" =>
                    "Opposes prediction",

                "neutral" =>
                    "Neutral",

                _ =>
                    Direction
            };
    }
}