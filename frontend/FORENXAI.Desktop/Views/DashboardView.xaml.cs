using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;

using FORENXAI.Desktop.Models;
using FORENXAI.Desktop.Services;

namespace FORENXAI.Desktop.Views;

public partial class DashboardView : UserControl
{
    private string fileMetadata = string.Empty;
    // =========================================================
    // SERVICES / STATE
    // =========================================================

    private readonly BackendApiService backendApi;

    private AnalysisDocument? currentAnalysis;

    private readonly ObservableCollection<ThreatRow> threats;
    private readonly ObservableCollection<PacketRow> packetRows = new();
    private readonly ObservableCollection<BarRow> attackLegend = new();
    private System.ComponentModel.ICollectionView? threatView;
    private const int PacketPageSize = 1000;
    private int packetOffset;
    private int packetMatched;
    private readonly System.Windows.Threading.DispatcherTimer packetSearchDelay =
        new() { Interval = TimeSpan.FromMilliseconds(350) };
    private const string AllOption = "All";

    // Programmatic filter changes (refill, Clear) must not each start a
    // reload; and only the newest request may fill the table.
    private bool suppressPacketEvents;
    private int packetRequest;
    private readonly ObservableCollection<TrafficLegendRow> trafficLegendRows;

    private readonly ObservableCollection<BarRow> tier1Bars = new();
    private readonly ObservableCollection<BarRow> tier2Bars = new();


    // =========================================================
    // DEFAULT CONSTRUCTOR
    // =========================================================

    public DashboardView()
    {
        InitializeComponent();

        backendApi = new BackendApiService();

        threats = new ObservableCollection<ThreatRow>();
        trafficLegendRows = new ObservableCollection<TrafficLegendRow>();

        ThreatDataGrid.ItemsSource = threats;
        PacketDataGrid.ItemsSource = packetRows;
        AttackEvidenceLegend.ItemsSource = attackLegend;
        threatView = System.Windows.Data.CollectionViewSource.GetDefaultView(threats);
        threatView.Filter = item => ThreatMatches((ThreatRow)item);
        packetSearchDelay.Tick += async (_, _) =>
        {
            packetSearchDelay.Stop();
            await LoadPacketPageAsync(resetOffset: true);
        };
        TrafficLegendItemsControl.ItemsSource = trafficLegendRows;

        Tier1Bars.ItemsSource = tier1Bars;
        Tier2Bars.ItemsSource = tier2Bars;


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


            threats.Clear();

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

            fileMetadata =
                $"{currentAnalysis.FileName}  •  {FormatFileSize(currentAnalysis.FileSize)}  •  SHA-256: {currentAnalysis.Sha256}";
            FileMetadataText.Text = fileMetadata;
            CopyMetadataButton.IsEnabled = true;


            LoadSummary();
            LoadTrafficClassification();
            LoadRulePanel();
            await LoadPacketPageAsync(resetOffset: true, refreshOptions: true);
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

    private void CopyMetadata_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(fileMetadata)) return;
        Clipboard.SetText(fileMetadata);
        StatusText.Text = "File metadata copied";
    }

    private static string FormatFileSize(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:0.##} KB";
        return $"{bytes / (1024.0 * 1024.0):0.##} MB";
    }


    // =========================================================
    // SUMMARY
    // =========================================================

    private void LoadSummary()
    {
        // Packet and forensic-flow counts come from the original
        // evidence-processing stages and are independent of ML.
        TotalPacketsText.Text =
            currentAnalysis?.TrafficSummary?.TotalPackets
                .ToString("N0")
            ?? "0";


        ForensicFlowsText.Text =
            currentAnalysis?.FlowSummary?.TotalFlows
                .ToString("N0")
            ?? "0";


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
            summary.TotalFlows.ToString("N0");


        BenignFlowsText.Text =
            summary.BenignFlows.ToString("N0");


        ThreatFlowsText.Text =
            summary.ThreatFlows.ToString("N0");


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

    private const string UncertainColour = "#64748B";

    private static Brush ToBrush(string colour) =>
        (Brush)new BrushConverter().ConvertFromString(colour)!;

    private static RuleHit? TopRuleHit(MlFinding finding) =>
        finding.RuleFindings?.FirstOrDefault(
            hit => hit.RuleId != "ALLOWLIST");

    private void ClearRulePanel()
    {
        tier1Bars.Clear();
        tier2Bars.Clear();
        EvidencePieCanvas.Children.Clear();
        EvidencePieTotalText.Text = "0";
        Tier1CoverageText.Text = string.Empty;
        EvidenceNoteText.Text = string.Empty;
        attackLegend.Clear();
        Tier1SummaryText.Text = "--";
        Tier2SummaryText.Text = "--";
        Tier2StatusText.Text = string.Empty;
        Tier2DetailsText.Text = string.Empty;
        Tier2DetailsPanel.Visibility = Visibility.Collapsed;
        RuleMlAgreementText.Text = string.Empty;
        RulesVersionText.Text = string.Empty;
    }

    private void Tier2DetailsToggle_Changed(object sender, RoutedEventArgs e)
    {
        Tier2DetailsBody.Visibility = Tier2DetailsToggle.IsChecked == true
            ? Visibility.Visible
            : Visibility.Collapsed;
        UpdateTier2DetailsHeader();
    }

    private void UpdateTier2DetailsHeader()
    {
        Tier2DetailsHeader.Text = (Tier2DetailsToggle.IsChecked == true ? "▾ Hide" : "▸ Show")
            + " Tier 2 rule evidence";
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

            // Card keeps one short line; the full evidence goes to the
            // collapsible panel under the three cards.
            Tier2StatusText.Text = tier2.Suricata == null
                ? "Suricata: unknown"
                : tier2.Suricata.Ran
                    ? $"Suricata: {tier2.Suricata.Alerts:N0} alerts · {tier2.Suricata.Mapped:N0} mapped"
                      + (tier2.InspectableShare == null ? string.Empty : $" · {tier2.InspectableShare:P0} inspectable")
                    : "Suricata not run";

            var details = new List<string>();
            if (tier2.Suricata != null)
            {
                details.Add(tier2.Suricata.Ran
                    ? $"Suricata ran: {tier2.Suricata.Alerts:N0} alerts, {tier2.Suricata.Mapped:N0} mapped to classes"
                      + (tier2.Suricata.Ignored > 0 ? $", {tier2.Suricata.Ignored:N0} ignored (checksum offload)" : string.Empty)
                    : $"Suricata not run: {tier2.Suricata.Reason}");
            }
            if (tier2.InspectableShare != null)
            {
                details.Add($"Payload inspectable: {tier2.InspectableShare:P1} of flows"
                    + $" ({tier2.EncryptedFlows ?? 0:N0} encrypted: content rules not applied)");
            }
            // Hits that belong to the capture rather than one flow (for
            // example ARP spoofing with no matching flow), with evidence.
            if (captureLevel > 0)
            {
                details.Add("\nCapture-level hits:");
                details.AddRange(tier2.CaptureLevelHits!.Select(
                    hit => $"• {hit.ClassName}: {hit.Evidence}"));
            }
            if ((tier2.Suricata?.UnmappedSignatures.Count ?? 0) > 0)
            {
                details.Add("\nSuricata alerts with no class:");
                details.AddRange(tier2.Suricata!.UnmappedSignatures.Select(name => $"• {name}"));
            }
            Tier2DetailsText.Text = string.Join("\n", details);
            Tier2DetailsPanel.Visibility = details.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
            Tier2DetailsToggle.IsChecked = false;
            UpdateTier2DetailsHeader();
        }

        // What the flow records (Tier 1 and ML input) cover, measured from
        // the packets: CICFlowMeter drops single-packet conversations.
        CaptureCoverage? coverage = currentAnalysis?.CaptureCoverage;
        Tier1CoverageText.Text = coverage == null
            ? string.Empty
            : $"Flow records cover {coverage.InFlowRecords:N0} of {coverage.PacketConversations:N0} TCP/UDP conversations in the capture."
              + (coverage.NotInFlowRecords == 0 ? string.Empty
                 : $" Not in them: {coverage.NotInFlowRecords:N0} ({coverage.SinglePacketNotExported:N0} single-packet; "
                   + "CICFlowMeter exports flows of 2+ packets only, as in the training data)."
                   + (coverage.UnansweredSynProbes.Count == 0 ? string.Empty
                      : " Single-packet SYN probes (no TCP reply): " + string.Join("; ", coverage.UnansweredSynProbes.Take(4)
                            .Select(p => $"{p.Source} → {p.Destination} {p.Ports:N0} ports"))
                        + ". Tier 2 and the Packets table still read them."));

        ShowRuleMlAgreement();
        LoadAttackEvidencePie();
    }

    // One line under both charts: where the rules and the model agree,
    // where they differ (with the most frequent pair), and what only one
    // side or neither could decide.
    private void ShowRuleMlAgreement()
    {
        var findings = currentAnalysis?.MlAnalysis?.Findings ?? new List<MlFinding>();
        int agree = 0, modelOnly = 0, uncertain = 0;
        var differ = new List<(string Ml, string Rule)>();
        foreach (MlFinding f in findings)
        {
            string? ruleClass = TopRuleHit(f)?.ClassName;
            if (ruleClass != null)
            {
                if (ruleClass == f.PredictedClass) agree++;
                else differ.Add((f.PredictedClass ?? "?", ruleClass));
            }
            else if (f.VerdictSource == "abstain") uncertain++;
            else modelOnly++;
        }

        RuleMlAgreementText.Inlines.Clear();
        void Chip(string colour, string text, string tip)
        {
            RuleMlAgreementText.Inlines.Add(new System.Windows.Documents.Run("●  ") { Foreground = ToBrush(colour) });
            RuleMlAgreementText.Inlines.Add(new System.Windows.Documents.Run(text) { ToolTip = tip });
            RuleMlAgreementText.Inlines.Add(new System.Windows.Documents.Run("      "));
        }
        RuleMlAgreementText.Inlines.Add(new System.Windows.Documents.Run("RULES vs ML    ") { FontWeight = FontWeights.Bold, Foreground = Brushes.White });
        Chip("#22C55E", $"Agree {agree:N0}", "A rule fired for the same class the model predicted");
        var top = differ.GroupBy(d => d).OrderByDescending(g => g.Count()).FirstOrDefault();
        Chip("#EF4444", $"Differ {differ.Count:N0}" + (top == null ? "" : $" (most: ML {top.Key.Ml} vs rule {top.Key.Rule}, {top.Count():N0})"),
             "A rule fired for a different class than the model predicted; the Supporting Evidence column shows which one decided");
        Chip("#3B82F6", $"Model only {modelOnly:N0}", "No rule fired; the model's class stands (including benign)");
        Chip("#64748B", $"Uncertain {uncertain:N0}", "No rule fired and the model abstained (low confidence or out of distribution): analyst review");
    }

    // Pie beside Traffic classification: the attack types (of the 15)
    // that the rule evidence supports, with the source behind each.
    private void LoadAttackEvidencePie()
    {
        var findings = currentAnalysis?.MlAnalysis?.Findings ?? new List<MlFinding>();
        var attacks = findings
            .Where(f => !string.IsNullOrEmpty(f.VerdictSource)
                        && f.VerdictSource != "abstain"
                        && f.VerdictSource != "ml"
                        && f.Verdict != "Benign"
                        && ClassColours.ContainsKey(f.Verdict ?? ""))
            .GroupBy(f => f.Verdict!)
            .OrderByDescending(g => g.Count())
            .ToList();
        int ruleBacked = attacks.Sum(g => g.Count());
        int uncertain = findings.Count(f => f.VerdictSource == "abstain");
        int charted = ruleBacked + uncertain;
        EvidencePieTotalText.Text = charted.ToString("N0");
        AttackEvidenceSubtitleText.Text = ruleBacked == 0
            ? "No attack type is supported by a Tier 1 or Tier 2 rule."
            : $"Attack types supported by Tier 1 / Tier 2 rules · {ruleBacked:N0} of {findings.Count:N0} flows";

        int modelOnly = findings.Count(f => f.VerdictSource == "ml" && f.Verdict != "Benign");
        EvidenceNoteText.Text = modelOnly == 0 ? "" : $"Not charted: {modelOnly:N0} backed by the model only.";
        if (uncertain > 0)
        {
            attacks.Add(findings.Where(f => f.VerdictSource == "abstain").GroupBy(_ => "Uncertain").First());
        }

        double start = -90.0;
        double[] sweeps = VisibleSweeps(attacks.Select(g => g.Count()).ToList());
        int slot = 0;
        foreach (var group in attacks)
        {
            int count = group.Count();
            var sources = group.GroupBy(EvidenceSourceOf).OrderByDescending(x => x.Count()).ToList();
            bool isUncertain = group.Key == "Uncertain";
            string source = isUncertain ? "no rule fired and the model abstained: analyst review"
                : sources.Count == 1
                ? EvidenceSource(sources[0].Key)
                : string.Join(" + ", sources.Select(x => $"{EvidenceSource(x.Key)} {x.Count():N0}"));
            Brush brush = ToBrush(isUncertain ? UncertainColour : ClassColours[group.Key]);
            double sweep = sweeps[slot++];
            Path slice = attacks.Count == 1
                ? CreateDonutSegment(110, 110, 100, 58, -90, 359.999, brush)
                : CreateDonutSegment(110, 110, 100, 58, start, sweep, brush);
            slice.ToolTip = $"{group.Key}: {count:N0} flows, {source}";
            EvidencePieCanvas.Children.Add(slice);
            start += sweep;

            attackLegend.Add(new BarRow
            {
                Label = $"{group.Key}  ({(double)count / charted:P1})",
                Count = count,
                Brush = brush,
                Tooltip = source,
            });
        }
    }

    // Slice angles proportional to the counts, except that every non-empty
    // slice gets at least MinSliceDegrees so a small group (e.g. 7
    // uncertain flows of 2,016) stays visible; the difference is taken from
    // the largest slice. Legends keep the exact counts and percentages.
    private const double MinSliceDegrees = 4.0;

    internal static double[] VisibleSweeps(IList<int> counts)
    {
        double total = counts.Sum();
        var sweeps = counts.Select(n => total <= 0 ? 0 : n * 360.0 / total).ToArray();
        if (sweeps.Count(s => s > 0) < 2)
        {
            return sweeps;
        }
        double added = 0;
        for (int i = 0; i < sweeps.Length; i++)
        {
            if (sweeps[i] > 0 && sweeps[i] < MinSliceDegrees)
            {
                added += MinSliceDegrees - sweeps[i];
                sweeps[i] = MinSliceDegrees;
            }
        }
        int largest = Array.IndexOf(sweeps, sweeps.Max());
        sweeps[largest] -= added;
        return sweeps;
    }

    // Source key of the evidence for one flow: "T1"/"T2" when a rule
    // decided, otherwise the verdict source (agree, ml, conflict).
    internal static string EvidenceSourceOf(MlFinding finding) =>
        finding.VerdictSource == "rule" && TopRuleHit(finding) is RuleHit hit
            ? $"T{hit.Tier}"
            : finding.VerdictSource ?? "";

    internal static string EvidenceSource(string key) => key switch
    {
        "T1" => "Tier 1 flow rule",
        "T2" => "Tier 2 packet rule",
        "agree" => "rule and model agree",
        "conflict" => "rule and model disagree",
        "ml" => "model only",
        _ => "rule",
    };

    // =========================================================
    // TRAFFIC CLASSIFICATION CHART
    // =========================================================

    private void LoadTrafficClassification()
    {
        trafficLegendRows.Clear();

        TrafficChartCanvas.Children.Clear();

        TrafficChartTotalText.Text =
            "0";


        if (
            currentAnalysis?.MlAnalysis?.Summary
            == null
            ||
            currentAnalysis?.MlAnalysis?.Findings
            == null
        )
        {
            return;
        }


        MlSummary summary =
            currentAnalysis.MlAnalysis.Summary;


        /*
         * IMPORTANT:
         *
         * This chart does not classify or modify traffic.
         * It only visualizes the predictions that already exist
         * in the completed FORENXAI analysis.
         */
        IEnumerable<MlFinding> findings =
            currentAnalysis.MlAnalysis.Findings;


        // Only the 15 attack types are charted; benign flows are counted
        // in the subtitle instead.
        int benignFlows = findings.Count(finding => !finding.Abstained &&
            string.Equals(finding.PredictedClass?.Trim(), "Benign", StringComparison.OrdinalIgnoreCase));
        TrafficChartSubtitleText.Text = benignFlows == 0
            ? "Attack types predicted by the ML model; Uncertain = model abstained"
            : $"Attack types predicted by the ML model; Uncertain = model abstained · {benignFlows:N0} benign flow{(benignFlows == 1 ? "" : "s")} not charted";

        Dictionary<string, int> classCounts =
            findings
                .Where(finding => finding.Abstained
                                  || !string.Equals(finding.PredictedClass?.Trim(), "Benign", StringComparison.OrdinalIgnoreCase))
                .GroupBy(
                    finding =>
                        finding.Abstained
                            ? "Uncertain"
                            : string.IsNullOrWhiteSpace(
                            finding.PredictedClass
                        )
                            ? "Unknown"
                            : finding.PredictedClass.Trim(),
                    StringComparer.OrdinalIgnoreCase
                )
                .ToDictionary(
                    group => group.Key,
                    group => group.Count(),
                    StringComparer.OrdinalIgnoreCase
                );


        int chartTotal =
            classCounts.Values.Sum();


        TrafficChartTotalText.Text =
            chartTotal.ToString();


        if (
            chartTotal <= 0
        )
        {
            return;
        }


        /*
         * The backend summary and the findings are produced by
         * the same completed XGBoost analysis. The chart is drawn
         * from the per-flow findings so every displayed slice
         * represents an actual predicted class from this case.
         */
        List<KeyValuePair<string, int>> orderedClasses =
            classCounts
                .OrderByDescending(
                    pair =>
                        pair.Key.Equals(
                            "Benign",
                            StringComparison.OrdinalIgnoreCase
                        )
                )
                .ThenByDescending(
                    pair => pair.Value
                )
                .ThenBy(
                    pair => pair.Key
                )
                .ToList();


        for (
            int index = 0;
            index < orderedClasses.Count;
            index++
        )
        {
            KeyValuePair<string, int> item =
                orderedClasses[index];


            double percentage =
                item.Value
                / (double)chartTotal
                * 100.0;


            Brush brush =
                GetTrafficClassBrush(
                    item.Key,
                    index
                );


            trafficLegendRows.Add(
                new TrafficLegendRow
                {
                    ClassName =
                        item.Key,

                    Count =
                        item.Value,

                    Percentage =
                        percentage,

                    Brush =
                        brush
                }
            );
        }


        DrawTrafficDonut(
            trafficLegendRows,
            chartTotal
        );


        /*
         * This is intentionally a display-only consistency check.
         * It does not alter the stored analysis or model results.
         */
        if (
            summary.TotalFlows > 0
            &&
            chartTotal != summary.TotalFlows
        )
        {
            TrafficChartTotalText.ToolTip =
                "Chart total is based on the per-flow findings. " +
                $"Summary total: {summary.TotalFlows:N0}; " +
                $"finding total: {chartTotal:N0}.";
        }
        else
        {
            TrafficChartTotalText.ToolTip =
                null;
        }
    }


    // =========================================================
    // DRAW DONUT CHART
    // =========================================================

    private void DrawTrafficDonut(
        IEnumerable<TrafficLegendRow> rows,
        int total)
    {
        TrafficChartCanvas.Children.Clear();


        if (
            total <= 0
        )
        {
            return;
        }


        const double canvasSize =
            220.0;

        const double center =
            canvasSize / 2.0;

        const double outerRadius =
            100.0;

        const double innerRadius =
            58.0;


        List<TrafficLegendRow> slices =
            rows
                .Where(
                    row =>
                        row.Count > 0
                )
                .ToList();


        if (
            slices.Count == 0
        )
        {
            return;
        }


        if (
            slices.Count == 1
        )
        {
            Ellipse fullRing =
                new Ellipse
                {
                    Width =
                        outerRadius * 2.0,

                    Height =
                        outerRadius * 2.0,

                    Stroke =
                        slices[0].Brush,

                    StrokeThickness =
                        outerRadius - innerRadius,

                    Fill =
                        Brushes.Transparent
                };


            Canvas.SetLeft(
                fullRing,
                center - outerRadius
            );

            Canvas.SetTop(
                fullRing,
                center - outerRadius
            );


            TrafficChartCanvas.Children.Add(
                fullRing
            );

            return;
        }


        double startAngle =
            -90.0;

        double[] sweeps =
            VisibleSweeps(slices.Select(row => row.Count).ToList());
        int slot = 0;

        foreach (
            TrafficLegendRow row
            in slices
        )
        {
            double sweepAngle =
                sweeps[slot++];


            if (
                sweepAngle <= 0.0
            )
            {
                continue;
            }


            Path segment =
                CreateDonutSegment(
                    center,
                    center,
                    outerRadius,
                    innerRadius,
                    startAngle,
                    sweepAngle,
                    row.Brush
                );


            TrafficChartCanvas.Children.Add(
                segment
            );


            startAngle +=
                sweepAngle;
        }
    }


    // =========================================================
    // CREATE DONUT SEGMENT
    // =========================================================

    private static Path CreateDonutSegment(
        double centerX,
        double centerY,
        double outerRadius,
        double innerRadius,
        double startAngle,
        double sweepAngle,
        Brush fill)
    {
        double safeSweep =
            Math.Min(
                sweepAngle,
                359.999
            );


        double endAngle =
            startAngle
            + safeSweep;


        Point outerStart =
            PointOnCircle(
                centerX,
                centerY,
                outerRadius,
                startAngle
            );


        Point outerEnd =
            PointOnCircle(
                centerX,
                centerY,
                outerRadius,
                endAngle
            );


        Point innerEnd =
            PointOnCircle(
                centerX,
                centerY,
                innerRadius,
                endAngle
            );


        Point innerStart =
            PointOnCircle(
                centerX,
                centerY,
                innerRadius,
                startAngle
            );


        bool isLargeArc =
            safeSweep > 180.0;


        PathFigure figure =
            new PathFigure
            {
                StartPoint =
                    outerStart,

                IsClosed =
                    true,

                IsFilled =
                    true
            };


        figure.Segments.Add(
            new ArcSegment
            {
                Point =
                    outerEnd,

                Size =
                    new Size(
                        outerRadius,
                        outerRadius
                    ),

                SweepDirection =
                    SweepDirection.Clockwise,

                IsLargeArc =
                    isLargeArc
            }
        );


        figure.Segments.Add(
            new LineSegment(
                innerEnd,
                true
            )
        );


        figure.Segments.Add(
            new ArcSegment
            {
                Point =
                    innerStart,

                Size =
                    new Size(
                        innerRadius,
                        innerRadius
                    ),

                SweepDirection =
                    SweepDirection.Counterclockwise,

                IsLargeArc =
                    isLargeArc
            }
        );


        figure.Segments.Add(
            new LineSegment(
                outerStart,
                true
            )
        );


        PathGeometry geometry =
            new PathGeometry();


        geometry.Figures.Add(
            figure
        );


        return new Path
        {
            Data =
                geometry,

            Fill =
                fill,

            Stroke =
                new SolidColorBrush(
                    Color.FromRgb(
                        11,
                        18,
                        32
                    )
                ),

            StrokeThickness =
                1.0,

            SnapsToDevicePixels =
                true
        };
    }


    // =========================================================
    // POINT ON CIRCLE
    // =========================================================

    private static Point PointOnCircle(
        double centerX,
        double centerY,
        double radius,
        double angleDegrees)
    {
        double radians =
            angleDegrees
            * Math.PI
            / 180.0;


        return new Point(
            centerX
            + radius
            * Math.Cos(
                radians
            ),

            centerY
            + radius
            * Math.Sin(
                radians
            )
        );
    }


    // =========================================================
    // TRAFFIC CLASS COLORS
    // =========================================================

    private static Brush GetTrafficClassBrush(
        string className,
        int fallbackIndex)
    {
        string normalized =
            className
                .Trim()
                .Replace(
                    "-",
                    string.Empty
                )
                .Replace(
                    "_",
                    string.Empty
                )
                .Replace(
                    " ",
                    string.Empty
                )
                .ToLowerInvariant();


        string colorHex =
            normalized switch
            {
                "benign" =>
                    "#4ADE80",

                "uncertain" =>
                    UncertainColour,

                "dos" =>
                    "#3B82F6",

                "ddos" =>
                    "#F59E0B",

                "portscan" =>
                    "#8B5CF6",

                "bruteforce" =>
                    "#EC4899",

                "slowloris" =>
                    "#F87171",

                "c2beaconing" =>
                    "#06B6D4",

                "dns" =>
                    "#22D3EE",

                "mitm" =>
                    "#A78BFA",

                "exfiltration" =>
                    "#FB7185",

                "exploitation" =>
                    "#F97316",

                "evasion" =>
                    "#EAB308",

                "webbased" =>
                    "#14B8A6",

                "api" =>
                    "#60A5FA",

                "bufferoverflow" =>
                    "#D946EF",

                "tlsssl" =>
                    "#2DD4BF",

                _ =>
                    FallbackTrafficColors[
                        Math.Abs(
                            fallbackIndex
                        )
                        % FallbackTrafficColors.Length
                    ]
            };


        return new SolidColorBrush(
            (Color)
            ColorConverter.ConvertFromString(
                colorHex
            )
        );
    }


    private static readonly string[]
        FallbackTrafficColors =
        {
            "#64748B",
            "#38BDF8",
            "#C084FC",
            "#FB7185",
            "#FBBF24",
            "#34D399",
            "#818CF8",
            "#F472B6"
        };


    // =========================================================
    // LOAD THREATS
    // =========================================================

    private void LoadThreats()
    {
        threats.Clear();


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

                    Source = finding.PseudoFlow ? NonIpLabel
                        : BuildSourceText(
                            finding.Metadata
                        ),

                    Destination = finding.PseudoFlow ? NonIpLabel
                        : BuildDestinationText(
                            finding.Metadata
                        ),

                    PredictedClass =
                        finding.PredictedClass,

                    Confidence =
                        finding.Confidence,

                    Time = finding.Connection != null
                        ? FormatTime(finding.Connection.FirstTime)
                        : finding.Metadata?.Timestamp ?? "",
                    Protocol = ProtocolName(finding.Metadata?.Protocol ?? 0),
                    Length = finding.Connection?.Bytes ?? 0,
                    Info = ConnectionInfo(finding),

                    RuleDisplay =
                        topHit == null
                            ? (finding.RuleFindings == null ? "not run" : "--")
                            : $"{topHit.ClassName} (T{topHit.Tier})",

                    SourceIp = finding.PseudoFlow ? NonIpLabel : finding.Metadata?.SrcIp ?? "",
                    DestinationIp = finding.PseudoFlow ? NonIpLabel : finding.Metadata?.DstIp ?? "",
                    SourcePort = finding.Metadata?.SrcPort ?? 0,
                    DestinationPort = finding.Metadata?.DstPort ?? 0,
                    EvidenceSource = finding.VerdictSource == "abstain" ? "Uncertain"
                        : string.IsNullOrEmpty(finding.VerdictSource) ? ""
                        : EvidenceSource(EvidenceSourceOf(finding)),

                    EvidenceClass =
                        finding.VerdictSource == "abstain" ? "Uncertain"
                        : string.IsNullOrEmpty(finding.VerdictSource) ? "" : finding.Verdict ?? "",

                    VerdictDisplay =
                        string.IsNullOrEmpty(finding.VerdictSource)
                            ? "--"
                            : finding.VerdictSource == "abstain"
                                ? "Uncertain · analyst review"
                                : $"{finding.Verdict} · {EvidenceSource(EvidenceSourceOf(finding))}"
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


        flowByConnection = new Dictionary<string, int>();
        foreach (MlFinding finding in currentAnalysis.MlAnalysis.Findings)
        {
            FlowMetadata? m = finding.Metadata;
            if (m != null)
            {
                flowByConnection.TryAdd(
                    ConnectionKey(m.SrcIp, m.SrcPort, m.DstIp, m.DstPort, ProtocolName(m.Protocol)),
                    finding.FlowIndex);
            }
        }

        // Options list only what this capture actually contains.
        FillFilter(ThreatProtocolFilter, "All", threats.Select(t => t.Protocol));
        FillFilter(ThreatClassFilter, "All", threats.Select(t => t.PredictedClass));
        FillFilter(ThreatEvidenceFilter, "All", threats.Select(t => t.EvidenceClass));
        FillFilter(ThreatEvidenceSourceFilter, "All", threats.Select(t => t.EvidenceSource));
        FillFilter(ThreatSourceFilter, "All", threats.Select(t => t.SourceIp));
        FillFilter(ThreatDestinationFilter, "All", threats.Select(t => t.DestinationIp));
        // Confidence bands that actually occur in this capture, highest first.
        ThreatConfidenceFilter.Items.Clear();
        ThreatConfidenceFilter.Items.Add("Any");
        foreach (var band in ConfidenceBands.Where(b => threats.Any(t => t.Confidence >= b.Min && t.Confidence < b.Max)))
        {
            ThreatConfidenceFilter.Items.Add(band.Label);
        }
        ThreatConfidenceFilter.SelectedIndex = 0;
        ApplyThreatFilter();
    }


    // =========================================================
    // PHASE 15.2
    // OPEN SELECTED THREAT IN XAI
    // =========================================================

    private void ThreatDataGrid_MouseDoubleClick(
        object sender,
        System.Windows.Input.MouseButtonEventArgs e)
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
    // PACKETS, CONNECTIONS AND FILTERS
    //
    // Length and Info for a detected flow come from the packets of
    // its connection (same addresses, ports and protocol, both
    // directions), the way Wireshark's conversation view counts them.
    // ponytail: keyed by 5-tuple, so a connection that CICFlowMeter
    // split into several flows shows the whole connection's totals.
    // =========================================================

    // Connection -> flow index of the first analysed flow on it, so a
    // double-clicked packet can open its flow in XAI.
    private Dictionary<string, int> flowByConnection = new();

    private static string ConnectionKey(string? a, int? aPort, string? b, int? bPort, string protocol)
    {
        var one = $"{a}:{aPort}";
        var two = $"{b}:{bPort}";
        return string.CompareOrdinal(one, two) < 0 ? $"{protocol}|{one}|{two}" : $"{protocol}|{two}|{one}";
    }

    private static string ProtocolName(int number) => number switch
    {
        6 => "TCP", 17 => "UDP", 1 => "ICMP", 58 => "ICMPv6", 0 => "Other (ICMP, IGMP, non-IP)", _ => $"IP {number}",
    };

    private static string FormatTime(double epochSeconds) =>
        DateTimeOffset.FromUnixTimeMilliseconds((long)(epochSeconds * 1000.0))
            .ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss.fff");

    // CICFlowMeter folds non-IP frames (ARP) into one pseudo-flow whose
    // addresses are ARP header bytes (e.g. 8.6.0.1 -> 8.0.6.4); the backend
    // flags it (pseudo_flow) because no packet carries those addresses.
    // ICMP / IGMP flows also have protocol 0 and ports 0 but real addresses,
    // so they are not relabelled.
    private const string NonIpLabel = "Non-IP frames (ARP)";

    // Ports, TCP flags and packet count of the flow's connection.
    private static string ConnectionInfo(MlFinding finding)
    {
        FlowMetadata? m = finding.Metadata;
        FlowConnection? c = finding.Connection;
        if (m == null || c == null)
        {
            return "";
        }
        return $"{m.SrcPort} → {m.DstPort}"
            + (c.Flags.Count > 0 ? $" [{string.Join(", ", c.Flags)}]" : "")
            + $" · {c.Packets:N0} packet{(c.Packets == 1 ? "" : "s")}";
    }

    // One page of packets, filtered on the backend. Filter options come
    // from what the capture contains (with counts), refreshed on case load.
    private async Task LoadPacketPageAsync(bool resetOffset, bool refreshOptions = false)
    {
        string caseId = CaseIdTextBox.Text.Trim();
        if (string.IsNullOrEmpty(caseId) || currentAnalysis == null)
        {
            return;
        }
        if (resetOffset)
        {
            packetOffset = 0;
        }

        int request = ++packetRequest;
        PacketFilterStatusText.Text = "Loading packets...";
        try
        {
            PacketPage page = await backendApi.GetPacketsAsync(
                caseId, packetOffset, PacketPageSize,
                new PacketQuery
                {
                    Protocol = Chosen(PacketProtocolFilter),
                    Flag = Chosen(PacketFlagFilter),
                    Source = Chosen(PacketSourceFilter),
                    Destination = Chosen(PacketDestinationFilter),
                    IpVersion = Chosen(PacketIpVersionFilter),
                    Interface = Chosen(PacketInterfaceFilter),
                    Port = PacketPortFilter.Text.Trim(),
                    MinLength = int.TryParse(PacketMinLengthFilter.Text, out int min) ? min : null,
                    MaxLength = int.TryParse(PacketMaxLengthFilter.Text, out int max) ? max : null,
                    Text = PacketSearchBox.Text.Trim(),
                });
            if (request != packetRequest)
            {
                return;     // a newer filter change superseded this page
            }
            double firstTime = page.FirstTime ?? 0;

            packetRows.Clear();
            foreach (PacketRecord packet in page.Rows)
            {
                packetRows.Add(new PacketRow
                {
                    Number = packet.PacketNumber,
                    Time = FormatTime(packet.Timestamp),
                    Source = packet.SourceIp ?? "",
                    SourcePort = packet.SourcePort?.ToString() ?? "",
                    Destination = packet.DestinationIp ?? "",
                    DestinationPort = packet.DestinationPort?.ToString() ?? "",
                    Protocol = packet.DisplayProtocol ?? packet.Protocol ?? "",
                    Transport = packet.Protocol ?? "",
                    Length = packet.WireLength ?? packet.PacketLength,
                    Flags = string.Join(", ", packet.Flags ?? new List<string>()),
                    Info = packet.Info ?? "",
                    Relative = (packet.Timestamp - firstTime).ToString("0.000000"),
                    SourceMac = packet.SourceMac ?? "",
                    DestinationMac = packet.DestinationMac ?? "",
                    EtherType = packet.EtherType ?? "",
                    Vlan = packet.Vlan?.ToString() ?? "",
                    Interface = packet.Interface ?? "",
                    IpVersion = packet.IpVersion?.ToString() ?? "",
                    Ttl = packet.Ttl?.ToString() ?? "",
                    IpId = packet.IpId?.ToString() ?? "",
                    IpFlags = packet.IpFlags ?? "",
                    FragmentOffset = packet.FragmentOffset?.ToString() ?? "",
                    Dscp = packet.Dscp?.ToString() ?? "",
                    Ecn = packet.Ecn?.ToString() ?? "",
                    IpHeaderLength = packet.IpHeaderLength?.ToString() ?? "",
                    IpTotalLength = packet.IpTotalLength?.ToString() ?? "",
                    TcpSeq = packet.TcpSeq?.ToString() ?? "",
                    TcpAck = packet.TcpAck?.ToString() ?? "",
                    TcpWindow = packet.TcpWindow?.ToString() ?? "",
                    TcpHeaderLength = packet.TcpHeaderLength?.ToString() ?? "",
                    TcpOptions = packet.TcpOptions ?? "",
                    UdpLength = packet.UdpLength?.ToString() ?? "",
                    IcmpType = packet.IcmpType?.ToString() ?? "",
                    IcmpCode = packet.IcmpCode?.ToString() ?? "",
                    PayloadLength = packet.PayloadLength?.ToString() ?? "",
                    CapturedLength = packet.CapturedLength?.ToString() ?? "",
                    Comment = packet.Comment ?? "",
                });
            }

            packetMatched = page.Matched;
            if (refreshOptions)
            {
                suppressPacketEvents = true;
                FillFilter(PacketProtocolFilter, "All", page.Protocols.Keys);
                FillFilter(PacketFlagFilter, "All", page.Flags.Keys);
                FillFilter(PacketSourceFilter, "All", page.Sources.Keys);
                FillFilter(PacketDestinationFilter, "All", page.Destinations.Keys);
                FillFilter(PacketIpVersionFilter, "All", page.IpVersions.Keys);
                FillFilter(PacketInterfaceFilter, "All", page.Interfaces.Keys);
                suppressPacketEvents = false;
                ShowPacketColumns(page.Columns);
                PacketInterfaceFilter.ToolTip = string.Join("\n", page.Interfaces.Select(i => $"{i.Key}: {i.Value:N0} packets"));
                PacketIpVersionFilter.ToolTip = string.Join("\n", page.IpVersions.Select(v => $"{v.Key}: {v.Value:N0} packets"));
                PacketCountText.Text =
                    $"{page.Total:N0} packets in the capture · "
                    + string.Join(", ", page.Protocols.OrderByDescending(p => p.Value).Select(p => $"{p.Key} {p.Value:N0}"));
            }

            int first = page.Matched == 0 ? 0 : packetOffset + 1;
            int last = packetOffset + packetRows.Count;
            PacketFilterStatusText.Text = $"Showing {first:N0}–{last:N0} of {page.Matched:N0} matching ({page.Total:N0} total)";
            PacketPrevButton.IsEnabled = packetOffset > 0;
            PacketNextButton.IsEnabled = last < page.Matched;
        }
        catch (Exception ex)
        {
            suppressPacketEvents = false;
            if (request == packetRequest)
            {
                PacketFilterStatusText.Text = "Could not load packets: " + ex.Message;
            }
        }
    }

    private async void PacketPrev_Click(object sender, RoutedEventArgs e)
    {
        packetOffset = Math.Max(0, packetOffset - PacketPageSize);
        await LoadPacketPageAsync(resetOffset: false);
    }

    private async void PacketNext_Click(object sender, RoutedEventArgs e)
    {
        if (packetOffset + PacketPageSize < packetMatched)
        {
            packetOffset += PacketPageSize;
            await LoadPacketPageAsync(resetOffset: false);
        }
    }

    private static void FillFilter(ComboBox box, string allLabel, IEnumerable<string> values)
    {
        box.Items.Clear();
        box.Items.Add(allLabel);
        foreach (var value in values.Where(v => !string.IsNullOrEmpty(v)).Distinct().OrderBy(v => v))
        {
            box.Items.Add(value);
        }
        box.SelectedIndex = 0;
    }

    private static string? Chosen(ComboBox box) => box.SelectedIndex > 0 ? box.SelectedItem as string : null;

    private bool ThreatMatches(ThreatRow row)
    {
        string? protocol = Chosen(ThreatProtocolFilter);
        string? mlClass = Chosen(ThreatClassFilter);
        string? evidence = Chosen(ThreatEvidenceFilter);
        string? evidenceSource = Chosen(ThreatEvidenceSourceFilter);
        string? source = Chosen(ThreatSourceFilter);
        string? destination = Chosen(ThreatDestinationFilter);
        string? band = Chosen(ThreatConfidenceFilter);
        var range = ConfidenceBands.FirstOrDefault(b => b.Label == band);
        bool portOk = !int.TryParse(ThreatPortFilter.Text.Trim(), out int port)
            || row.SourcePort == port || row.DestinationPort == port;
        return (protocol == null || row.Protocol == protocol)
            && (mlClass == null || row.PredictedClass == mlClass)
            && (evidence == null || row.EvidenceClass == evidence)
            && (evidenceSource == null || row.EvidenceSource == evidenceSource)
            && (source == null || row.SourceIp == source)
            && (destination == null || row.DestinationIp == destination)
            && (band == null || (row.Confidence >= range.Min && row.Confidence < range.Max))
            && portOk
            && AllWordsIn(ThreatSearchBox.Text,
                $"{row.FlowIndex} {row.Time} {row.Source} {row.Destination} {row.Protocol} {row.Length} {row.PredictedClass} {row.VerdictDisplay} {row.Info}");
    }

    private static readonly (string Label, double Min, double Max)[] ConfidenceBands =
    {
        ("90% and above", 0.90, 1.01), ("70% to 90%", 0.70, 0.90), ("50% to 70%", 0.50, 0.70), ("Below 50%", 0.0, 0.50),
    };

    // Columns the capture has no value for (e.g. VLAN, comments) are hidden.
    private static readonly Dictionary<string, string> PacketColumnFields = new()
    {
        ["No."] = "packet_number", ["Time"] = "timestamp", ["Relative (s)"] = "timestamp", ["Source"] = "source_ip",
        ["Src Port"] = "source_port", ["Destination"] = "destination_ip", ["Dst Port"] = "destination_port",
        ["Protocol"] = "display_protocol", ["Length"] = "wire_length", ["Info"] = "info", ["Src MAC"] = "src_mac",
        ["Dst MAC"] = "dst_mac", ["EtherType"] = "ether_type", ["VLAN"] = "vlan", ["Interface"] = "interface",
        ["IP Ver"] = "ip_version", ["TTL"] = "ttl", ["IP ID"] = "ip_id", ["IP Flags"] = "ip_flags",
        ["Frag Offset"] = "fragment_offset", ["DSCP"] = "dscp", ["ECN"] = "ecn", ["IP Hdr"] = "ip_header_length",
        ["IP Len"] = "ip_total_length", ["TCP Flags"] = "tcp_flags", ["Seq"] = "tcp_seq", ["Ack"] = "tcp_ack",
        ["Window"] = "tcp_window", ["TCP Hdr"] = "tcp_header_length", ["TCP Options"] = "tcp_options",
        ["UDP Len"] = "udp_length", ["ICMP Type"] = "icmp_type", ["ICMP Code"] = "icmp_code",
        ["Payload"] = "payload_length", ["Bytes in file"] = "captured_length", ["Comment"] = "comment",
    };

    private void ShowPacketColumns(IReadOnlyCollection<string> present)
    {
        var fields = new HashSet<string>(present);
        foreach (DataGridColumn column in PacketDataGrid.Columns)
        {
            string header = column.Header?.ToString() ?? "";
            column.Visibility = !PacketColumnFields.TryGetValue(header, out string? field) || fields.Contains(field)
                ? Visibility.Visible
                : Visibility.Collapsed;
        }
        // Filters stay enabled even with one value (e.g. one interface), so
        // the dropdown shows what the capture recorded; empty ones are off.
        PacketInterfaceFilter.IsEnabled = PacketInterfaceFilter.Items.Count > 1;
        PacketIpVersionFilter.IsEnabled = PacketIpVersionFilter.Items.Count > 1;
    }

    private void ThreatClearFilters_Click(object sender, RoutedEventArgs e)
    {
        foreach (ComboBox box in new[] { ThreatProtocolFilter, ThreatClassFilter, ThreatConfidenceFilter, ThreatEvidenceFilter,
                                         ThreatEvidenceSourceFilter, ThreatSourceFilter, ThreatDestinationFilter })
        {
            box.SelectedIndex = 0;
        }
        ThreatPortFilter.Clear();
        ThreatSearchBox.Clear();
        ApplyThreatFilter();
    }

    private async void PacketClearFilters_Click(object sender, RoutedEventArgs e)
    {
        suppressPacketEvents = true;
        foreach (ComboBox box in new[] { PacketProtocolFilter, PacketFlagFilter, PacketSourceFilter, PacketDestinationFilter,
                                         PacketIpVersionFilter, PacketInterfaceFilter })
        {
            box.SelectedIndex = 0;
        }
        foreach (TextBox box in new[] { PacketPortFilter, PacketMinLengthFilter, PacketMaxLengthFilter, PacketSearchBox })
        {
            box.Clear();
        }
        suppressPacketEvents = false;
        packetSearchDelay.Stop();
        await LoadPacketPageAsync(resetOffset: true);
    }

    // Space-separated words, all of which must appear (any order, any case).
    private static bool AllWordsIn(string query, string haystack) =>
        query.Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .All(word => haystack.Contains(word, StringComparison.OrdinalIgnoreCase));

    private void ApplyThreatFilter()
    {
        threatView?.Refresh();
        ThreatFilterStatusText.Text = $"Showing {threatView?.Cast<object>().Count() ?? 0:N0} of {threats.Count:N0}";
    }

    private void ThreatFilter_Changed(object sender, RoutedEventArgs e)
    {
        if (IsLoaded) ApplyThreatFilter();
    }

    private void PacketDataGrid_MouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (PacketDataGrid.SelectedItem is not PacketRow packet)
        {
            return;
        }

        int? sourcePort = int.TryParse(packet.SourcePort, out int sp) ? sp : null;
        int? destinationPort = int.TryParse(packet.DestinationPort, out int dp) ? dp : null;
        string key = ConnectionKey(packet.Source, sourcePort, packet.Destination, destinationPort, packet.Transport);
        bool isIp = packet.IpVersion != "";

        // CICFlowMeter records IP packets without ports (ICMP, IGMP) as
        // protocol 0 with ports 0, and folds non-IP frames (ARP) into one
        // pseudo-flow; look those up the same way.
        bool found = flowByConnection.TryGetValue(key, out int flowIndex);
        if (!found && isIp && sourcePort == null)
        {
            found = flowByConnection.TryGetValue(
                ConnectionKey(packet.Source, 0, packet.Destination, 0, ProtocolName(0)), out flowIndex);
        }
        if (!found && !isIp
            && currentAnalysis?.MlAnalysis?.Findings.FirstOrDefault(f => f.PseudoFlow) is MlFinding pseudo)
        {
            flowIndex = pseudo.FlowIndex;
            found = true;
        }

        if (!found)
        {
            string reason = sourcePort != null
                ? $"Its connection ({packet.Source}:{packet.SourcePort} ↔ {packet.Destination}:{packet.DestinationPort}) "
                  + "is not in the CICFlowMeter flow records. CICFlowMeter exports only connections with 2 or more packets, "
                  + "as in the model's training data, so single-packet probes and one-off queries have no flow."
                : $"CICFlowMeter made no flow for this {packet.Protocol} packet.";
            MessageBox.Show(
                $"Packet {packet.Number} ({packet.Protocol}) cannot be opened in XAI: it has no ML prediction or SHAP explanation.\n\n"
                + reason + "\n\nTier 2 rules and Suricata still inspect it.",
                "FORENXAI: no XAI for this packet", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!threats.Any(t => t.FlowIndex == flowIndex))
        {
            MessageBox.Show(
                $"Packet {packet.Number} belongs to flow {flowIndex}, which the model classified as benign. The XAI tab lists detected threats only.",
                "FORENXAI: no XAI for this packet", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (Window.GetWindow(this) is FORENXAI.Desktop.MainWindow mainWindow)
        {
            mainWindow.ShowXai(CaseIdTextBox.Text.Trim(), flowIndex);
        }
    }

    // Drop-downs reload at once; typing waits for a short pause.
    private async void PacketFilter_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded || currentAnalysis == null || suppressPacketEvents)
        {
            return;
        }
        if (sender is TextBox)
        {
            packetSearchDelay.Stop();
            packetSearchDelay.Start();
            return;
        }
        await LoadPacketPageAsync(resetOffset: true);
    }

    private sealed class PacketRow
    {
        public int Number { get; set; }
        public string Time { get; set; } = string.Empty;
        public string Source { get; set; } = string.Empty;
        public string SourcePort { get; set; } = string.Empty;
        public string Destination { get; set; } = string.Empty;
        public string DestinationPort { get; set; } = string.Empty;
        public string Protocol { get; set; } = string.Empty;
        public int Length { get; set; }
        public string Flags { get; set; } = string.Empty;
        public string Info { get; set; } = string.Empty;
        public string Transport { get; set; } = string.Empty;
        public string Relative { get; set; } = string.Empty;
        public string SourceMac { get; set; } = string.Empty;
        public string DestinationMac { get; set; } = string.Empty;
        public string EtherType { get; set; } = string.Empty;
        public string Vlan { get; set; } = string.Empty;
        public string Interface { get; set; } = string.Empty;
        public string IpVersion { get; set; } = string.Empty;
        public string Ttl { get; set; } = string.Empty;
        public string IpId { get; set; } = string.Empty;
        public string IpFlags { get; set; } = string.Empty;
        public string FragmentOffset { get; set; } = string.Empty;
        public string Dscp { get; set; } = string.Empty;
        public string Ecn { get; set; } = string.Empty;
        public string IpHeaderLength { get; set; } = string.Empty;
        public string IpTotalLength { get; set; } = string.Empty;
        public string TcpSeq { get; set; } = string.Empty;
        public string TcpAck { get; set; } = string.Empty;
        public string TcpWindow { get; set; } = string.Empty;
        public string TcpHeaderLength { get; set; } = string.Empty;
        public string TcpOptions { get; set; } = string.Empty;
        public string UdpLength { get; set; } = string.Empty;
        public string IcmpType { get; set; } = string.Empty;
        public string IcmpCode { get; set; } = string.Empty;
        public string PayloadLength { get; set; } = string.Empty;
        public string CapturedLength { get; set; } = string.Empty;
        public string Comment { get; set; } = string.Empty;
    }


    // =========================================================
    // RESET DASHBOARD
    // =========================================================

    private void ResetDashboard()
    {
        currentAnalysis = null;

        ClearRulePanel();

        threats.Clear();
        packetRows.Clear();
        trafficLegendRows.Clear();

        TrafficChartCanvas.Children.Clear();

        TrafficChartTotalText.Text =
            "0";


        TotalPacketsText.Text =
            "0";


        ForensicFlowsText.Text =
            "0";


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
    // TRAFFIC LEGEND ROW
    // =========================================================

    private sealed class TrafficLegendRow
    {
        public string ClassName { get; set; }
            = string.Empty;


        public int Count { get; set; }


        public double Percentage { get; set; }


        public Brush Brush { get; set; }
            = Brushes.Gray;


        public string DisplayValue =>
            $"{Count:N0} ({Percentage:F1}%)";
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

        public string Time { get; set; } = string.Empty;

        public string Protocol { get; set; } = string.Empty;

        public long Length { get; set; }

        public string Info { get; set; } = string.Empty;

        public string EvidenceClass { get; set; } = string.Empty;

        public string EvidenceSource { get; set; } = string.Empty;

        public string SourceIp { get; set; } = string.Empty;

        public string DestinationIp { get; set; } = string.Empty;

        public int SourcePort { get; set; }

        public int DestinationPort { get; set; }
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
