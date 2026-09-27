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
    private System.ComponentModel.ICollectionView? packetView;
    private const string AllOption = "All";
    private readonly ObservableCollection<TrafficLegendRow> trafficLegendRows;

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
        trafficLegendRows = new ObservableCollection<TrafficLegendRow>();

        ThreatDataGrid.ItemsSource = threats;
        PacketDataGrid.ItemsSource = packetRows;
        AttackEvidenceLegend.ItemsSource = attackLegend;
        threatView = System.Windows.Data.CollectionViewSource.GetDefaultView(threats);
        threatView.Filter = item => ThreatMatches((ThreatRow)item);
        packetView = System.Windows.Data.CollectionViewSource.GetDefaultView(packetRows);
        packetView.Filter = item => PacketMatches((PacketRow)item);
        TrafficLegendItemsControl.ItemsSource = trafficLegendRows;

        Tier1Bars.ItemsSource = tier1Bars;
        Tier2Bars.ItemsSource = tier2Bars;
        VerdictLegend.ItemsSource = verdictLegend;


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
            LoadPackets();
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
        EvidencePieCanvas.Children.Clear();
        EvidencePieTotalText.Text = "0";
        EvidenceNoteText.Text = string.Empty;
        attackLegend.Clear();
        Tier1SummaryText.Text = "--";
        Tier2SummaryText.Text = "--";
        Tier2StatusText.Text = string.Empty;
        Tier2DetailsText.Text = string.Empty;
        Tier2DetailsPanel.Visibility = Visibility.Collapsed;
        VerdictSummaryText.Text = "--";
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

        // Hybrid source: one stacked line of rule / model / uncertain.
        int decided = rules.VerdictSources.Values.Sum();
        VerdictSummaryText.Text = decided == 0
            ? "No flows in this case."
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
            var segment = new Border { Background = ToBrush(colour), ToolTip = meaning };
            Grid.SetColumn(segment, VerdictBar.ColumnDefinitions.Count - 1);
            VerdictBar.Children.Add(segment);

            verdictLegend.Add(new BarRow
            {
                Label = $"{label} · {count:N0} ({(double)count / decided:P1}): {meaning}",
                Count = count,
                Brush = ToBrush(colour),
                Tooltip = meaning,
            });
        }

        LoadAttackEvidencePie();
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
        EvidencePieTotalText.Text = ruleBacked.ToString("N0");
        AttackEvidenceSubtitleText.Text = ruleBacked == 0
            ? "No attack type is supported by a Tier 1 or Tier 2 rule."
            : $"Attack types supported by Tier 1 / Tier 2 rules · {ruleBacked:N0} of {findings.Count:N0} flows";

        int modelOnly = findings.Count(f => f.VerdictSource == "ml" && f.Verdict != "Benign");
        int uncertain = findings.Count(f => f.VerdictSource == "abstain");
        var notCharted = new List<string>();
        if (modelOnly > 0) notCharted.Add($"{modelOnly:N0} backed by the model only");
        if (uncertain > 0) notCharted.Add($"{uncertain:N0} uncertain (analyst review)");
        EvidenceNoteText.Text = notCharted.Count == 0 ? "" : "Not charted: " + string.Join(", ", notCharted) + ".";

        double start = -90.0;
        foreach (var group in attacks)
        {
            int count = group.Count();
            var sources = group.GroupBy(EvidenceSourceOf).OrderByDescending(x => x.Count()).ToList();
            string source = sources.Count == 1
                ? EvidenceSource(sources[0].Key)
                : string.Join(" + ", sources.Select(x => $"{EvidenceSource(x.Key)} {x.Count():N0}"));
            Brush brush = ToBrush(ClassColours[group.Key]);
            double sweep = count * 360.0 / ruleBacked;
            Path slice = attacks.Count == 1
                ? CreateDonutSegment(110, 110, 100, 58, -90, 359.999, brush)
                : CreateDonutSegment(110, 110, 100, 58, start, sweep, brush);
            slice.ToolTip = $"{group.Key}: {count:N0} flows, {source}";
            EvidencePieCanvas.Children.Add(slice);
            start += sweep;

            attackLegend.Add(new BarRow
            {
                Label = $"{group.Key}  ({(double)count / ruleBacked:P1})",
                Count = count,
                Brush = brush,
                Tooltip = source,
            });
        }
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
        int benignFlows = findings.Count(finding =>
            string.Equals(finding.PredictedClass?.Trim(), "Benign", StringComparison.OrdinalIgnoreCase));
        TrafficChartSubtitleText.Text = benignFlows == 0
            ? "Attack types predicted by the ML model"
            : $"Attack types predicted by the ML model · {benignFlows:N0} benign flow{(benignFlows == 1 ? "" : "s")} not charted";

        Dictionary<string, int> classCounts =
            findings
                .Where(finding => !string.Equals(finding.PredictedClass?.Trim(), "Benign", StringComparison.OrdinalIgnoreCase))
                .GroupBy(
                    finding =>
                        string.IsNullOrWhiteSpace(
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


        foreach (
            TrafficLegendRow row
            in slices
        )
        {
            double sweepAngle =
                row.Count
                / (double)total
                * 360.0;


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

                    Time = ConnectionOf(finding.Metadata)?.FirstTime ?? finding.Metadata?.Timestamp ?? "",
                    Protocol = ProtocolName(finding.Metadata?.Protocol ?? 0),
                    Length = ConnectionOf(finding.Metadata)?.Bytes ?? 0,
                    Info = ConnectionOf(finding.Metadata)?.Info(finding.Metadata!) ?? "",

                    RuleDisplay =
                        topHit == null
                            ? (finding.RuleFindings == null ? "not run" : "--")
                            : $"{topHit.ClassName} (T{topHit.Tier})",

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

        FillFilter(ThreatProtocolFilter, "All protocols", threats.Select(t => t.Protocol));
        FillFilter(ThreatClassFilter, "All ML predictions", threats.Select(t => t.PredictedClass));
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

    private Dictionary<string, Connection> connections = new();

    // Connection -> flow index of the first analysed flow on it, so a
    // double-clicked packet can open its flow in XAI.
    private Dictionary<string, int> flowByConnection = new();

    private static string ConnectionKey(string? a, int? aPort, string? b, int? bPort, string protocol)
    {
        var one = $"{a}:{aPort}";
        var two = $"{b}:{bPort}";
        return string.CompareOrdinal(one, two) < 0 ? $"{protocol}|{one}|{two}" : $"{protocol}|{two}|{one}";
    }

    private Connection? ConnectionOf(FlowMetadata? m) =>
        m == null ? null
        : connections.GetValueOrDefault(ConnectionKey(m.SrcIp, m.SrcPort, m.DstIp, m.DstPort, ProtocolName(m.Protocol)));

    private static string ProtocolName(int number) => number switch
    {
        6 => "TCP", 17 => "UDP", 1 => "ICMP", 58 => "ICMPv6", 0 => "Other", _ => $"IP {number}",
    };

    private static string FormatTime(double epochSeconds) =>
        DateTimeOffset.FromUnixTimeMilliseconds((long)(epochSeconds * 1000.0))
            .ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss.fff");

    private void LoadPackets()
    {
        packetRows.Clear();
        connections = new Dictionary<string, Connection>();
        var packets = currentAnalysis?.Packets ?? new List<PacketRecord>();
        foreach (var packet in packets)
        {
            string protocol = packet.Protocol ?? "Other";
            var row = new PacketRow
            {
                Number = packet.PacketNumber,
                Time = FormatTime(packet.Timestamp),
                Source = packet.SourceIp ?? "",
                SourcePort = packet.SourcePort?.ToString() ?? "",
                Destination = packet.DestinationIp ?? "",
                DestinationPort = packet.DestinationPort?.ToString() ?? "",
                Protocol = protocol,
                Length = packet.PacketLength,
                Flags = FlagNames(packet.TcpFlags),
            };
            row.Info = packet.SourcePort.HasValue
                ? $"{packet.SourcePort} → {packet.DestinationPort}" + (row.Flags.Length > 0 ? $" [{row.Flags}]" : "")
                : protocol == "ARP" ? "Address resolution (link layer)" : protocol;
            packetRows.Add(row);

            if (packet.SourcePort.HasValue)
            {
                string key = ConnectionKey(packet.SourceIp, packet.SourcePort, packet.DestinationIp, packet.DestinationPort, protocol);
                if (!connections.TryGetValue(key, out var c))
                {
                    connections[key] = c = new Connection { FirstTime = row.Time };
                }
                c.Packets++;
                c.Bytes += packet.PacketLength;
                foreach (var flag in row.Flags.Split(", ", StringSplitOptions.RemoveEmptyEntries))
                {
                    c.Flags.Add(flag);
                }
            }
        }

        PacketCountText.Text = $"{packets.Count:N0} packets in the capture";
        FillFilter(PacketProtocolFilter, "All protocols", packetRows.Select(p => p.Protocol));
        FillFilter(PacketFlagFilter, "All TCP flags",
            packetRows.SelectMany(p => p.Flags.Split(", ", StringSplitOptions.RemoveEmptyEntries)));
        ApplyPacketFilter();
    }

    private static string FlagNames(string? flags) => string.Join(", ", (flags ?? "").Select(f => f switch
    {
        'S' => "SYN", 'A' => "ACK", 'F' => "FIN", 'R' => "RST", 'P' => "PSH", 'U' => "URG", 'E' => "ECE", 'C' => "CWR",
        _ => f.ToString(),
    }));

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
        string text = ThreatSearchBox.Text.Trim();
        return (protocol == null || row.Protocol == protocol)
            && (mlClass == null || row.PredictedClass == mlClass)
            && (text.Length == 0 || $"{row.FlowIndex} {row.Source} {row.Destination} {row.PredictedClass} {row.VerdictDisplay} {row.Info}"
                .Contains(text, StringComparison.OrdinalIgnoreCase));
    }

    private bool PacketMatches(PacketRow row)
    {
        string? protocol = Chosen(PacketProtocolFilter);
        string? flag = Chosen(PacketFlagFilter);
        string text = PacketSearchBox.Text.Trim();
        return (protocol == null || row.Protocol == protocol)
            && (flag == null || row.Flags.Split(", ").Contains(flag))
            && (text.Length == 0 || $"{row.Number} {row.Source} {row.SourcePort} {row.Destination} {row.DestinationPort} {row.Info}"
                .Contains(text, StringComparison.OrdinalIgnoreCase));
    }

    private void ApplyThreatFilter()
    {
        threatView?.Refresh();
        ThreatFilterStatusText.Text = $"Showing {threatView?.Cast<object>().Count() ?? 0:N0} of {threats.Count:N0}";
    }

    private void ApplyPacketFilter()
    {
        packetView?.Refresh();
        PacketFilterStatusText.Text = $"Showing {packetView?.Cast<object>().Count() ?? 0:N0} of {packetRows.Count:N0}";
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
        string key = ConnectionKey(packet.Source, sourcePort, packet.Destination, destinationPort, packet.Protocol);

        if (!flowByConnection.TryGetValue(key, out int flowIndex))
        {
            MessageBox.Show(
                $"Packet {packet.Number} ({packet.Protocol}) is not part of an analysed flow, so it has no ML prediction or SHAP explanation.",
                "FORENXAI", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (!threats.Any(t => t.FlowIndex == flowIndex))
        {
            MessageBox.Show(
                $"Packet {packet.Number} belongs to flow {flowIndex}, which the model classified as benign. The XAI tab lists detected threats only.",
                "FORENXAI", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (Window.GetWindow(this) is FORENXAI.Desktop.MainWindow mainWindow)
        {
            mainWindow.ShowXai(CaseIdTextBox.Text.Trim(), flowIndex);
        }
    }

    private void PacketFilter_Changed(object sender, RoutedEventArgs e)
    {
        if (IsLoaded) ApplyPacketFilter();
    }

    private sealed class Connection
    {
        public string FirstTime { get; set; } = string.Empty;
        public int Packets { get; set; }
        public long Bytes { get; set; }
        public SortedSet<string> Flags { get; } = new();

        public string Info(FlowMetadata m) =>
            $"{m.SrcPort} → {m.DstPort}"
            + (Flags.Count > 0 ? $" [{string.Join(", ", Flags)}]" : "")
            + $" · {Packets:N0} packet{(Packets == 1 ? "" : "s")}";
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
