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
    // =========================================================
    // SERVICES / STATE
    // =========================================================

    private readonly BackendApiService backendApi;

    private AnalysisDocument? currentAnalysis;

    private readonly ObservableCollection<ThreatRow> threats;
    private readonly ObservableCollection<ShapRow> shapRows;
    private readonly ObservableCollection<TrafficLegendRow> trafficLegendRows;


    // =========================================================
    // DEFAULT CONSTRUCTOR
    // =========================================================

    public DashboardView()
    {
        InitializeComponent();

        backendApi = new BackendApiService();

        threats = new ObservableCollection<ThreatRow>();
        shapRows = new ObservableCollection<ShapRow>();
        trafficLegendRows = new ObservableCollection<TrafficLegendRow>();

        ThreatDataGrid.ItemsSource = threats;
        ShapDataGrid.ItemsSource = shapRows;
        TrafficLegendItemsControl.ItemsSource = trafficLegendRows;

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
            LoadTrafficClassification();
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


        Dictionary<string, int> classCounts =
            findings
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
            if (!finding.IsThreat)
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
                        finding.Confidence
                }
            );
        }


        ThreatCountText.Text =
            $"{threats.Count} threat flow" +
            (threats.Count == 1 ? "" : "s");


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

        threats.Clear();
        shapRows.Clear();
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