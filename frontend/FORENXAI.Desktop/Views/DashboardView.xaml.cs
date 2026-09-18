using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

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