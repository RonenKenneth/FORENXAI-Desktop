using Microsoft.Win32;

using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

using FORENXAI.Desktop.Services;

namespace FORENXAI.Desktop.Views;


public partial class ReportsView : UserControl
{
    private readonly BackendApiService backendApi;

    private readonly ObservableCollection<ReportThreatRow>
        threatRows;

    private CaseReportResponse? currentReport;


    // =========================================================
    // DEFAULT CONSTRUCTOR
    // =========================================================

    public ReportsView()
    {
        InitializeComponent();


        backendApi =
            new BackendApiService();


        threatRows =
            new ObservableCollection<ReportThreatRow>();


        ThreatFindingsDataGrid.ItemsSource =
            threatRows;


        ClearReport();
    }


    // =========================================================
    // CONSTRUCTOR WITH CASE ID
    // =========================================================

    public ReportsView(
        string caseId)
        : this()
    {
        CaseIdTextBox.Text =
            caseId;


        Loaded += async (_, _) =>
        {
            await LoadReportAsync(
                caseId
            );
        };
    }


    // =========================================================
    // LOAD REPORT BUTTON
    // =========================================================

    private async void LoadReportButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        string caseId =
            CaseIdTextBox
                .Text
                .Trim();


        if (
            string.IsNullOrWhiteSpace(
                caseId
            )
        )
        {
            MessageBox.Show(
                "Please enter a Case ID.",
                "FORENXAI",
                MessageBoxButton.OK,
                MessageBoxImage.Information
            );


            return;
        }


        await LoadReportAsync(
            caseId
        );
    }


    // =========================================================
    // LOAD REPORT
    // =========================================================

    private async Task LoadReportAsync(
        string caseId)
    {
        try
        {
            // =================================================
            // LOADING STATE
            // =================================================

            LoadReportButton.IsEnabled =
                false;


            LoadReportButton.Content =
                "LOADING...";


            ExportJsonButton.IsEnabled =
                false;


            ExportPdfButton.IsEnabled =
                false;


            ReportStatusText.Text =
                $"Loading forensic report for {caseId}...";


            threatRows.Clear();


            // =================================================
            // GET REPORT FROM BACKEND
            // =================================================

            currentReport =
                await backendApi
                    .GetCaseReportAsync(
                        caseId
                    );


            if (
                currentReport
                == null
            )
            {
                throw new InvalidOperationException(
                    "The backend returned no report data."
                );
            }


            // =================================================
            // CASE INFORMATION
            // =================================================

            CaseIdTextBox.Text =
                currentReport
                    .Case
                    .CaseId;


            CaseIdValueText.Text =
                SafeText(
                    currentReport
                        .Case
                        .CaseId
                );


            EvidenceFileValueText.Text =
                SafeText(
                    currentReport
                        .Case
                        .EvidenceFile
                );


            FileSizeValueText.Text =
                FormatFileSize(
                    currentReport
                        .Case
                        .FileSize
                );


            Sha256ValueText.Text =
                SafeText(
                    currentReport
                        .Case
                        .Sha256
                );


            // =================================================
            // ML SUMMARY
            // =================================================

            TotalFlowsText.Text =
                currentReport
                    .MlSummary
                    .TotalFlows
                    .ToString();


            BenignFlowsText.Text =
                currentReport
                    .MlSummary
                    .BenignFlows
                    .ToString();


            ThreatFlowsText.Text =
                currentReport
                    .MlSummary
                    .ThreatFlows
                    .ToString();


            // =================================================
            // REVIEW SUMMARY
            // =================================================

            ConfirmedReviewsText.Text =
                currentReport
                    .ReviewSummary
                    .Confirmed
                    .ToString();


            RejectedReviewsText.Text =
                currentReport
                    .ReviewSummary
                    .Rejected
                    .ToString();


            InconclusiveReviewsText.Text =
                currentReport
                    .ReviewSummary
                    .Inconclusive
                    .ToString();


            // =================================================
            // THREAT FINDINGS
            // =================================================

            LoadThreatFindings();


            // =================================================
            // STATUS
            // =================================================

            ReportStatusText.Text =
                BuildReportStatus();


            // =================================================
            // ENABLE EXPORT
            // =================================================

            ExportJsonButton.IsEnabled =
                true;


            ExportPdfButton.IsEnabled =
                true;
        }
        catch (Exception ex)
        {
            currentReport =
                null;


            ClearReport();


            ReportStatusText.Text =
                "Could not load forensic report.";


            MessageBox.Show(
                "Could not load the forensic report.\n\n" +
                ex.Message,
                "FORENXAI Report Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error
            );
        }
        finally
        {
            LoadReportButton.IsEnabled =
                true;


            LoadReportButton.Content =
                "LOAD REPORT";
        }
    }


    // =========================================================
    // LOAD THREAT FINDINGS
    // =========================================================

    private void LoadThreatFindings()
    {
        threatRows.Clear();


        if (
            currentReport
            == null
            ||
            currentReport.ThreatFindings
            == null
        )
        {
            ThreatFindingCountText.Text =
                "0 findings";


            return;
        }


        foreach (
            ReportThreatFinding finding
            in currentReport.ThreatFindings
        )
        {
            // =================================================
            // REVIEW DECISION
            // =================================================

            string reviewDecision =
                "Not Reviewed";


            if (
                finding.InvestigatorReview
                != null
                &&
                !string.IsNullOrWhiteSpace(
                    finding
                        .InvestigatorReview
                        .Decision
                )
            )
            {
                reviewDecision =
                    finding
                        .InvestigatorReview
                        .Decision;
            }


            // =================================================
            // RECOMMENDATION SUMMARY
            // =================================================

            string recommendationSummary =
                "No recommendation available.";


            if (
                finding.Recommendation
                != null
                &&
                !string.IsNullOrWhiteSpace(
                    finding
                        .Recommendation
                        .Summary
                )
            )
            {
                recommendationSummary =
                    finding
                        .Recommendation
                        .Summary;
            }


            // =================================================
            // ADD ROW
            // =================================================

            threatRows.Add(
                new ReportThreatRow
                {
                    FlowIndex =
                        finding.FlowIndex,

                    PredictedClass =
                        finding.PredictedClass,

                    Confidence =
                        finding.Confidence,

                    ReviewDecision =
                        reviewDecision,

                    RecommendationSummary =
                        recommendationSummary
                }
            );
        }


        ThreatFindingCountText.Text =
            $"{threatRows.Count} " +
            (
                threatRows.Count == 1
                    ? "finding"
                    : "findings"
            );
    }


    // =========================================================
    // BUILD REPORT STATUS
    // =========================================================

    private string BuildReportStatus()
    {
        if (
            currentReport
            == null
        )
        {
            return
                "No report loaded.";
        }


        int totalThreats =
            currentReport
                .MlSummary
                .ThreatFlows;


        int reviewed =
            currentReport
                .ReviewSummary
                .TotalReviews;


        int unreviewed =
            Math.Max(
                0,
                totalThreats - reviewed
            );


        if (
            totalThreats == 0
        )
        {
            return
                "Report loaded successfully. " +
                "No threat flows were identified.";
        }


        if (
            unreviewed == 0
        )
        {
            return
                $"Report loaded successfully. " +
                $"All {totalThreats} detected threat flows " +
                $"have investigator reviews.";
        }


        return
            $"Report loaded successfully. " +
            $"{reviewed} of {totalThreats} detected threat flows " +
            $"have investigator reviews. " +
            $"{unreviewed} remain unreviewed.";
    }


    // =========================================================
    // CLEAR REPORT
    // =========================================================

    private void ClearReport()
    {
        threatRows.Clear();


        CaseIdValueText.Text =
            "--";


        EvidenceFileValueText.Text =
            "--";


        FileSizeValueText.Text =
            "--";


        Sha256ValueText.Text =
            "--";


        TotalFlowsText.Text =
            "0";


        BenignFlowsText.Text =
            "0";


        ThreatFlowsText.Text =
            "0";


        ConfirmedReviewsText.Text =
            "0";


        RejectedReviewsText.Text =
            "0";


        InconclusiveReviewsText.Text =
            "0";


        ThreatFindingCountText.Text =
            "0 findings";


        ReportStatusText.Text =
            "No report loaded.";


        ExportJsonButton.IsEnabled =
            false;


        ExportPdfButton.IsEnabled =
            false;
    }


    // =========================================================
    // EXPORT JSON
    // =========================================================

    private void ExportJsonButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (
            currentReport
            == null
        )
        {
            MessageBox.Show(
                "Please load a forensic report first.",
                "FORENXAI",
                MessageBoxButton.OK,
                MessageBoxImage.Information
            );


            return;
        }


        try
        {
            // =================================================
            // SAVE DIALOG
            // =================================================

            SaveFileDialog dialog =
                new SaveFileDialog
                {
                    Title =
                        "Export FORENXAI JSON Report",

                    Filter =
                        "JSON Files (*.json)|*.json",

                    DefaultExt =
                        ".json",

                    AddExtension =
                        true,

                    FileName =
                        $"{currentReport.Case.CaseId}" +
                        "_FORENXAI_Report.json"
                };


            bool? result =
                dialog.ShowDialog();


            if (
                result != true
            )
            {
                return;
            }


            // =================================================
            // SERIALIZE REPORT
            // =================================================

            JsonSerializerOptions options =
                new JsonSerializerOptions
                {
                    WriteIndented =
                        true
                };


            string json =
                JsonSerializer.Serialize(
                    currentReport,
                    options
                );


            // =================================================
            // WRITE JSON FILE
            // =================================================

            File.WriteAllText(
                dialog.FileName,
                json
            );


            // =================================================
            // STATUS
            // =================================================

            ReportStatusText.Text =
                "JSON report exported successfully.";


            MessageBox.Show(
                "FORENXAI JSON report exported successfully.\n\n" +
                $"Saved to:\n{dialog.FileName}",
                "FORENXAI JSON Export",
                MessageBoxButton.OK,
                MessageBoxImage.Information
            );
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                "Could not export the JSON report.\n\n" +
                ex.Message,
                "FORENXAI JSON Export Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error
            );
        }
    }


    // =========================================================
    // EXPORT PDF
    // =========================================================

    private void ExportPdfButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (
            currentReport
            == null
        )
        {
            MessageBox.Show(
                "Please load a forensic report first.",
                "FORENXAI",
                MessageBoxButton.OK,
                MessageBoxImage.Information
            );


            return;
        }


        try
        {
            // =================================================
            // SAVE DIALOG
            // =================================================

            SaveFileDialog dialog =
                new SaveFileDialog
                {
                    Title =
                        "Export FORENXAI PDF Report",

                    Filter =
                        "PDF Files (*.pdf)|*.pdf",

                    DefaultExt =
                        ".pdf",

                    AddExtension =
                        true,

                    FileName =
                        $"{currentReport.Case.CaseId}" +
                        "_FORENXAI_Report.pdf"
                };


            bool? result =
                dialog.ShowDialog();


            if (
                result != true
            )
            {
                return;
            }


            // =================================================
            // DISABLE BUTTON WHILE GENERATING
            // =================================================

            ExportPdfButton.IsEnabled =
                false;


            ExportPdfButton.Content =
                "EXPORTING...";


            ReportStatusText.Text =
                "Generating PDF report...";


            // =================================================
            // GENERATE PDF
            // =================================================

            PdfReportService.Generate(
                currentReport,
                dialog.FileName
            );


            // =================================================
            // STATUS
            // =================================================

            ReportStatusText.Text =
                "PDF report exported successfully.";


            // =================================================
            // SUCCESS MESSAGE
            // =================================================

            MessageBox.Show(
                "FORENXAI PDF report exported successfully.\n\n" +
                $"Saved to:\n{dialog.FileName}",
                "FORENXAI PDF Export",
                MessageBoxButton.OK,
                MessageBoxImage.Information
            );
        }
        catch (Exception ex)
        {
            ReportStatusText.Text =
                "PDF export failed.";


            MessageBox.Show(
                "Could not export the PDF report.\n\n" +
                $"Error type: {ex.GetType().Name}\n\n" +
                $"Message: {ex.Message}",
                "FORENXAI PDF Export Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error
            );
        }
        finally
        {
            if (
                currentReport
                != null
            )
            {
                ExportPdfButton.IsEnabled =
                    true;
            }


            ExportPdfButton.Content =
                "EXPORT PDF";
        }
    }


    // =========================================================
    // SAFE TEXT
    // =========================================================

    private static string SafeText(
        string? value)
    {
        if (
            string.IsNullOrWhiteSpace(
                value
            )
        )
        {
            return
                "--";
        }


        return
            value;
    }


    // =========================================================
    // FORMAT FILE SIZE
    // =========================================================

    private static string FormatFileSize(
        long bytes)
    {
        if (
            bytes < 0
        )
        {
            return
                "--";
        }


        if (
            bytes < 1024
        )
        {
            return
                $"{bytes:N0} bytes";
        }


        double kilobytes =
            bytes / 1024.0;


        if (
            kilobytes < 1024
        )
        {
            return
                $"{kilobytes:N2} KB";
        }


        double megabytes =
            kilobytes / 1024.0;


        if (
            megabytes < 1024
        )
        {
            return
                $"{megabytes:N2} MB";
        }


        double gigabytes =
            megabytes / 1024.0;


        return
            $"{gigabytes:N2} GB";
    }


    // =========================================================
    // REPORT THREAT TABLE ROW
    // =========================================================

    private sealed class ReportThreatRow
    {
        public int FlowIndex
        {
            get;
            set;
        }


        public string PredictedClass
        {
            get;
            set;
        }
        = string.Empty;


        public double Confidence
        {
            get;
            set;
        }


        public string ConfidenceDisplay
        {
            get
            {
                return
                    $"{Confidence:P2}";
            }
        }


        public string ReviewDecision
        {
            get;
            set;
        }
        = string.Empty;


        public string RecommendationSummary
        {
            get;
            set;
        }
        = string.Empty;
    }
}