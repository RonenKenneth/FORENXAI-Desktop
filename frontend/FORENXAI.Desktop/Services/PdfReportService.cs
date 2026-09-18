using System;
using System.Linq;

using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;

namespace FORENXAI.Desktop.Services;


public static class PdfReportService
{
    // =========================================================
    // GENERATE FORENXAI PDF REPORT
    // =========================================================

    public static void Generate(
        CaseReportResponse report,
        string outputPath)
    {
        if (report == null)
        {
            throw new ArgumentNullException(
                nameof(report)
            );
        }


        if (
            string.IsNullOrWhiteSpace(
                outputPath
            )
        )
        {
            throw new ArgumentException(
                "PDF output path cannot be empty.",
                nameof(outputPath)
            );
        }


        QuestPDF.Settings.License =
            LicenseType.Community;


        Document.Create(
            document =>
            {
                document.Page(
                    page =>
                    {
                        // =====================================
                        // PAGE CONFIGURATION
                        // =====================================

                        page.Size(
                            PageSizes.A4
                        );


                        page.Margin(
                            35
                        );


                        page.DefaultTextStyle(
                            style =>
                                style
                                    .FontSize(10)
                                    .FontColor(
                                        Colors.Grey.Darken3
                                    )
                        );


                        // =====================================
                        // HEADER
                        // =====================================

                        page.Header()
                            .Column(
                                column =>
                                {
                                    column.Spacing(
                                        4
                                    );


                                    column.Item()
                                        .Text(
                                            "FORENXAI"
                                        )
                                        .FontSize(
                                            22
                                        )
                                        .Bold()
                                        .FontColor(
                                            Colors.Blue.Darken3
                                        );


                                    column.Item()
                                        .Text(
                                            "Forensic Analysis Report"
                                        )
                                        .FontSize(
                                            16
                                        )
                                        .SemiBold();


                                    column.Item()
                                        .Text(
                                            $"Case ID: {report.Case.CaseId}"
                                        )
                                        .FontSize(
                                            10
                                        )
                                        .FontColor(
                                            Colors.Grey.Darken1
                                        );
                                }
                            );


                        // =====================================
                        // CONTENT
                        // =====================================

                        page.Content()
                            .PaddingVertical(
                                18
                            )
                            .Column(
                                column =>
                                {
                                    column.Spacing(
                                        18
                                    );


                                    // =================================
                                    // CASE INFORMATION
                                    // =================================

                                    column.Item()
                                        .Element(
                                            container =>
                                                SectionTitle(
                                                    container,
                                                    "1. Case Information"
                                                )
                                        );


                                    column.Item()
                                        .Table(
                                            table =>
                                            {
                                                table.ColumnsDefinition(
                                                    columns =>
                                                    {
                                                        columns.ConstantColumn(
                                                            120
                                                        );

                                                        columns.RelativeColumn();
                                                    }
                                                );


                                                AddInfoRow(
                                                    table,
                                                    "Case ID",
                                                    report.Case.CaseId
                                                );


                                                AddInfoRow(
                                                    table,
                                                    "Evidence File",
                                                    report.Case.EvidenceFile
                                                );


                                                AddInfoRow(
                                                    table,
                                                    "File Size",
                                                    FormatFileSize(
                                                        report.Case.FileSize
                                                    )
                                                );


                                                AddInfoRow(
                                                    table,
                                                    "SHA-256",
                                                    report.Case.Sha256
                                                );
                                            }
                                        );


                                    // =================================
                                    // TRAFFIC SUMMARY
                                    // =================================

                                    column.Item()
                                        .Element(
                                            container =>
                                                SectionTitle(
                                                    container,
                                                    "2. Traffic Summary"
                                                )
                                        );


                                    column.Item()
                                        .Table(
                                            table =>
                                            {
                                                table.ColumnsDefinition(
                                                    columns =>
                                                    {
                                                        columns.ConstantColumn(
                                                            160
                                                        );

                                                        columns.RelativeColumn();
                                                    }
                                                );


                                                AddInfoRow(
                                                    table,
                                                    "Total Packets",
                                                    report
                                                        .TrafficSummary
                                                        .TotalPackets
                                                        .ToString("N0")
                                                );


                                                AddInfoRow(
                                                    table,
                                                    "Total Bytes",
                                                    report
                                                        .TrafficSummary
                                                        .TotalBytes
                                                        .ToString("N0")
                                                );


                                                AddInfoRow(
                                                    table,
                                                    "Custom Flows",
                                                    report
                                                        .FlowSummary
                                                        .TotalFlows
                                                        .ToString("N0")
                                                );


                                                string protocols =
                                                    report
                                                        .TrafficSummary
                                                        .Protocols
                                                        .Count == 0
                                                    ? "None"
                                                    : string.Join(
                                                        ", ",
                                                        report
                                                            .TrafficSummary
                                                            .Protocols
                                                            .Select(
                                                                item =>
                                                                    $"{item.Key}: {item.Value:N0}"
                                                            )
                                                    );


                                                AddInfoRow(
                                                    table,
                                                    "Protocols",
                                                    protocols
                                                );
                                            }
                                        );


                                    // =================================
                                    // ML SUMMARY
                                    // =================================

                                    column.Item()
                                        .Element(
                                            container =>
                                                SectionTitle(
                                                    container,
                                                    "3. Machine Learning Summary"
                                                )
                                        );


                                    column.Item()
                                        .Table(
                                            table =>
                                            {
                                                table.ColumnsDefinition(
                                                    columns =>
                                                    {
                                                        columns.RelativeColumn();
                                                        columns.RelativeColumn();
                                                        columns.RelativeColumn();
                                                        columns.RelativeColumn();
                                                    }
                                                );


                                                AddSummaryHeader(
                                                    table,
                                                    "ML Flows"
                                                );

                                                AddSummaryHeader(
                                                    table,
                                                    "Benign"
                                                );

                                                AddSummaryHeader(
                                                    table,
                                                    "Threats"
                                                );

                                                AddSummaryHeader(
                                                    table,
                                                    "Threat %"
                                                );


                                                AddSummaryValue(
                                                    table,
                                                    report
                                                        .MlSummary
                                                        .TotalFlows
                                                        .ToString("N0")
                                                );

                                                AddSummaryValue(
                                                    table,
                                                    report
                                                        .MlSummary
                                                        .BenignFlows
                                                        .ToString("N0")
                                                );

                                                AddSummaryValue(
                                                    table,
                                                    report
                                                        .MlSummary
                                                        .ThreatFlows
                                                        .ToString("N0")
                                                );

                                                AddSummaryValue(
                                                    table,
                                                    $"{report.MlSummary.ThreatPercentage:F2}%"
                                                );
                                            }
                                        );


                                    // =================================
                                    // CLASS DISTRIBUTION
                                    // =================================

                                    if (
                                        report
                                            .MlSummary
                                            .ClassCounts
                                            .Count
                                        > 0
                                    )
                                    {
                                        column.Item()
                                            .Text(
                                                "Class Distribution"
                                            )
                                            .SemiBold()
                                            .FontSize(
                                                11
                                            );


                                        column.Item()
                                            .Table(
                                                table =>
                                                {
                                                    table.ColumnsDefinition(
                                                        columns =>
                                                        {
                                                            columns.RelativeColumn();

                                                            columns.ConstantColumn(
                                                                90
                                                            );
                                                        }
                                                    );


                                                    table.Header(
                                                        header =>
                                                        {
                                                            HeaderCell(
                                                                header.Cell(),
                                                                "Class"
                                                            );


                                                            HeaderCell(
                                                                header.Cell(),
                                                                "Count"
                                                            );
                                                        }
                                                    );


                                                    foreach (
                                                        var item
                                                        in report
                                                            .MlSummary
                                                            .ClassCounts
                                                            .OrderByDescending(
                                                                item =>
                                                                    item.Value
                                                            )
                                                    )
                                                    {
                                                        BodyCell(
                                                            table.Cell(),
                                                            item.Key
                                                        );


                                                        BodyCell(
                                                            table.Cell(),
                                                            item.Value.ToString(
                                                                "N0"
                                                            )
                                                        );
                                                    }
                                                }
                                            );
                                    }


                                    // =================================
                                    // INVESTIGATOR REVIEW SUMMARY
                                    // =================================

                                    column.Item()
                                        .Element(
                                            container =>
                                                SectionTitle(
                                                    container,
                                                    "4. Investigator Review Summary"
                                                )
                                        );


                                    column.Item()
                                        .Table(
                                            table =>
                                            {
                                                table.ColumnsDefinition(
                                                    columns =>
                                                    {
                                                        columns.RelativeColumn();
                                                        columns.RelativeColumn();
                                                        columns.RelativeColumn();
                                                        columns.RelativeColumn();
                                                    }
                                                );


                                                AddSummaryHeader(
                                                    table,
                                                    "Reviewed"
                                                );

                                                AddSummaryHeader(
                                                    table,
                                                    "Confirmed"
                                                );

                                                AddSummaryHeader(
                                                    table,
                                                    "Rejected"
                                                );

                                                AddSummaryHeader(
                                                    table,
                                                    "Inconclusive"
                                                );


                                                AddSummaryValue(
                                                    table,
                                                    report
                                                        .ReviewSummary
                                                        .TotalReviews
                                                        .ToString()
                                                );

                                                AddSummaryValue(
                                                    table,
                                                    report
                                                        .ReviewSummary
                                                        .Confirmed
                                                        .ToString()
                                                );

                                                AddSummaryValue(
                                                    table,
                                                    report
                                                        .ReviewSummary
                                                        .Rejected
                                                        .ToString()
                                                );

                                                AddSummaryValue(
                                                    table,
                                                    report
                                                        .ReviewSummary
                                                        .Inconclusive
                                                        .ToString()
                                                );
                                            }
                                        );


                                    // =================================
                                    // THREAT FINDINGS
                                    // =================================

                                    column.Item()
                                        .Element(
                                            container =>
                                                SectionTitle(
                                                    container,
                                                    "5. Threat Findings"
                                                )
                                        );


                                    if (
                                        report
                                            .ThreatFindings
                                            .Count
                                        == 0
                                    )
                                    {
                                        column.Item()
                                            .Text(
                                                "No threat findings were recorded."
                                            );
                                    }
                                    else
                                    {
                                        foreach (
                                            ReportThreatFinding finding
                                            in report.ThreatFindings
                                        )
                                        {
                                            column.Item()
                                                .Element(
                                                    container =>
                                                        ThreatFinding(
                                                            container,
                                                            finding
                                                        )
                                                );
                                        }
                                    }


                                    // =================================
                                    // METHODOLOGY
                                    // =================================

                                    column.Item()
                                        .Element(
                                            container =>
                                                SectionTitle(
                                                    container,
                                                    "6. Methodology and Interpretation"
                                                )
                                        );


                                    column.Item()
                                        .Text(
                                            "FORENXAI performs flow-based network analysis " +
                                            "using an XGBoost multiclass classifier. " +
                                            "TreeSHAP is used to identify the features that " +
                                            "supported or opposed each model prediction. " +
                                            "Recommendations are taken from the response " +
                                            "playbook associated with the predicted class. " +
                                            "Investigator review decisions remain separate " +
                                            "from the automated model output."
                                        );


                                    column.Item()
                                        .Text(
                                            "Model predictions and SHAP explanations are " +
                                            "decision-support information and should be " +
                                            "evaluated together with the underlying network " +
                                            "evidence and other case artifacts."
                                        )
                                        .Italic();
                                }
                            );


                        // =====================================
                        // FOOTER
                        // =====================================

                        page.Footer()
                            .Row(
                                row =>
                                {
                                    row.RelativeItem()
                                        .Text(
                                            $"FORENXAI - {report.Case.CaseId}"
                                        )
                                        .FontSize(
                                            8
                                        )
                                        .FontColor(
                                            Colors.Grey.Medium
                                        );


                                    row.ConstantItem(
                                        120
                                    )
                                    .AlignRight()
                                    .DefaultTextStyle(
                                        style =>
                                            style
                                                .FontSize(
                                                    8
                                                )
                                                .FontColor(
                                                    Colors.Grey.Medium
                                                )
                                    )
                                    .Text(
                                        text =>
                                        {
                                            text.Span(
                                                "Page "
                                            );


                                            text.CurrentPageNumber();


                                            text.Span(
                                                " of "
                                            );


                                            text.TotalPages();
                                        }
                                    );
                                }
                            );
                    }
                );
            }
        )
        .GeneratePdf(
            outputPath
        );
    }


    // =========================================================
    // SECTION TITLE
    // =========================================================

    private static void SectionTitle(
        IContainer container,
        string title)
    {
        container
            .PaddingBottom(
                5
            )
            .BorderBottom(
                1
            )
            .BorderColor(
                Colors.Grey.Lighten2
            )
            .Text(
                title
            )
            .FontSize(
                14
            )
            .SemiBold()
            .FontColor(
                Colors.Blue.Darken3
            );
    }


    // =========================================================
    // INFORMATION ROW
    // =========================================================

    private static void AddInfoRow(
        TableDescriptor table,
        string label,
        string? value)
    {
        table.Cell()
            .BorderBottom(
                1
            )
            .BorderColor(
                Colors.Grey.Lighten3
            )
            .Padding(
                6
            )
            .Text(
                label
            )
            .SemiBold();


        table.Cell()
            .BorderBottom(
                1
            )
            .BorderColor(
                Colors.Grey.Lighten3
            )
            .Padding(
                6
            )
            .Text(
                string.IsNullOrWhiteSpace(
                    value
                )
                    ? "--"
                    : value
            );
    }


    // =========================================================
    // SUMMARY HEADER
    // =========================================================

    private static void AddSummaryHeader(
        TableDescriptor table,
        string value)
    {
        table.Cell()
            .Background(
                Colors.Grey.Lighten3
            )
            .Padding(
                6
            )
            .AlignCenter()
            .Text(
                value
            )
            .SemiBold();
    }


    // =========================================================
    // SUMMARY VALUE
    // =========================================================

    private static void AddSummaryValue(
        TableDescriptor table,
        string value)
    {
        table.Cell()
            .BorderBottom(
                1
            )
            .BorderColor(
                Colors.Grey.Lighten2
            )
            .Padding(
                8
            )
            .AlignCenter()
            .Text(
                value
            )
            .FontSize(
                12
            )
            .SemiBold();
    }


    // =========================================================
    // TABLE HEADER CELL
    // =========================================================

    private static void HeaderCell(
        IContainer container,
        string text)
    {
        container
            .Background(
                Colors.Grey.Lighten3
            )
            .Padding(
                6
            )
            .Text(
                text
            )
            .SemiBold();
    }


    // =========================================================
    // TABLE BODY CELL
    // =========================================================

    private static void BodyCell(
        IContainer container,
        string text)
    {
        container
            .BorderBottom(
                1
            )
            .BorderColor(
                Colors.Grey.Lighten3
            )
            .Padding(
                6
            )
            .Text(
                text
            );
    }


    // =========================================================
    // THREAT FINDING
    // =========================================================

    private static void ThreatFinding(
        IContainer container,
        ReportThreatFinding finding)
    {
        container
            .Border(
                1
            )
            .BorderColor(
                Colors.Grey.Lighten2
            )
            .Padding(
                10
            )
            .Column(
                column =>
                {
                    column.Spacing(
                        5
                    );


                    column.Item()
                        .Text(
                            $"Flow {finding.FlowIndex} - " +
                            $"{finding.PredictedClass}"
                        )
                        .Bold()
                        .FontSize(
                            12
                        );


                    column.Item()
                        .Text(
                            $"Confidence: " +
                            $"{finding.Confidence:P2}"
                        );


                    // =========================================
                    // SHAP CONTRIBUTORS
                    // =========================================

                    if (
                        finding.ShapExplanation
                        != null
                        &&
                        finding
                            .ShapExplanation
                            .Contributors
                            .Count
                        > 0
                    )
                    {
                        column.Item()
                            .Text(
                                "Top SHAP Contributors"
                            )
                            .SemiBold();


                        foreach (
                            var contributor
                            in finding
                                .ShapExplanation
                                .Contributors
                                .Take(
                                    5
                                )
                        )
                        {
                            string direction =
                                contributor.Direction
                                switch
                                {
                                    "supports_prediction"
                                        => "Supports",

                                    "opposes_prediction"
                                        => "Opposes",

                                    _
                                        => "Neutral"
                                };


                            column.Item()
                                .PaddingLeft(
                                    10
                                )
                                .Text(
                                    $"{contributor.Rank}. " +
                                    $"{contributor.Feature} - " +
                                    $"{direction} " +
                                    $"(SHAP {contributor.ShapValue:F4})"
                                );
                        }
                    }


                    // =========================================
                    // RECOMMENDATION
                    // =========================================

                    if (
                        finding.Recommendation
                        != null
                    )
                    {
                        column.Item()
                            .Text(
                                "Recommendation"
                            )
                            .SemiBold();


                        if (
                            !string.IsNullOrWhiteSpace(
                                finding
                                    .Recommendation
                                    .Summary
                            )
                        )
                        {
                            column.Item()
                                .Text(
                                    finding
                                        .Recommendation
                                        .Summary
                                );
                        }


                        foreach (
                            string action
                            in finding
                                .Recommendation
                                .Actions
                        )
                        {
                            column.Item()
                                .PaddingLeft(
                                    10
                                )
                                .Text(
                                    $"• {action}"
                                );
                        }
                    }


                    // =========================================
                    // INVESTIGATOR REVIEW
                    // =========================================

                    column.Item()
                        .Text(
                            "Investigator Review"
                        )
                        .SemiBold();


                    if (
                        finding.InvestigatorReview
                        == null
                    )
                    {
                        column.Item()
                            .Text(
                                "Not reviewed."
                            );
                    }
                    else
                    {
                        column.Item()
                            .Text(
                                $"Decision: " +
                                $"{finding.InvestigatorReview.Decision}"
                            );


                        if (
                            !string.IsNullOrWhiteSpace(
                                finding
                                    .InvestigatorReview
                                    .Notes
                            )
                        )
                        {
                            column.Item()
                                .Text(
                                    $"Notes: " +
                                    $"{finding.InvestigatorReview.Notes}"
                                );
                        }


                        if (
                            !string.IsNullOrWhiteSpace(
                                finding
                                    .InvestigatorReview
                                    .ReviewTimestamp
                            )
                        )
                        {
                            column.Item()
                                .Text(
                                    $"Reviewed: " +
                                    $"{finding.InvestigatorReview.ReviewTimestamp}"
                                )
                                .FontSize(
                                    8
                                )
                                .FontColor(
                                    Colors.Grey.Darken1
                                );
                        }
                    }
                }
            );
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
}