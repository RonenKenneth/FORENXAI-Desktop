using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;

using FORENXAI.Desktop.Models;
using FORENXAI.Desktop.Services;

namespace FORENXAI.Desktop.Views;


public partial class InvestigationView : UserControl
{
    private readonly BackendApiService backendApi =
        new BackendApiService();

    private readonly ObservableCollection<InvestigationRow> rows =
        new();

    private readonly string caseId;

    private readonly ICollectionView rowsView;


    public InvestigationView(
        string caseId)
    {
        InitializeComponent();

        this.caseId =
            caseId;

        rowsView =
            CollectionViewSource
                .GetDefaultView(
                    rows
                );

        rowsView.Filter =
            FilterInvestigationRow;

        rowsView.SortDescriptions.Clear();

        rowsView.SortDescriptions.Add(
            new SortDescription(
                nameof(InvestigationRow.ReviewPriorityRank),
                ListSortDirection.Ascending
            )
        );

        rowsView.SortDescriptions.Add(
            new SortDescription(
                nameof(InvestigationRow.PriorityRank),
                ListSortDirection.Ascending
            )
        );

        rowsView.SortDescriptions.Add(
            new SortDescription(
                nameof(InvestigationRow.Confidence),
                ListSortDirection.Descending
            )
        );

        InvestigationGrid.ItemsSource =
            rowsView;

        CaseText.Text =
            $"Case: {caseId}";

        Loaded += InvestigationView_Loaded;
    }


    private async void InvestigationView_Loaded(
        object sender,
        RoutedEventArgs e)
    {
        await LoadInvestigationAsync();
    }


    private async Task LoadInvestigationAsync()
    {
        try
        {
            StatusText.Text =
                "Loading threat findings and investigator reviews...";

            ReviewSelectedButton.IsEnabled =
                false;

            rows.Clear();


            AnalysisDocument? analysis =
                await backendApi
                    .GetAnalysisAsync(
                        caseId
                    );


            InvestigatorReviewsResponse? reviews =
                await backendApi
                    .GetInvestigatorReviewsAsync(
                        caseId
                    );


            if (
                analysis?
                .MlAnalysis?
                .Findings
                == null
            )
            {
                throw new InvalidOperationException(
                    "No machine-learning findings are available for this case."
                );
            }


            foreach (
                MlFinding finding
                in analysis.MlAnalysis.Findings
            )
            {
                if (!finding.IsThreat)
                {
                    continue;
                }


                InvestigatorReviewData? review =
                    reviews?
                    .Reviews?
                    .FirstOrDefault(
                        item =>
                            item.FlowIndex
                            == finding.FlowIndex
                    );


                rows.Add(
                    new InvestigationRow
                    {
                        FlowIndex =
                            finding.FlowIndex,

                        PredictedClass =
                            finding.PredictedClass,

                        Confidence =
                            finding.Confidence,

                        // Final verdict and what backs it, worded as in
                        // the Dashboard's Supporting Evidence column.
                        Verdict =
                            finding.Verdict ?? "",

                        VerdictSource =
                            finding.VerdictSource ?? "",

                        EvidenceDisplay =
                            string.IsNullOrEmpty(finding.VerdictSource)
                                ? "--"
                                : $"{finding.Verdict} · {DashboardView.EvidenceSource(DashboardView.EvidenceSourceOf(finding))}",

                        SourceDisplay =
                            BuildEndpoint(
                                finding.Metadata?.SrcIp,
                                finding.Metadata?.SrcPort
                                ?? 0
                            ),

                        DestinationDisplay =
                            BuildEndpoint(
                                finding.Metadata?.DstIp,
                                finding.Metadata?.DstPort
                                ?? 0
                            ),

                        ReviewDecision =
                            review?.Decision
                            ?? "Unreviewed"
                    }
                );
            }


            PopulateClassFilter();

            rowsView.Refresh();

            UpdateCounts();


            StatusText.Text =
                rows.Count == 0
                ? "No threat findings are available for investigation."
                : "Use the filters to narrow the investigation or select a threat flow.";
        }
        catch (Exception error)
        {
            rows.Clear();

            rowsView.Refresh();

            ThreatCountText.Text =
                "0 threat flows";

            ReviewCountText.Text =
                "0 reviewed";

            VisibleCountText.Text =
                "0 shown";

            SummaryTotalText.Text =
                "0";

            SummaryUnreviewedText.Text =
                "0";

            SummaryConfirmedText.Text =
                "0";

            SummaryRejectedText.Text =
                "0";

            SummaryInconclusiveText.Text =
                "0";

            ReviewProgressBar.Value =
                0;

            ReviewProgressText.Text =
                "0% reviewed";

            StatusText.Text =
                "Could not load the investigation workspace.";

            MessageBox.Show(
                "FORENXAI could not load this investigation.\n\n" +
                error.Message,
                "Investigation Workspace",
                MessageBoxButton.OK,
                MessageBoxImage.Error
            );
        }
    }


    // =========================================================
    // FILTERING
    // =========================================================

    private bool FilterInvestigationRow(
        object item)
    {
        if (
            item
            is not InvestigationRow row
        )
        {
            return false;
        }


        string searchText =
            SearchTextBox?
                .Text?
                .Trim()
                .ToLowerInvariant()
            ?? string.Empty;


        if (
            !string.IsNullOrWhiteSpace(
                searchText
            )
        )
        {
            bool searchMatch =
                row.FlowIndex
                    .ToString()
                    .Contains(
                        searchText,
                        StringComparison.OrdinalIgnoreCase
                    )
                ||
                row.PredictedClass
                    .Contains(
                        searchText,
                        StringComparison.OrdinalIgnoreCase
                    )
                ||
                row.EvidenceDisplay
                    .Contains(
                        searchText,
                        StringComparison.OrdinalIgnoreCase
                    )
                ||
                row.SourceDisplay
                    .Contains(
                        searchText,
                        StringComparison.OrdinalIgnoreCase
                    )
                ||
                row.DestinationDisplay
                    .Contains(
                        searchText,
                        StringComparison.OrdinalIgnoreCase
                    );


            if (!searchMatch)
            {
                return false;
            }
        }


        string reviewFilter =
            GetSelectedComboText(
                ReviewFilterComboBox
            );


        if (
            !string.IsNullOrWhiteSpace(
                reviewFilter
            )
            &&
            !string.Equals(
                reviewFilter,
                "All Reviews",
                StringComparison.OrdinalIgnoreCase
            )
            &&
            !string.Equals(
                row.ReviewDecision,
                reviewFilter,
                StringComparison.OrdinalIgnoreCase
            )
        )
        {
            return false;
        }


        string classFilter =
            GetSelectedComboText(
                ClassFilterComboBox
            );


        if (
            !string.IsNullOrWhiteSpace(
                classFilter
            )
            &&
            !string.Equals(
                classFilter,
                "All Classes",
                StringComparison.OrdinalIgnoreCase
            )
            &&
            !string.Equals(
                row.PredictedClass,
                classFilter,
                StringComparison.OrdinalIgnoreCase
            )
        )
        {
            return false;
        }


        string priorityFilter =
            GetSelectedComboText(
                PriorityFilterComboBox
            );


        if (
            !string.IsNullOrWhiteSpace(
                priorityFilter
            )
            &&
            !string.Equals(
                priorityFilter,
                "All Priorities",
                StringComparison.OrdinalIgnoreCase
            )
            &&
            !string.Equals(
                row.Priority,
                priorityFilter,
                StringComparison.OrdinalIgnoreCase
            )
        )
        {
            return false;
        }


        return true;
    }


    private void PopulateClassFilter()
    {
        string previousSelection =
            GetSelectedComboText(
                ClassFilterComboBox
            );


        ClassFilterComboBox.Items.Clear();

        ClassFilterComboBox.Items.Add(
            "All Classes"
        );


        foreach (
            string predictedClass
            in rows
                .Select(
                    row =>
                        row.PredictedClass
                )
                .Where(
                    value =>
                        !string.IsNullOrWhiteSpace(
                            value
                        )
                )
                .Distinct(
                    StringComparer.OrdinalIgnoreCase
                )
                .OrderBy(
                    value =>
                        value,
                    StringComparer.OrdinalIgnoreCase
                )
        )
        {
            ClassFilterComboBox.Items.Add(
                predictedClass
            );
        }


        if (
            !string.IsNullOrWhiteSpace(
                previousSelection
            )
            &&
            ClassFilterComboBox.Items
                .Cast<object>()
                .Any(
                    item =>
                        string.Equals(
                            item?.ToString(),
                            previousSelection,
                            StringComparison.OrdinalIgnoreCase
                        )
                )
        )
        {
            ClassFilterComboBox.SelectedItem =
                ClassFilterComboBox.Items
                    .Cast<object>()
                    .First(
                        item =>
                            string.Equals(
                                item?.ToString(),
                                previousSelection,
                                StringComparison.OrdinalIgnoreCase
                            )
                    );
        }
        else
        {
            ClassFilterComboBox.SelectedIndex =
                0;
        }
    }


    private static string GetSelectedComboText(
        ComboBox comboBox)
    {
        if (
            comboBox.SelectedItem
            is ComboBoxItem item
        )
        {
            return item.Content?
                .ToString()
                ?? string.Empty;
        }


        return comboBox.SelectedItem?
            .ToString()
            ?? string.Empty;
    }


    private void SearchTextBox_TextChanged(
        object sender,
        TextChangedEventArgs e)
    {
        RefreshFilters();
    }


    private void FilterComboBox_SelectionChanged(
        object sender,
        SelectionChangedEventArgs e)
    {
        RefreshFilters();
    }


    private void ClearFiltersButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        SearchTextBox.Text =
            string.Empty;

        ReviewFilterComboBox.SelectedIndex =
            0;

        if (
            ClassFilterComboBox.Items.Count
            > 0
        )
        {
            ClassFilterComboBox.SelectedIndex =
                0;
        }

        PriorityFilterComboBox.SelectedIndex =
            0;

        RefreshFilters();
    }


    private void RefreshFilters()
    {
        if (rowsView == null)
        {
            return;
        }


        InvestigationGrid.SelectedItem =
            null;

        ReviewSelectedButton.IsEnabled =
            false;

        rowsView.Refresh();

        UpdateCounts();
    }


    private void UpdateCounts()
    {
        int totalCount =
            rows.Count;


        int unreviewedCount =
            rows.Count(
                row =>
                    string.Equals(
                        row.ReviewDecision,
                        "Unreviewed",
                        StringComparison.OrdinalIgnoreCase
                    )
            );


        int confirmedCount =
            rows.Count(
                row =>
                    string.Equals(
                        row.ReviewDecision,
                        "Confirmed",
                        StringComparison.OrdinalIgnoreCase
                    )
            );


        int rejectedCount =
            rows.Count(
                row =>
                    string.Equals(
                        row.ReviewDecision,
                        "Rejected",
                        StringComparison.OrdinalIgnoreCase
                    )
            );


        int inconclusiveCount =
            rows.Count(
                row =>
                    string.Equals(
                        row.ReviewDecision,
                        "Inconclusive",
                        StringComparison.OrdinalIgnoreCase
                    )
            );


        int reviewedCount =
            confirmedCount
            + rejectedCount
            + inconclusiveCount;


        int visibleCount =
            rowsView
                .Cast<object>()
                .Count();


        double completionPercentage =
            totalCount == 0
            ? 0
            : (
                (double)reviewedCount
                / totalCount
            ) * 100.0;


        ThreatCountText.Text =
            $"{totalCount} threat flow(s)";

        ReviewCountText.Text =
            $"{reviewedCount} reviewed";

        VisibleCountText.Text =
            $"{visibleCount} shown";


        SummaryTotalText.Text =
            totalCount.ToString();

        SummaryUnreviewedText.Text =
            unreviewedCount.ToString();

        SummaryConfirmedText.Text =
            confirmedCount.ToString();

        SummaryRejectedText.Text =
            rejectedCount.ToString();

        SummaryInconclusiveText.Text =
            inconclusiveCount.ToString();


        ReviewProgressBar.Value =
            completionPercentage;

        ReviewProgressText.Text =
            completionPercentage > 0 && completionPercentage < 0.1
                ? "<0.1% reviewed"
                : $"{completionPercentage:F1}% reviewed";


        if (
            rows.Count > 0
            && visibleCount == 0
        )
        {
            StatusText.Text =
                "No threat flows match the current filters.";
        }
        else if (
            rows.Count > 0
        )
        {
            StatusText.Text =
                "Select a threat flow to continue the investigation.";
        }
    }


    // =========================================================
    // PRIORITIZED WORKFLOW
    // =========================================================

    private void NextUnreviewedButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        InvestigationRow? nextRow =
            rowsView
                .Cast<object>()
                .OfType<InvestigationRow>()
                .FirstOrDefault(
                    row =>
                        string.Equals(
                            row.ReviewDecision,
                            "Unreviewed",
                            StringComparison.OrdinalIgnoreCase
                        )
                );


        if (nextRow == null)
        {
            MessageBox.Show(
                "No unreviewed threat flows are available in the current filtered view.",
                "Investigation Workspace",
                MessageBoxButton.OK,
                MessageBoxImage.Information
            );

            return;
        }


        InvestigationGrid.SelectedItem =
            nextRow;

        InvestigationGrid.ScrollIntoView(
            nextRow
        );

        StatusText.Text =
            $"Selected next unreviewed flow: {nextRow.FlowIndex}.";
    }


    // =========================================================
    // FLOW SELECTION
    // =========================================================

    private void InvestigationGrid_SelectionChanged(
        object sender,
        SelectionChangedEventArgs e)
    {
        ReviewSelectedButton.IsEnabled =
            InvestigationGrid.SelectedItem
            is InvestigationRow;
    }


    private void InvestigationGrid_MouseDoubleClick(
        object sender,
        MouseButtonEventArgs e)
    {
        OpenSelectedFlow();
    }


    private void ReviewSelectedButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        OpenSelectedFlow();
    }


    private void OpenSelectedFlow()
    {
        if (
            InvestigationGrid.SelectedItem
            is not InvestigationRow selected
        )
        {
            return;
        }


        MainWindow? mainWindow =
            Window.GetWindow(this)
            as MainWindow;


        if (mainWindow == null)
        {
            return;
        }


        mainWindow.ShowXai(
            caseId,
            selected.FlowIndex
        );
    }


    private static string BuildEndpoint(
        string? ip,
        int port)
    {
        string safeIp =
            string.IsNullOrWhiteSpace(ip)
            ? "--"
            : ip;


        if (port <= 0)
        {
            return safeIp;
        }


        return $"{safeIp}:{port}";
    }


    private sealed class InvestigationRow
    {
        public int FlowIndex { get; set; }

        public string PredictedClass { get; set; }
            = string.Empty;

        public double Confidence { get; set; }

        public string SourceDisplay { get; set; }
            = string.Empty;

        public string DestinationDisplay { get; set; }
            = string.Empty;

        public string ReviewDecision { get; set; }
            = "Unreviewed";

        public string Verdict { get; set; }
            = string.Empty;

        public string VerdictSource { get; set; }
            = string.Empty;

        public string EvidenceDisplay { get; set; }
            = string.Empty;

        public string ConfidenceDisplay =>
            $"{Confidence:P2}";

        // Priority follows the evidence behind the verdict, not the ML
        // score alone: a rule backing the verdict (source "rule" or
        // "agree") counts as strong evidence; a flow the model abstained
        // on with no rule is Uncertain and needs the analyst.
        public string Priority =>
            VerdictSource == "abstain"
                ? "Uncertain"
                : VerdictSource is "rule" or "agree" || Confidence >= 0.90
                    ? "High"
                    : Confidence >= 0.70
                        ? "Medium"
                        : "Low";

        public int PriorityRank =>
            Priority switch
            {
                "High" => 1,
                "Uncertain" => 2,
                "Medium" => 3,
                _ => 4
            };

        public int ReviewPriorityRank =>
            string.Equals(
                ReviewDecision,
                "Unreviewed",
                StringComparison.OrdinalIgnoreCase
            )
            ? 0
            : 1;
    }
}
