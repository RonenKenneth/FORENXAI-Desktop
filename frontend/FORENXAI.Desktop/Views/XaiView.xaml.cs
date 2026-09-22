using System.Windows.Data;
using System.ComponentModel;
using System.Collections.Generic;
using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

using FORENXAI.Desktop.Models;
using FORENXAI.Desktop.Services;

namespace FORENXAI.Desktop.Views;

public partial class XaiView : UserControl
{
    private readonly BackendApiService backendApi;

    private AnalysisDocument? currentAnalysis;

    private readonly ObservableCollection<ThreatRow> threats;
    private readonly ObservableCollection<ShapRow> shapRows;

    private InvestigatorReviewsResponse? currentReviews;

    private int? requestedFlowIndex;

    private int narrationRequestVersion;


    public XaiView()
    {
        InitializeComponent();

        backendApi = new BackendApiService();

        threats =
            new ObservableCollection<ThreatRow>();

        shapRows =
            new ObservableCollection<ShapRow>();

        ThreatList.ItemsSource =
            threats;

        ShapDataGrid.ItemsSource =
            shapRows;

        ClearRecommendationPanel();
        ClearReviewPanel();
        ClearNarrationPanel();
    }


    public XaiView(
        string caseId)
        : this()
    {
        CaseIdTextBox.Text =
            caseId;

        Loaded += async (_, _) =>
        {
            await LoadCaseAsync(
                caseId
            );
        };
    }


    public XaiView(
        string caseId,
        int flowIndex)
        : this()
    {
        CaseIdTextBox.Text =
            caseId;

        requestedFlowIndex =
            flowIndex;

        Loaded += async (_, _) =>
        {
            await LoadCaseAsync(
                caseId
            );

            SelectThreatFlow(
                flowIndex
            );
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

        requestedFlowIndex =
            null;

        await LoadCaseAsync(
            caseId
        );
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
                "Loading analysis...";

            threats.Clear();
            shapRows.Clear();

            currentAnalysis =
                null;

            currentReviews =
                null;

            ClearRecommendationPanel();
            ClearReviewPanel();
            ClearNarrationPanel();


            // -------------------------------------------------
            // Load main analysis
            // -------------------------------------------------

            currentAnalysis =
                await backendApi
                    .GetAnalysisAsync(
                        caseId
                    );


            if (
                currentAnalysis
                == null
            )
            {
                throw new InvalidOperationException(
                    "The backend returned no analysis data."
                );
            }


            // -------------------------------------------------
            // Load saved investigator reviews
            // -------------------------------------------------

            currentReviews =
                await backendApi
                    .GetInvestigatorReviewsAsync(
                        caseId
                    );


            CaseIdTextBox.Text =
                caseId;


            LoadThreats();


            StatusText.Text =
                $"Case loaded: {caseId}";
        }
        catch (Exception ex)
        {
            currentAnalysis =
                null;

            currentReviews =
                null;

            threats.Clear();
            shapRows.Clear();

            ThreatList.SelectedItem =
                null;

            ShapDataGrid.SelectedItem =
                null;

            ThreatCountText.Text =
                "0 threat flows";

            SelectedClassText.Text =
                "Select a detected threat";

            SelectedConfidenceText.Text =
                "--";

            ExplanationText.Text =
                "Select a threat flow to view its SHAP explanation.";

            ClearRecommendationPanel();
            ClearReviewPanel();
            ClearNarrationPanel();

            StatusText.Text =
                "Could not load case.";

            MessageBox.Show(
                "Could not load XAI analysis.\n\n" +
                ex.Message,
                "FORENXAI XAI Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error
            );
        }
    }


    // =========================================================
    // LOAD THREAT LIST
    // =========================================================

    private void LoadThreats()
    {
        threats.Clear();
        shapRows.Clear();

        ThreatList.SelectedItem =
            null;

        ShapDataGrid.SelectedItem =
            null;

        SelectedClassText.Text =
            "Select a detected threat";

        SelectedConfidenceText.Text =
            "--";

        ExplanationText.Text =
            "Select a threat flow to view its SHAP explanation.";

        ClearRecommendationPanel();
        ClearReviewPanel();
        ClearNarrationPanel();


        if (
            currentAnalysis?
            .MlAnalysis?
            .Findings
            == null
        )
        {
            ThreatCountText.Text =
                "0 threat flows";

            return;
        }


        foreach (
            MlFinding finding
            in currentAnalysis
                .MlAnalysis
                .Findings
        )
        {
            if (
                !finding.IsThreat
            )
            {
                continue;
            }


            threats.Add(
                new ThreatRow
                {
                    FlowIndex =
                        finding.FlowIndex,

                    PredictedClass =
                        finding.PredictedClass,

                    Confidence =
                        finding.Confidence,

                    TopDriver =
                        DescribeTopDriver(
                            finding.FlowIndex
                        )
                }
            );
        }


        ThreatCountText.Text =
            $"{threats.Count} threat flow" +
            (
                threats.Count == 1
                    ? ""
                    : "s"
            );


        if (
            requestedFlowIndex.HasValue
        )
        {
            return;
        }


        ApplyThreatFilter();


        if (
            threats.Count > 0
        )
        {
            ThreatList.SelectedIndex =
                0;
        }
    }


    // =========================================================
    // THREAT SELECTION
    // =========================================================

    private void ThreatList_SelectionChanged(
        object sender,
        SelectionChangedEventArgs e)
    {
        if (
            ThreatList.SelectedItem
            is not ThreatRow selected
        )
        {
            return;
        }


        ShapDataGrid.SelectedItem =
            null;


        LoadShapExplanation(
            selected.FlowIndex
        );


        LoadRecommendation(
            selected.FlowIndex
        );


        LoadSavedReview(
            selected.FlowIndex
        );


        _ = LoadNarrationAsync(
            selected.FlowIndex
        );
    }


    // =========================================================
    // SELECT SPECIFIC FLOW
    // =========================================================

    private void SelectThreatFlow(
        int flowIndex)
    {
        ThreatRow? target =
            threats.FirstOrDefault(
                item =>
                    item.FlowIndex
                    == flowIndex
            );


        if (
            target == null
        )
        {
            ThreatList.SelectedItem =
                null;

            ShapDataGrid.SelectedItem =
                null;

            SelectedClassText.Text =
                "Threat flow not found";

            SelectedConfidenceText.Text =
                "--";

            ExplanationText.Text =
                $"Flow {flowIndex} could not be found " +
                "in the detected threat list.";

            ClearRecommendationPanel();
            ClearReviewPanel();
            ClearNarrationPanel();

            requestedFlowIndex =
                null;

            return;
        }


        ThreatList.SelectedItem =
            target;


        ThreatList.ScrollIntoView(
            target
        );


        ShapDataGrid.SelectedItem =
            null;


        LoadShapExplanation(
            flowIndex
        );


        LoadRecommendation(
            flowIndex
        );


        LoadSavedReview(
            flowIndex
        );


        requestedFlowIndex =
            null;
    }


    // =========================================================
    // SHAP
    // =========================================================

    private void LoadShapExplanation(
        int flowIndex)
    {
        shapRows.Clear();

        ShapDataGrid.SelectedItem =
            null;


        if (
            currentAnalysis?
            .ShapAnalysis?
            .Explanations
            == null
        )
        {
            SelectedClassText.Text =
                "Explanation unavailable";

            SelectedConfidenceText.Text =
                "--";

            ExplanationText.Text =
                "No SHAP analysis is available for this case.";

            return;
        }


        ShapExplanation? explanation =
            currentAnalysis
                .ShapAnalysis
                .Explanations
                .FirstOrDefault(
                    item =>
                        item.FlowIndex
                        == flowIndex
                );


        if (
            explanation == null
        )
        {
            SelectedClassText.Text =
                "Explanation unavailable";

            SelectedConfidenceText.Text =
                "--";

            ExplanationText.Text =
                "No SHAP explanation was found for this flow.";

            return;
        }


        SelectedClassText.Text =
            explanation
                .PredictedClass;


        SelectedConfidenceText.Text =
            $"{explanation.Confidence:P2}";


        ExplanationText.Text =
            BuildExplanationText(
                explanation
            );


        if (
            explanation.Contributors
            == null
        )
        {
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
    }


    // =========================================================
    // PHASE 18A
    // LOCAL QWEN NARRATION
    // =========================================================

    private async Task LoadNarrationAsync(
        int flowIndex)
    {
        int requestVersion =
            ++narrationRequestVersion;


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
            GenAiStatusText.Text =
                "Unavailable";

            GenAiExplanationText.Text =
                "No Case ID is currently loaded.";

            return;
        }


        GenAiStatusText.Text =
            "Generating...";

        GenAiExplanationText.Text =
            "Generating a grounded explanation with the local Qwen model...";


        try
        {
            NarrationResponse? response =
                await backendApi
                    .GetNarrationAsync(
                        caseId,
                        flowIndex
                    );


            // If the user selected another flow while Qwen was
            // generating this result, ignore the stale response.
            if (
                requestVersion
                != narrationRequestVersion
            )
            {
                return;
            }


            if (
                response?.Narration
                == null
            )
            {
                throw new InvalidOperationException(
                    "The backend returned no narration data."
                );
            }


            if (
                string.IsNullOrWhiteSpace(
                    response.Narration.Text
                )
            )
            {
                throw new InvalidOperationException(
                    "The narration response contained no explanation text."
                );
            }


            GenAiExplanationText.Text =
                response.Narration.Text;


            if (
                response.Narration.FallbackUsed
            )
            {
                GenAiStatusText.Text =
                    "Deterministic fallback";
            }
            else if (
                response.Narration.Available
            )
            {
                GenAiStatusText.Text =
                    "Qwen local";
            }
            else
            {
                GenAiStatusText.Text =
                    "Fallback";
            }
        }
        catch (Exception ex)
        {
            if (
                requestVersion
                != narrationRequestVersion
            )
            {
                return;
            }


            GenAiStatusText.Text =
                "Unavailable";

            GenAiExplanationText.Text =
                "Could not generate the local AI explanation.\n\n" +
                ex.Message;
        }
    }


    private void ClearNarrationPanel()
    {
        ++narrationRequestVersion;

        GenAiStatusText.Text =
            "Not generated";

        GenAiExplanationText.Text =
            "Select a detected threat to generate a local AI explanation.";
    }


    // =========================================================
    // RECOMMENDATIONS
    // =========================================================

    private void LoadRecommendation(
        int flowIndex)
    {
        RecommendationActionsList.ItemsSource =
            null;


        if (
            currentAnalysis?
            .MlAnalysis?
            .Findings
            == null
        )
        {
            RecommendationSummaryText.Text =
                "Recommendation data is unavailable.";

            return;
        }


        MlFinding? finding =
            currentAnalysis
                .MlAnalysis
                .Findings
                .FirstOrDefault(
                    item =>
                        item.FlowIndex
                        == flowIndex
                );


        if (
            finding == null
        )
        {
            RecommendationSummaryText.Text =
                "No machine-learning finding was found for this flow.";

            return;
        }


        RecommendationData? recommendation =
            finding.Recommendation;


        if (
            recommendation == null
        )
        {
            RecommendationSummaryText.Text =
                "No recommendation is available for this threat.";

            return;
        }


        if (
            string.IsNullOrWhiteSpace(
                recommendation.Summary
            )
        )
        {
            RecommendationSummaryText.Text =
                "No recommendation summary is available.";
        }
        else
        {
            RecommendationSummaryText.Text =
                recommendation.Summary;
        }


        ShowRecommendationProvenance(
            recommendation
        );


        if (
            recommendation.Actions
            == null
            ||
            recommendation.Actions.Count
            == 0
        )
        {
            RecommendationActionsList.ItemsSource =
                null;

            return;
        }


        // Prefer the cited form: the same sentence with its in-text
        // citation appended. Falls back to the plain text for a bundle
        // produced before citations were added.
        RecommendationActionsList.ItemsSource =
            recommendation.ActionsCited != null
            && recommendation.ActionsCited.Count
                == recommendation.Actions.Count
                ? recommendation.ActionsCited
                : recommendation.Actions;
    }


    private void ClearRecommendationPanel()
    {
        RecommendationSummaryText.Text =
            "Select a detected threat to view recommended actions.";

        RecommendationActionsList.ItemsSource =
            null;

        RecommendationVerificationText.Text =
            string.Empty;

        RecommendationSourcesText.Text =
            string.Empty;
    }


    // =========================================================
    // RECOMMENDATION PROVENANCE
    //
    // Every action the backend returns has already been traced
    // to one retrieved passage; an action that could not be
    // traced was dropped before it reached here. This shows the
    // analyst which documents were used, so a recommendation can
    // be checked rather than taken on trust.
    // =========================================================

    private void ShowRecommendationProvenance(
        RecommendationData recommendation)
    {
        int actionCount =
            recommendation.Actions?.Count
            ?? 0;

        string generator =
            recommendation.Generator
            == "qwen2.5-3b-q4.gguf"
                ? "written by the local model from the retrieved passages"
                : recommendation.Generator == "extraction"
                    ? "quoted directly from the retrieved playbook"
                    : "fixed text";

        int rejected =
            recommendation.RejectedUngrounded?.Count
            ?? 0;

        string verification =
            actionCount == 0
                ? "No actions were returned."
                : $"{actionCount} action(s), {generator}. "
                  + "Each one was matched back to a source before display.";

        if (rejected > 0)
        {
            verification +=
                $" {rejected} generated statement(s) could not be matched "
                + "to a source and were discarded.";
        }

        MeasuredContext? measured =
            recommendation.Measured;

        if (measured != null
            && measured.LowConfidenceClass
            && measured.ClassF1 != null)
        {
            verification +=
                $" Classifier test F1 for this class is "
                + $"{measured.ClassF1:F4}; treat the class itself as "
                + "uncertain.";
        }

        if (measured != null
            && measured.Alternatives.Count > 0)
        {
            var names = new List<string>();

            foreach (AlternativeClass alternative in measured.Alternatives)
            {
                names.Add(
                    alternative.Probability != null
                        ? $"{alternative.ClassName} "
                          + $"({alternative.Probability:P1})"
                        : alternative.ClassName
                );
            }

            verification +=
                " This flow may instead be "
                + string.Join(", ", names)
                + ". The guidance below was written to hold either way, "
                + "and that class's profile was retrieved alongside.";
        }

        if (actionCount > 0
            && !recommendation.StandardsGrounded)
        {
            verification +=
                " No action here rests on a published standard: all of "
                + "them trace to the internal corpus, whose response "
                + "playbooks are marked PLACEHOLDER.";
        }

        RecommendationVerificationText.Text =
            verification;


        var lines = new List<string>();

        if (recommendation.ActionEvidence != null
            && recommendation.ActionEvidence.Count > 0)
        {
            lines.Add("SOURCE FOR EACH ACTION");

            for (int i = 0;
                 i < recommendation.ActionEvidence.Count;
                 i++)
            {
                ActionEvidence evidence =
                    recommendation.ActionEvidence[i];

                lines.Add(
                    $"  {i + 1}. {evidence.Source}"
                    + $"  [{evidence.Match}]"
                );
            }
        }

        if (recommendation.Controls != null
            && recommendation.Controls.Count > 0)
        {
            lines.Add(
                "NIST SP 800-53 controls: "
                + string.Join(", ", recommendation.Controls)
            );
        }

        if (recommendation.Mitre != null
            && recommendation.Mitre.Count > 0)
        {
            lines.Add(
                "MITRE ATT&CK: "
                + string.Join(", ", recommendation.Mitre)
                + "  (mappings need review)"
            );
        }

        if (measured != null
            && measured.Notes.Count > 0)
        {
            lines.Add("MEASURED FOR THIS PREDICTION");

            foreach (string note in measured.Notes)
            {
                lines.Add("  " + note);
            }
        }

        if (recommendation.References != null
            && recommendation.References.Count > 0)
        {
            lines.Add("REFERENCES (ACM Reference Format)");

            foreach (ReferenceEntry reference in recommendation.References)
            {
                lines.Add(
                    $"  [{reference.Number}] {reference.Acm}"
                );
            }
        }

        RecommendationSourcesText.Text =
            string.Join("\n", lines);
    }


    // =========================================================
    // PHASE 16
    // LOAD SAVED REVIEW
    // =========================================================

    private void LoadSavedReview(
        int flowIndex)
    {
        ConfirmedRadioButton.IsChecked =
            false;

        RejectedRadioButton.IsChecked =
            false;

        InconclusiveRadioButton.IsChecked =
            false;

        InvestigatorNotesTextBox.Text =
            string.Empty;


        if (
            currentReviews?
            .Reviews
            == null
        )
        {
            InconclusiveRadioButton.IsChecked =
                true;

            ReviewStatusText.Text =
                $"No review saved for Flow {flowIndex}.";

            return;
        }


        InvestigatorReviewData? savedReview =
            currentReviews
                .Reviews
                .FirstOrDefault(
                    item =>
                        item.FlowIndex
                        == flowIndex
                );


        if (
            savedReview == null
        )
        {
            InconclusiveRadioButton.IsChecked =
                true;

            ReviewStatusText.Text =
                $"No review saved for Flow {flowIndex}.";

            return;
        }


        switch (
            savedReview.Decision
        )
        {
            case "Confirmed":

                ConfirmedRadioButton.IsChecked =
                    true;

                break;


            case "Rejected":

                RejectedRadioButton.IsChecked =
                    true;

                break;


            case "Inconclusive":

                InconclusiveRadioButton.IsChecked =
                    true;

                break;


            default:

                InconclusiveRadioButton.IsChecked =
                    true;

                break;
        }


        InvestigatorNotesTextBox.Text =
            savedReview.Notes
            ?? string.Empty;


        ReviewStatusText.Text =
            $"Saved review: {savedReview.Decision}";
    }


    // =========================================================
    // SAVE REVIEW
    // =========================================================

    private async void SaveReviewButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        try
        {
            if (
                ThreatList.SelectedItem
                is not ThreatRow selected
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
                    "No Case ID is currently loaded.",
                    "FORENXAI",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information
                );

                return;
            }


            string decision =
                GetSelectedDecision();


            if (
                string.IsNullOrWhiteSpace(
                    decision
                )
            )
            {
                MessageBox.Show(
                    "Please select an investigator decision.",
                    "FORENXAI",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information
                );

                return;
            }


            string notes =
                InvestigatorNotesTextBox
                    .Text
                    .Trim();


            SaveReviewButton.IsEnabled =
                false;

            SaveReviewButton.Content =
                "SAVING...";


            ReviewStatusText.Text =
                $"Saving review for Flow " +
                $"{selected.FlowIndex}...";


            InvestigatorReviewResponse? response =
                await backendApi
                    .SaveInvestigatorReviewAsync(
                        caseId,
                        selected.FlowIndex,
                        decision,
                        notes
                    );


            if (
                response?.Review
                == null
            )
            {
                throw new InvalidOperationException(
                    "The backend did not return the saved review."
                );
            }


            // -------------------------------------------------
            // Refresh reviews from backend after saving
            // -------------------------------------------------

            currentReviews =
                await backendApi
                    .GetInvestigatorReviewsAsync(
                        caseId
                    );


            LoadSavedReview(
                selected.FlowIndex
            );


            MessageBox.Show(
                $"Investigator review saved successfully.\n\n" +
                $"Flow: {response.Review.FlowIndex}\n" +
                $"Class: {response.Review.PredictedClass}\n" +
                $"Decision: {response.Review.Decision}",
                "FORENXAI",
                MessageBoxButton.OK,
                MessageBoxImage.Information
            );
        }
        catch (Exception ex)
        {
            ReviewStatusText.Text =
                "Could not save investigator review.";


            MessageBox.Show(
                "Could not save investigator review.\n\n" +
                ex.Message,
                "FORENXAI Review Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error
            );
        }
        finally
        {
            SaveReviewButton.IsEnabled =
                true;

            SaveReviewButton.Content =
                "SAVE REVIEW";
        }
    }


    // =========================================================
    // SELECTED DECISION
    // =========================================================

    private string GetSelectedDecision()
    {
        if (
            ConfirmedRadioButton.IsChecked
            == true
        )
        {
            return "Confirmed";
        }


        if (
            RejectedRadioButton.IsChecked
            == true
        )
        {
            return "Rejected";
        }


        if (
            InconclusiveRadioButton.IsChecked
            == true
        )
        {
            return "Inconclusive";
        }


        return string.Empty;
    }


    // =========================================================
    // CLEAR REVIEW PANEL
    // =========================================================

    private void ClearReviewPanel()
    {
        ConfirmedRadioButton.IsChecked =
            false;

        RejectedRadioButton.IsChecked =
            false;

        InconclusiveRadioButton.IsChecked =
            true;

        InvestigatorNotesTextBox.Text =
            string.Empty;

        ReviewStatusText.Text =
            "No review saved for the selected flow.";
    }


    // =========================================================
    // HUMAN-READABLE SHAP SUMMARY
    // =========================================================

    private static string BuildExplanationText(
        ShapExplanation explanation)
    {
        if (
            explanation.Contributors
            == null
            ||
            explanation.Contributors.Count
            == 0
        )
        {
            return
                "The model classified this flow as " +
                $"{explanation.PredictedClass} with " +
                $"{explanation.Confidence:P2} confidence, " +
                "but no SHAP contributors were available.";
        }


        ShapContributor? strongest =
            explanation
                .Contributors
                .OrderByDescending(
                    item =>
                        Math.Abs(
                            item.ShapValue
                        )
                )
                .FirstOrDefault();


        if (
            strongest == null
        )
        {
            return
                $"The model classified this flow as " +
                $"{explanation.PredictedClass} with " +
                $"{explanation.Confidence:P2} confidence.";
        }


        string directionText =
            strongest.Direction switch
            {
                "supports_prediction" =>
                    "supported",

                "opposes_prediction" =>
                    "opposed",

                "neutral" =>
                    "had a neutral effect on",

                _ =>
                    "influenced"
            };


        return
            $"The model classified this network flow as " +
            $"{explanation.PredictedClass} with " +
            $"{explanation.Confidence:P2} confidence. " +
            $"The strongest SHAP contributor was " +
            $"\"{strongest.Feature}\". " +
            $"Its observed value {directionText} " +
            $"the predicted class. " +
            $"The table below lists the most influential " +
            $"features for this prediction.";
    }


    // =========================================================
    // CARD SUPPORT
    // =========================================================

    /// <summary>
    /// The single feature TreeSHAP attributes most of this flow's
    /// decision to, phrased for a card. Returns an empty string when
    /// SHAP has not run, rather than inventing a driver.
    /// </summary>
    private string DescribeTopDriver(
        int flowIndex)
    {
        List<ShapContributor>? contributors =
            currentAnalysis?
                .ShapAnalysis?
                .TopFeaturesPerFlow?
                .GetValueOrDefault(
                    flowIndex.ToString()
                );

        if (contributors == null
            || contributors.Count == 0)
        {
            return string.Empty;
        }

        ShapContributor top =
            contributors[0];

        string direction =
            top.ShapValue >= 0
                ? "toward"
                : "away from";

        return
            $"{top.Feature}  {top.ShapValue:+0.000;-0.000}  "
            + $"({direction} this class)";
    }


    /// <summary>
    /// Filter the card list by class name or flow number. Substring
    /// matching, case-insensitive: a capture can hold hundreds of
    /// detections and scrolling to find one is slower than typing it.
    /// </summary>
    private void ThreatFilterBox_TextChanged(
        object sender,
        TextChangedEventArgs e)
    {
        ApplyThreatFilter();
    }


    private void ApplyThreatFilter()
    {
        if (ThreatList == null
            || ThreatEmptyText == null)
        {
            return;
        }

        string query =
            (ThreatFilterBox?.Text ?? string.Empty)
            .Trim();

        if (ThreatFilterPlaceholder != null)
        {
            ThreatFilterPlaceholder.Visibility =
                query.Length == 0
                    ? Visibility.Visible
                    : Visibility.Collapsed;
        }

        ICollectionView view =
            CollectionViewSource.GetDefaultView(
                ThreatList.ItemsSource
            );

        if (view == null)
        {
            return;
        }

        if (query.Length == 0)
        {
            view.Filter = null;
        }
        else
        {
            view.Filter = item =>
            {
                if (item is not ThreatRow row)
                {
                    return false;
                }

                return
                    row.PredictedClass.Contains(
                        query,
                        StringComparison.OrdinalIgnoreCase
                    )
                    || row.FlowIndex
                        .ToString()
                        .Contains(query);
            };
        }

        view.Refresh();

        int shown = 0;

        foreach (object _ in view)
        {
            shown++;
        }

        ThreatEmptyText.Text =
            shown == 0
                ? $"No detection matches \"{query}\"."
                : string.Empty;

        ThreatList.Visibility =
            shown == 0
                ? Visibility.Collapsed
                : Visibility.Visible;

        if (shown > 0
            && ThreatList.SelectedItem == null)
        {
            ThreatList.SelectedIndex = 0;
        }
    }


    // =========================================================
    // DISPLAY MODELS
    // =========================================================

    private sealed class ThreatRow
    {
        public int FlowIndex { get; set; }


        public string PredictedClass { get; set; }
            = string.Empty;


        public double Confidence { get; set; }


        public string ConfidenceDisplay =>
            $"{Confidence:P2}";


        public string FlowLabel =>
            $"flow {FlowIndex}";


        /// <summary>
        /// The feature TreeSHAP says moved this decision most. Shown on
        /// the card so a list can be triaged without opening every one.
        /// </summary>
        public string TopDriver { get; set; }
            = string.Empty;


        /// <summary>
        /// Width of the filled part of the confidence bar, in a fixed
        /// 120px track. Bound rather than computed in XAML so the card
        /// template stays declarative.
        /// </summary>
        public double ConfidenceBarWidth =>
            Math.Max(
                2.0,
                Math.Min(1.0, Confidence) * 120.0
            );


        /// <summary>
        /// Colour is a second channel only -- the class name carries the
        /// same information in words, so the card is still readable
        /// without it.
        /// </summary>
        public string SeverityBrush =>
            PredictedClass switch
            {
                "Benign" => "#475569",

                "DoS" or "DDoS" or "Slowloris" =>
                    "#F97316",

                "Exploitation" or "BufferOverflow" or "C2Beaconing"
                    or "Exfiltration" or "MITM" =>
                    "#EF4444",

                _ => "#EAB308",
            };
    }


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