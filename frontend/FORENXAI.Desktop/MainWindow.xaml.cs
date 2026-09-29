using System.Threading.Tasks;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

using FORENXAI.Desktop.Services;
using FORENXAI.Desktop.Views;

namespace FORENXAI.Desktop;


public partial class MainWindow : Window
{
    // =========================================================
    // CURRENT CASE
    // =========================================================

    private string CurrentCaseId =
        string.Empty;
    private AnalysisResponse? CurrentAnalysis;


    // =========================================================
    // NAVIGATION COLORS
    // =========================================================

    private readonly Brush NavigationNormalBackground =
        Brushes.Transparent;


    private readonly Brush NavigationNormalForeground =
        new SolidColorBrush(
            Color.FromRgb(
                203,
                213,
                225
            )
        );


    private readonly Brush NavigationSelectedBackground =
        new SolidColorBrush(
            Color.FromRgb(
                30,
                64,
                175
            )
        );


    private readonly Brush NavigationSelectedForeground =
        Brushes.White;


    // =========================================================
    // CONSTRUCTOR
    // =========================================================

    public MainWindow()
    {
        InitializeComponent();


        // Default page.
        ShowEvidence();
    }


    // =========================================================
    // CURRENT CASE
    // =========================================================

    public void SetCurrentCase(
        string caseId)
    {
        if (
            string.IsNullOrWhiteSpace(
                caseId
            )
        )
        {
            return;
        }


        CurrentCaseId =
            caseId.Trim();
    }


    public string GetCurrentCase()
    {
        return CurrentCaseId;
    }


    // =========================================================
    // EXIT: WARNING AND SESSION CASES
    // =========================================================

    private bool exitConfirmed;
    private bool exitPromptOpen;

    // Every exit asks first. Cases created in this session hold a copy of
    // the evidence, flow records and reviews, which can include personal
    // data (IP addresses, hostnames, payload excerpts). The investigator
    // decides whether they stay: deleting protects privacy (data
    // minimisation), keeping preserves the forensic record.
    protected override async void OnClosing(System.ComponentModel.CancelEventArgs e)
    {
        if (exitConfirmed)
        {
            base.OnClosing(e);
            return;
        }

        e.Cancel = true;

        // A second close request (taskbar, Alt+F4) while the prompt is
        // open or cases are being deleted is ignored.
        if (exitPromptOpen)
        {
            return;
        }

        exitPromptOpen = true;
        try
        {
            if (await ConfirmExitAsync())
            {
                exitConfirmed = true;
                // Close() cannot run while this Closing event is in progress.
                _ = Dispatcher.BeginInvoke(Close);
            }
        }
        finally
        {
            exitPromptOpen = false;
        }
    }

    // "kept until deleted" or "deleted automatically on <date>", from the
    // case's retention.json.
    private static string RetentionLabel(string caseId)
    {
        try
        {
            string file = Path.Combine(EvidenceView.GetCasesDirectory(), caseId, "retention.json");
            using var document = System.Text.Json.JsonDocument.Parse(File.ReadAllText(file));
            if (DateTimeOffset.TryParse(document.RootElement.GetProperty("delete_after").GetString(), out var when))
            {
                return $"deleted automatically on {when.LocalDateTime:yyyy-MM-dd HH:mm}";
            }
        }
        catch (Exception)
        {
            // no schedule
        }
        return "kept until deleted";
    }

    private async Task<bool> ConfirmExitAsync()
    {
        List<string> sessionCases = App.SessionCaseIds
            .Where(id => Directory.Exists(Path.Combine(EvidenceView.GetCasesDirectory(), id)))
            .OrderBy(id => id)
            .ToList();

        // Step 1: always confirm. No stays in FORENXAI.
        if (MessageBox.Show(this, "Exit FORENXAI?", "Exit FORENXAI",
                MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes)
        {
            return false;
        }

        if (sessionCases.Count == 0)
        {
            return true;
        }

        // Step 2: what happens to this session's cases.
        MessageBoxResult choice = MessageBox.Show(this,
            $"{sessionCases.Count} case(s) created in this session are stored on this computer:\n"
            + string.Join("\n", sessionCases.Take(8).Select(id => "  • " + id + " — " + RetentionLabel(id)))
            + (sessionCases.Count > 8 ? $"\n  • … {sessionCases.Count - 8} more" : string.Empty)
            + "\n\nEach holds a copy of the evidence, its flow records, the analysis and the reviews,"
            + " which can contain personal data (IP addresses, hostnames, payload excerpts)."
            + " Export any report you need first (Reports tab).\n\n"
            + "Yes: delete these cases now and exit\n"
            + "No: keep them and exit (a scheduled deletion still applies; set one in the Cases tab)\n"
            + "Cancel: stay in FORENXAI",
            "Delete this session's cases?", MessageBoxButton.YesNoCancel, MessageBoxImage.Warning,
            MessageBoxResult.Cancel);

        if (choice == MessageBoxResult.No)
        {
            return true;
        }

        if (choice != MessageBoxResult.Yes)
        {
            return false;
        }

        IsEnabled = false;
        var api = new BackendApiService();
        var failed = new List<string>();
        foreach (string caseId in sessionCases)
        {
            try
            {
                await api.DeleteCaseAsync(caseId);
            }
            catch (Exception ex)
            {
                failed.Add($"{caseId}: {ex.Message.Split('\n')[0]}");
            }
        }
        IsEnabled = true;

        return failed.Count == 0
            || MessageBox.Show(this,
                "These cases could not be deleted:\n" + string.Join("\n", failed)
                + $"\n\nThey remain in {EvidenceView.GetCasesDirectory()}.\nExit anyway?",
                "Exit FORENXAI", MessageBoxButton.YesNo, MessageBoxImage.Error) == MessageBoxResult.Yes;
    }

    public void SetCurrentAnalysis(AnalysisResponse response)
    {
        CurrentAnalysis = response;
        SetCurrentCase(response.CaseId);
    }



    // =========================================================
    // SIDEBAR HIGHLIGHT
    // =========================================================

    private void SetActiveNavigation(
        Button activeButton)
    {
        Button[] navigationButtons =
        {
            EvidenceButton,
            DashboardButton,
            XaiButton,
            InvestigationButton,
            CasesButton,
            ReportsButton
        };


        // Reset every navigation button.
        foreach (
            Button button
            in navigationButtons
        )
        {
            button.Background =
                NavigationNormalBackground;


            button.Foreground =
                NavigationNormalForeground;


            button.FontWeight =
                FontWeights.Normal;
        }


        // Highlight the current page.
        activeButton.Background =
            NavigationSelectedBackground;


        activeButton.Foreground =
            NavigationSelectedForeground;


        activeButton.FontWeight =
            FontWeights.SemiBold;
    }


    // =========================================================
    // EVIDENCE
    // =========================================================

    private void Evidence_Click(
        object sender,
        RoutedEventArgs e)
    {
        ShowEvidence();
    }


    private void ShowEvidence()
    {
        MainContent.Content =
            new EvidenceView();


        SetActiveNavigation(
            EvidenceButton
        );
    }


    // =========================================================
    // DASHBOARD BUTTON
    // =========================================================

    private void Dashboard_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (
            !string.IsNullOrWhiteSpace(
                CurrentCaseId
            )
        )
        {
            ShowDashboard(
                CurrentCaseId
            );


            return;
        }


        MessageBox.Show(
            "No analyzed case is currently selected.\n\n" +
            "Please analyze evidence first.",
            "FORENXAI",
            MessageBoxButton.OK,
            MessageBoxImage.Information
        );
    }


    // =========================================================
    // SHOW DASHBOARD
    // =========================================================

    public void ShowDashboard(
        string caseId)
    {
        if (
            string.IsNullOrWhiteSpace(
                caseId
            )
        )
        {
            return;
        }


        CurrentCaseId =
            caseId.Trim();


        MainContent.Content =
            new DashboardView(
                CurrentCaseId
            );


        SetActiveNavigation(
            DashboardButton
        );
    }


    // =========================================================
    // XAI BUTTON
    // =========================================================

    private void Xai_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (
            !string.IsNullOrWhiteSpace(
                CurrentCaseId
            )
        )
        {
            ShowXai(
                CurrentCaseId
            );


            return;
        }


        MessageBox.Show(
            "No analyzed case is currently selected.\n\n" +
            "Please analyze evidence first.",
            "FORENXAI",
            MessageBoxButton.OK,
            MessageBoxImage.Information
        );
    }


    // =========================================================
    // SHOW XAI
    // =========================================================

    public void ShowXai(
        string caseId)
    {
        if (
            string.IsNullOrWhiteSpace(
                caseId
            )
        )
        {
            return;
        }


        CurrentCaseId =
            caseId.Trim();


        MainContent.Content =
            new XaiView(
                CurrentCaseId
            );


        SetActiveNavigation(
            XaiButton
        );
    }


    // =========================================================
    // SHOW XAI FOR SPECIFIC FLOW
    // =========================================================

    public void ShowXai(
        string caseId,
        int flowIndex)
    {
        if (
            string.IsNullOrWhiteSpace(
                caseId
            )
        )
        {
            return;
        }


        if (
            flowIndex < 0
        )
        {
            return;
        }


        CurrentCaseId =
            caseId.Trim();


        MainContent.Content =
            new XaiView(
                CurrentCaseId,
                flowIndex
            );


        SetActiveNavigation(
            XaiButton
        );
    }


    // =========================================================
    // INVESTIGATION WORKSPACE
    // =========================================================

    private void Investigation_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (
            !string.IsNullOrWhiteSpace(
                CurrentCaseId
            )
        )
        {
            ShowInvestigation(
                CurrentCaseId
            );

            return;
        }


        MessageBox.Show(
            "No analyzed case is currently selected.\n\n" +
            "Please analyze or open a case first.",
            "FORENXAI",
            MessageBoxButton.OK,
            MessageBoxImage.Information
        );
    }


    public void ShowInvestigation(
        string caseId)
    {
        if (
            string.IsNullOrWhiteSpace(
                caseId
            )
        )
        {
            return;
        }


        CurrentCaseId =
            caseId.Trim();


        MainContent.Content =
            new InvestigationView(
                CurrentCaseId
            );


        SetActiveNavigation(
            InvestigationButton
        );
    }


    // =========================================================
    // CASE MANAGEMENT
    // =========================================================

    private void Cases_Click(
        object sender,
        RoutedEventArgs e)
    {
        ShowCases();
    }


    public void ShowCases()
    {
        MainContent.Content =
            new CasesView();


        SetActiveNavigation(
            CasesButton
        );
    }


    // =========================================================
    // REPORTS BUTTON
    // =========================================================

    private void Reports_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (
            !string.IsNullOrWhiteSpace(
                CurrentCaseId
            )
        )
        {
            ShowReports(
                CurrentCaseId
            );


            return;
        }


        ShowReports();
    }


    // =========================================================
    // SHOW REPORTS
    // =========================================================

    public void ShowReports()
    {
        MainContent.Content =
            new ReportsView();


        SetActiveNavigation(
            ReportsButton
        );
    }


    public void ShowReports(
        string caseId)
    {
        if (
            string.IsNullOrWhiteSpace(
                caseId
            )
        )
        {
            ShowReports();


            return;
        }


        CurrentCaseId =
            caseId.Trim();


        MainContent.Content =
            new ReportsView(
                CurrentCaseId
            );


        SetActiveNavigation(
            ReportsButton
        );
    }
}
