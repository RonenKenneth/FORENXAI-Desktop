using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

using FORENXAI.Desktop.Views;

namespace FORENXAI.Desktop;


public partial class MainWindow : Window
{
    // =========================================================
    // CURRENT CASE
    // =========================================================

    private string CurrentCaseId =
        string.Empty;


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