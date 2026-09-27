using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

using FORENXAI.Desktop.Models;
using FORENXAI.Desktop.Services;

namespace FORENXAI.Desktop.Views;


public partial class CasesView : UserControl
{
    private readonly BackendApiService _backendApiService =
        new BackendApiService();


    public CasesView()
    {
        InitializeComponent();

        Loaded += CasesView_Loaded;
    }


    private async void CasesView_Loaded(
        object sender,
        RoutedEventArgs e)
    {
        await LoadCasesAsync();
    }


    private async Task LoadCasesAsync()
    {
        try
        {
            StatusText.Text =
                "Loading existing investigations...";

            OpenCaseButton.IsEnabled =
                false;

            DeleteCaseButton.IsEnabled =
                false;

            CaseListResponse? response =
                await _backendApiService
                    .GetCasesAsync();


            if (response == null)
            {
                throw new Exception(
                    "The backend returned no case data."
                );
            }


            CasesGrid.ItemsSource =
                response.Cases;

            CaseCountText.Text =
                $"{response.TotalCases} case(s)";

            StatusText.Text =
                response.TotalCases == 0
                ? "No FORENXAI cases were found."
                : "Select an analyzed case to open it.";
        }
        catch (Exception error)
        {
            CasesGrid.ItemsSource =
                null;

            CaseCountText.Text =
                string.Empty;

            StatusText.Text =
                "Could not load cases.";

            MessageBox.Show(
                "FORENXAI could not load the case list.\n\n" +
                error.Message,
                "Case Management",
                MessageBoxButton.OK,
                MessageBoxImage.Error
            );
        }
    }


    private async void Refresh_Click(
        object sender,
        RoutedEventArgs e)
    {
        await LoadCasesAsync();
    }


    private void CasesGrid_SelectionChanged(
        object sender,
        SelectionChangedEventArgs e)
    {
        CaseSummary? selectedCase =
            CasesGrid.SelectedItem
            as CaseSummary;


        OpenCaseButton.IsEnabled =
            selectedCase != null
            && selectedCase.AnalysisExists
            && string.Equals(
                selectedCase.Status,
                "Analyzed",
                StringComparison.OrdinalIgnoreCase
            );


        MainWindow? mainWindow =
            Window.GetWindow(this)
            as MainWindow;


        bool isCurrentCase =
            selectedCase != null
            && mainWindow != null
            && string.Equals(
                mainWindow.GetCurrentCase(),
                selectedCase.CaseId,
                StringComparison.OrdinalIgnoreCase
            );


        DeleteCaseButton.IsEnabled =
            selectedCase != null
            && !isCurrentCase;


        if (selectedCase == null)
        {
            StatusText.Text =
                "Select an analyzed case to open it.";

            return;
        }


        if (isCurrentCase)
        {
            StatusText.Text =
                $"Case {selectedCase.CaseId} is currently open. " +
                "Open another case before deleting it.";

            return;
        }


        if (
            !selectedCase.AnalysisExists
            || !string.Equals(
                selectedCase.Status,
                "Analyzed",
                StringComparison.OrdinalIgnoreCase
            )
        )
        {
            StatusText.Text =
                $"Case {selectedCase.CaseId} is " +
                $"{selectedCase.Status} and cannot be opened yet.";

            return;
        }


        StatusText.Text =
            $"Ready to open {selectedCase.CaseId}.";
    }


    private async void CasesGrid_MouseDoubleClick(
        object sender,
        MouseButtonEventArgs e)
    {
        await OpenSelectedCaseAsync();
    }


    private async void DeleteCase_Click(
        object sender,
        RoutedEventArgs e)
    {
        await DeleteSelectedCaseAsync();
    }


    private async Task DeleteSelectedCaseAsync()
    {
        CaseSummary? selectedCase =
            CasesGrid.SelectedItem
            as CaseSummary;


        if (selectedCase == null)
        {
            return;
        }


        MainWindow? mainWindow =
            Window.GetWindow(this)
            as MainWindow;


        if (
            mainWindow != null
            && string.Equals(
                mainWindow.GetCurrentCase(),
                selectedCase.CaseId,
                StringComparison.OrdinalIgnoreCase
            )
        )
        {
            MessageBox.Show(
                "This case is currently open.\n\n" +
                "Open another case before deleting it.",
                "Delete Case",
                MessageBoxButton.OK,
                MessageBoxImage.Information
            );

            return;
        }


        MessageBoxResult confirmation =
            MessageBox.Show(
                "Delete this FORENXAI case permanently?\n\n" +
                $"Case ID: {selectedCase.CaseId}\n" +
                $"Evidence: {selectedCase.EvidenceFile ?? "Unknown"}\n\n" +
                "This deletes the stored evidence, analysis, " +
                "reviews, and case files. This action cannot be undone.",
                "Confirm Case Deletion",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning,
                MessageBoxResult.No
            );


        if (confirmation != MessageBoxResult.Yes)
        {
            StatusText.Text =
                "Case deletion cancelled.";

            return;
        }


        try
        {
            OpenCaseButton.IsEnabled =
                false;

            DeleteCaseButton.IsEnabled =
                false;

            StatusText.Text =
                $"Deleting {selectedCase.CaseId}...";


            DeleteCaseResponse? response =
                await _backendApiService
                    .DeleteCaseAsync(
                        selectedCase.CaseId
                    );


            if (
                response == null
                || !string.Equals(
                    response.Status,
                    "deleted",
                    StringComparison.OrdinalIgnoreCase
                )
            )
            {
                throw new Exception(
                    "The backend did not confirm case deletion."
                );
            }


            await LoadCasesAsync();


            StatusText.Text =
                $"Case {selectedCase.CaseId} was deleted successfully.";
        }
        catch (Exception error)
        {
            StatusText.Text =
                "Could not delete the selected case.";

            MessageBox.Show(
                "FORENXAI could not delete this case.\n\n" +
                error.Message,
                "Delete Case",
                MessageBoxButton.OK,
                MessageBoxImage.Error
            );
        }
    }


    private async void OpenCase_Click(
        object sender,
        RoutedEventArgs e)
    {
        await OpenSelectedCaseAsync();
    }


    private async Task OpenSelectedCaseAsync()
    {
        CaseSummary? selectedCase =
            CasesGrid.SelectedItem
            as CaseSummary;


        if (selectedCase == null)
        {
            return;
        }


        if (
            !selectedCase.AnalysisExists
            || !string.Equals(
                selectedCase.Status,
                "Analyzed",
                StringComparison.OrdinalIgnoreCase
            )
        )
        {
            MessageBox.Show(
                "This case does not contain a completed analysis.",
                "Case Management",
                MessageBoxButton.OK,
                MessageBoxImage.Information
            );

            return;
        }


        try
        {
            OpenCaseButton.IsEnabled =
                false;

            StatusText.Text =
                $"Opening {selectedCase.CaseId}...";


            CaseDetailsResponse? details =
                await _backendApiService
                    .GetCaseDetailsAsync(
                        selectedCase.CaseId
                    );


            if (
                details == null
                || details.Analysis == null
            )
            {
                throw new Exception(
                    "The selected case does not contain " +
                    "a valid stored analysis."
                );
            }


            MainWindow? mainWindow =
                Window.GetWindow(this)
                as MainWindow;


            if (mainWindow == null)
            {
                throw new Exception(
                    "FORENXAI could not access the main window."
                );
            }


            mainWindow.SetCurrentCase(
                details.CaseId
            );


            mainWindow.ShowDashboard(
                details.CaseId
            );
        }
        catch (Exception error)
        {
            StatusText.Text =
                "Could not open the selected case.";

            MessageBox.Show(
                "FORENXAI could not open this case.\n\n" +
                error.Message,
                "Case Management",
                MessageBoxButton.OK,
                MessageBoxImage.Error
            );
        }
        finally
        {
            CaseSummary? currentSelection =
                CasesGrid.SelectedItem
                as CaseSummary;


            OpenCaseButton.IsEnabled =
                currentSelection != null
                && currentSelection.AnalysisExists
                && string.Equals(
                    currentSelection.Status,
                    "Analyzed",
                    StringComparison.OrdinalIgnoreCase
                );


            MainWindow? mainWindow =
                Window.GetWindow(this)
                as MainWindow;


            DeleteCaseButton.IsEnabled =
                currentSelection != null
                && (
                    mainWindow == null
                    || !string.Equals(
                        mainWindow.GetCurrentCase(),
                        currentSelection.CaseId,
                        StringComparison.OrdinalIgnoreCase
                    )
                );
        }
    }
}
