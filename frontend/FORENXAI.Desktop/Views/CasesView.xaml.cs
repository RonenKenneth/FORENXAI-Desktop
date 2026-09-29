using System;
using System.Collections.Generic;
using System.Linq;
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

            ScheduleDeletionButton.IsEnabled =
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

            ClearAllButton.IsEnabled =
                response.TotalCases > 0;

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

        ScheduleDeletionButton.IsEnabled =
            selectedCase != null;


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


    // Deletes every stored case except the one open in the app. Bulk and
    // irreversible, so the investigator has to type DELETE; a case being
    // analysed is refused by the backend and reported.
    private async void ClearAll_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (CasesGrid.ItemsSource is not IEnumerable<CaseSummary> all)
        {
            return;
        }

        string current = (Window.GetWindow(this) as MainWindow)?.GetCurrentCase() ?? string.Empty;
        List<CaseSummary> targets = all
            .Where(c => !string.Equals(c.CaseId, current, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (targets.Count == 0)
        {
            StatusText.Text = "The only stored case is open. Open another case before deleting it.";
            return;
        }

        int reviewed = targets.Count(c => c.HasReviews);
        string message =
            $"Permanently delete {targets.Count} case(s)?\n\n"
            + "This removes each case's evidence copy, flow records, analysis, Suricata logs"
            + (reviewed > 0 ? $" and investigator reviews ({reviewed} case(s) have reviews)" : " and reviews")
            + ". Export any report you need first. This cannot be undone."
            + (current.Length > 0 && targets.Count < all.Count() ? $"\n\nThe open case {current} is kept." : string.Empty)
            + "\n\nType DELETE to confirm:";

        if (!ConfirmByTyping(message, "DELETE"))
        {
            StatusText.Text = "Clear all cancelled.";
            return;
        }

        ClearAllButton.IsEnabled = false;
        var failed = new List<string>();
        for (int i = 0; i < targets.Count; i++)
        {
            StatusText.Text = $"Deleting {i + 1} of {targets.Count}: {targets[i].CaseId}...";
            try
            {
                await _backendApiService.DeleteCaseAsync(targets[i].CaseId);
            }
            catch (Exception error)
            {
                failed.Add($"{targets[i].CaseId}: {error.Message.Split('\n')[0]}");
            }
        }

        await LoadCasesAsync();
        StatusText.Text = $"Deleted {targets.Count - failed.Count} of {targets.Count} case(s).";
        if (failed.Count > 0)
        {
            MessageBox.Show("These cases could not be deleted:\n\n" + string.Join("\n", failed),
                "Clear All", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }


    // A small modal that returns true only when the exact word is typed.
    private bool ConfirmByTyping(string message, string word)
    {
        var input = new TextBox { Margin = new Thickness(0, 10, 0, 0), Padding = new Thickness(6, 4, 6, 4) };
        var delete = new Button
        {
            Content = "Delete All", MinWidth = 96, Height = 32, IsEnabled = false,
            Margin = new Thickness(8, 0, 0, 0), Foreground = System.Windows.Media.Brushes.White,
            Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x7F, 0x1D, 0x1D)),
        };
        var cancel = new Button { Content = "Cancel", MinWidth = 96, Height = 32, IsCancel = true, Margin = new Thickness(8, 0, 0, 0) };
        input.TextChanged += (_, _) => delete.IsEnabled = input.Text == word;

        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 14, 0, 0) };
        buttons.Children.Add(cancel);
        buttons.Children.Add(delete);
        var panel = new StackPanel { Margin = new Thickness(20) };
        panel.Children.Add(new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap });
        panel.Children.Add(input);
        panel.Children.Add(buttons);

        var dialog = new Window
        {
            Title = "Clear All Cases", Owner = Window.GetWindow(this), Width = 480,
            SizeToContent = SizeToContent.Height, ResizeMode = ResizeMode.NoResize,
            WindowStartupLocation = WindowStartupLocation.CenterOwner, Content = panel,
        };
        delete.Click += (_, _) => dialog.DialogResult = true;
        dialog.Loaded += (_, _) => input.Focus();
        return dialog.ShowDialog() == true;
    }


    private async void ScheduleDeletion_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (CasesGrid.SelectedItem is not CaseSummary selectedCase)
        {
            return;
        }

        var dialog = new RetentionDialog(
            Window.GetWindow(this), selectedCase.CaseId, selectedCase.DeleteAfterTime);

        if (dialog.ShowDialog() != true || dialog.Result == null)
        {
            return;
        }

        try
        {
            DateTimeOffset? deleteAfter =
                dialog.Result == RetentionDialog.Outcome.Scheduled ? dialog.DeleteAfter : null;

            await _backendApiService.SetCaseRetentionAsync(selectedCase.CaseId, deleteAfter);
            await LoadCasesAsync();

            StatusText.Text = deleteAfter is DateTimeOffset when
                ? $"Case {selectedCase.CaseId} will be deleted automatically on {when.LocalDateTime:yyyy-MM-dd HH:mm}."
                : $"Scheduled deletion of {selectedCase.CaseId} removed; the case is kept until deleted.";
        }
        catch (Exception error)
        {
            MessageBox.Show(
                "FORENXAI could not schedule the deletion of this case.\n\n" + error.Message,
                "Schedule Deletion", MessageBoxButton.OK, MessageBoxImage.Error);
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


            // Load through the same cached call the Dashboard uses, so
            // opening a case downloads its analysis once, not twice.
            AnalysisDocument? analysis =
                await _backendApiService
                    .GetAnalysisAsync(
                        selectedCase.CaseId
                    );


            if (
                analysis?.MlAnalysis == null
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
                selectedCase.CaseId
            );


            mainWindow.ShowDashboard(
                selectedCase.CaseId
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
