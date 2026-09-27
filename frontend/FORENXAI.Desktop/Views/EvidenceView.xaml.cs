using Microsoft.Win32;

using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;

using FORENXAI.Desktop.Services;

namespace FORENXAI.Desktop.Views;


public partial class EvidenceView : UserControl
{
    private string? selectedFilePath;

    private string? caseDirectory;

    private string? caseId;


    private readonly BackendApiService backendApi;

    private Window? analysisProgressWindow;
    private Window? analysisOwnerWindow;
    private ProgressBar? analysisProgressBar;
    private TextBlock? analysisElapsedText;
    private TextBlock? analysisStatusText;
    private Button? analysisViewResultsButton;
    private readonly Stopwatch analysisStopwatch = new();
    private readonly DispatcherTimer analysisTimer = new();


    // =========================================================
    // CONSTRUCTOR
    // =========================================================

    public EvidenceView()
    {
        InitializeComponent();
        SupportedFormatsText.Text =
            $"PCAP or PCAPng  •  up to {MaxEvidenceMegabytes} MB";


        backendApi =
            new BackendApiService();
    }


    // =========================================================
    // BROWSE FOR PCAP / PCAPNG
    // =========================================================

    // ponytail: size cap chosen, not measured; the analysis keeps every packet
    // in memory and analysis.json grows with the flow count (88 MB for a
    // 1 MB, 2,016-flow capture). Raise it after profiling a larger capture.
    private const int MaxEvidenceMegabytes = 100;
    private const long MaxEvidenceBytes = MaxEvidenceMegabytes * 1024L * 1024L;

    private void BrowsePcap_Click(
        object sender,
        RoutedEventArgs e)
    {
        // The progress pop-up can be closed while the backend still runs.
        if (analysisTimer.IsEnabled)
        {
            MessageBox.Show(
                "An analysis is still running. Wait for it to finish before loading new evidence.",
                "FORENXAI", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        OpenFileDialog dialog =
            new OpenFileDialog
            {
                Title =
                    "Select Network Evidence",

                Filter =
                    "PCAP Files (*.pcap;*.pcapng)|*.pcap;*.pcapng",

                Multiselect =
                    false
            };


        bool? result =
            dialog.ShowDialog();


        if (
            result != true
        )
        {
            return;
        }


        long size = new FileInfo(dialog.FileName).Length;
        if (size > MaxEvidenceBytes)
        {
            MessageBox.Show(
                $"This capture is {size / (1024.0 * 1024.0):N1} MB. FORENXAI accepts captures up to {MaxEvidenceMegabytes} MB.\n\n" +
                "Split it into smaller files (for example with Wireshark's editcap -c) and analyze them separately.",
                "Evidence Too Large", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        selectedFilePath =
            dialog.FileName;


        ProcessEvidence();
    }


    // =========================================================
    // PROCESS EVIDENCE
    // =========================================================

    private void ProcessEvidence()
    {
        if (
            string.IsNullOrEmpty(
                selectedFilePath
            )
        )
        {
            return;
        }


        try
        {
            FileInfo fileInfo =
                new FileInfo(
                    selectedFilePath
                );


            // =================================================
            // VALIDATE EXTENSION
            // =================================================

            string extension =
                fileInfo
                    .Extension
                    .ToLowerInvariant();


            if (
                extension != ".pcap"
                &&
                extension != ".pcapng"
            )
            {
                MessageBox.Show(
                    "Please select a valid PCAP or PCAPNG file.",
                    "Invalid Evidence",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning
                );


                return;
            }


            // =================================================
            // GENERATE CASE ID
            // =================================================

            caseId =
                GenerateCaseId();


            // =================================================
            // GET FORENXAI CASE STORAGE DIRECTORY
            // =================================================

            string casesDirectory =
                GetCasesDirectory();


            // =================================================
            // CREATE CASE DIRECTORY
            // =================================================

            caseDirectory =
                Path.Combine(
                    casesDirectory,
                    caseId
                );


            string evidenceDirectory =
                Path.Combine(
                    caseDirectory,
                    "evidence"
                );


            Directory.CreateDirectory(
                evidenceDirectory
            );


            // =================================================
            // COPY ORIGINAL EVIDENCE
            // =================================================

            string destinationPath =
                Path.Combine(
                    evidenceDirectory,
                    fileInfo.Name
                );


            File.Copy(
                selectedFilePath,
                destinationPath,
                true
            );


            /*
             * From this point forward, FORENXAI works
             * with the evidence copy stored inside the
             * case directory.
             */
            selectedFilePath =
                destinationPath;


            // =================================================
            // HASH EVIDENCE
            // =================================================

            string sha256 =
                CalculateSha256(
                    destinationPath
                );


            // =================================================
            // UPDATE UI
            // =================================================

            CaseIdText.Text =
                caseId;


            FileNameText.Text =
                fileInfo.Name;


            FileSizeText.Text =
                FormatFileSize(
                    fileInfo.Length
                );


            HashText.Text =
                sha256;


            StatusText.Text =
                "Evidence acquired";


            StatusText.Foreground =
                new SolidColorBrush(
                    Colors.LightGreen
                );


            CaseLocationText.Text =
                $"Evidence stored in:\n" +
                $"{evidenceDirectory}";


            StartAnalysisButton.IsEnabled =
                true;

            StartAnalysisButton.Visibility =
                Visibility.Visible;


            // =================================================
            // COMPLETE
            // =================================================

            MessageBox.Show(
                "The network evidence was successfully acquired.\n\n" +
                $"Case ID: {caseId}\n" +
                $"SHA-256: {sha256}",
                "Evidence Acquired",
                MessageBoxButton.OK,
                MessageBoxImage.Information
            );
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                "Could not acquire the evidence.\n\n" +
                ex.Message,
                "Evidence Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error
            );
        }
    }


    // =========================================================
    // GENERATE CASE ID
    // =========================================================

    private static string GenerateCaseId()
    {
        return
            $"FX-{DateTime.Now:yyyyMMdd-HHmmss}";
    }


    // =========================================================
    // CALCULATE SHA-256
    // =========================================================

    private static string CalculateSha256(
        string filePath)
    {
        using SHA256 sha256 =
            SHA256.Create();


        using FileStream stream =
            File.OpenRead(
                filePath
            );


        byte[] hash =
            sha256.ComputeHash(
                stream
            );


        return
            Convert.ToHexString(
                hash
            );
    }


    // =========================================================
    // FORMAT FILE SIZE
    // =========================================================

    private static string FormatFileSize(
        long bytes)
    {
        if (
            bytes < 1024
        )
        {
            return
                $"{bytes} B";
        }


        if (
            bytes < 1024 * 1024
        )
        {
            return
                $"{bytes / 1024.0:F2} KB";
        }


        if (
            bytes
            <
            1024L
            * 1024L
            * 1024L
        )
        {
            return
                $"{bytes / (1024.0 * 1024.0):F2} MB";
        }


        return
            $"{bytes / (1024.0 * 1024.0 * 1024.0):F2} GB";
    }


    // =========================================================
    // GET FORENXAI CASES DIRECTORY
    // =========================================================

    private static string GetCasesDirectory()  
    {
        /*
         * If FORENXAI_DATA_DIR is configured,
         * use the same override as the Python backend.
         */
        string? configuredDataDirectory =
            Environment.GetEnvironmentVariable(
                "FORENXAI_DATA_DIR"
            );


        string dataDirectory;


        if (
            !string.IsNullOrWhiteSpace(
                configuredDataDirectory
            )
        )
        {
            dataDirectory =
                Path.GetFullPath(
                    configuredDataDirectory
                );
        }
        else
        {
            /*
             * Production/default location:
             *
             * %LOCALAPPDATA%\FORENXAI
             */
            string localAppData =
                Environment.GetFolderPath(
                    Environment.SpecialFolder.LocalApplicationData
                );


            dataDirectory =
                Path.Combine(
                    localAppData,
                    "FORENXAI"
                );
        }


        string casesDirectory =
            Path.Combine(
                dataDirectory,
                "cases"
            );


        Directory.CreateDirectory(
            casesDirectory
        );


        return casesDirectory;
    }


    // =========================================================
    // START FORENSIC ANALYSIS
    // =========================================================

    private void ShowAnalysisProgressDialog()
    {
        analysisOwnerWindow = Window.GetWindow(this);
        if (analysisOwnerWindow != null)
        {
            // Keep the user focused on the running analysis. The window is
            // re-enabled when the analysis finishes or fails.
            analysisOwnerWindow.IsEnabled = false;
        }

        analysisProgressWindow = new Window
        {
            Title = "FORENXAI Analysis",
            Width = 520,
            Height = 260,
            // Minimize (no maximize); a taskbar button brings it back.
            ResizeMode = ResizeMode.CanMinimize,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Owner = analysisOwnerWindow,
            Background = new SolidColorBrush(Color.FromRgb(15, 23, 42)),
            ShowInTaskbar = true,
            WindowStyle = WindowStyle.SingleBorderWindow,
            ShowActivated = true,
            Topmost = true
        };

        StackPanel panel = new StackPanel { Margin = new Thickness(28) };
        panel.Children.Add(new TextBlock
        {
            Text = "FORENXAI FORENSIC ANALYSIS",
            Foreground = Brushes.White,
            FontSize = 18,
            FontWeight = FontWeights.Bold,
            Margin = new Thickness(0, 0, 0, 16)
        });

        analysisStatusText = new TextBlock
        {
            Text = "Analyzing evidence...",
            Foreground = new SolidColorBrush(Color.FromRgb(148, 163, 184)),
            FontSize = 13,
            Margin = new Thickness(0, 0, 0, 12)
        };
        panel.Children.Add(analysisStatusText);

        analysisProgressBar = new ProgressBar
        {
            Height = 18,
            IsIndeterminate = true,
            Foreground = new SolidColorBrush(Color.FromRgb(37, 99, 235)),
            Background = new SolidColorBrush(Color.FromRgb(30, 41, 59)),
            Margin = new Thickness(0, 0, 0, 12)
        };
        panel.Children.Add(analysisProgressBar);

        analysisElapsedText = new TextBlock
        {
            Text = "Elapsed time: 00:00",
            Foreground = new SolidColorBrush(Color.FromRgb(148, 163, 184)),
            FontSize = 12,
            Margin = new Thickness(0, 0, 0, 18)
        };
        panel.Children.Add(analysisElapsedText);

        analysisViewResultsButton = new Button
        {
            Content = "View Results",
            IsEnabled = false,
            Visibility = Visibility.Collapsed,
            Height = 38,
            Background = new SolidColorBrush(Color.FromRgb(22, 163, 74)),
            Foreground = Brushes.White,
            BorderThickness = new Thickness(0),
            FontWeight = FontWeights.Bold
        };
        panel.Children.Add(analysisViewResultsButton);

        analysisProgressWindow.Content = panel;
        analysisProgressWindow.StateChanged += (_, _) =>
        {
            // Minimized: the app stays usable while the analysis runs.
            // Restored before it finishes: back to the locked progress view.
            if (analysisOwnerWindow != null && analysisProgressWindow != null)
            {
                analysisOwnerWindow.IsEnabled =
                    analysisProgressWindow.WindowState == WindowState.Minimized
                    || !analysisTimer.IsEnabled;
            }
        };
        analysisProgressWindow.Closed += (_, _) =>
        {
            // X hides the pop-up only: the backend keeps running and the
            // Evidence status line reports the result when it finishes.
            if (analysisOwnerWindow != null)
            {
                analysisOwnerWindow.IsEnabled = true;
                analysisOwnerWindow.Activate();
            }
            analysisProgressWindow = null;
        };
        analysisStopwatch.Restart();
        analysisTimer.Interval = TimeSpan.FromSeconds(1);
        analysisTimer.Tick -= AnalysisTimer_Tick;
        analysisTimer.Tick += AnalysisTimer_Tick;
        analysisTimer.Start();
        analysisProgressWindow.Show();
    }

    private async void AnalysisTimer_Tick(object? sender, EventArgs e)
    {
        if (analysisElapsedText != null)
        {
            analysisElapsedText.Text =
                $"Elapsed time: {analysisStopwatch.Elapsed:mm\\:ss}";
        }

        // Poll the backend's current pipeline step every other second.
        if (analysisStopwatch.Elapsed.Seconds % 2 != 0 || caseId == null)
        {
            return;
        }
        try
        {
            string stage = await backendApi.GetAnalysisStageAsync(caseId);
            if (!string.IsNullOrEmpty(stage) && analysisTimer.IsEnabled)
            {
                if (analysisStatusText != null)
                {
                    analysisStatusText.Text = stage;
                }
                StatusText.Text = stage;
            }
        }
        catch (Exception)
        {
            // Progress is informational; a failed poll keeps the last text.
        }
    }

    private void CompleteAnalysisProgressDialog(Action viewResults)
    {
        analysisTimer.Stop();
        analysisStopwatch.Stop();
        if (analysisProgressWindow == null)
        {
            // Pop-up was closed with X; results open from the Dashboard tab.
            return;
        }
        if (analysisProgressBar != null)
        {
            analysisProgressBar.IsIndeterminate = false;
            analysisProgressBar.Value = 100;
        }
        if (analysisStatusText != null)
        {
            analysisStatusText.Text = "Analysis complete.";
            analysisStatusText.Foreground =
                new SolidColorBrush(Color.FromRgb(74, 222, 128));
        }
        if (analysisElapsedText != null)
        {
            analysisElapsedText.Text =
                $"Completed in: {analysisStopwatch.Elapsed:mm\\:ss}";
        }
        if (analysisViewResultsButton != null)
        {
            analysisViewResultsButton.Visibility = Visibility.Visible;
            analysisViewResultsButton.IsEnabled = true;
            analysisViewResultsButton.Click += (_, _) =>
            {
                if (analysisOwnerWindow != null)
                {
                    analysisOwnerWindow.IsEnabled = true;
                    analysisOwnerWindow.Activate();
                }
                analysisProgressWindow?.Close();
                viewResults();
            };
        }
    }

    private void CloseAnalysisProgressDialog()
    {
        analysisTimer.Stop();
        analysisStopwatch.Stop();
        if (analysisOwnerWindow != null)
        {
            analysisOwnerWindow.IsEnabled = true;
        }
        analysisProgressWindow?.Close();
        analysisProgressWindow = null;
        analysisOwnerWindow = null;
    }

    private async void StartAnalysis_Click(
        object sender,
        RoutedEventArgs e)
    {
        try
        {
            // =================================================
            // VALIDATE CASE ID
            // =================================================

            if (
                string.IsNullOrWhiteSpace(
                    caseId
                )
            )
            {
                MessageBox.Show(
                    "No Case ID was created. " +
                    "Please select a PCAP file first.",
                    "FORENXAI",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning
                );


                return;
            }


            // =================================================
            // VALIDATE EVIDENCE
            // =================================================

            if (
                string.IsNullOrWhiteSpace(
                    selectedFilePath
                )
            )
            {
                MessageBox.Show(
                    "No evidence file was selected.",
                    "FORENXAI",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning
                );


                return;
            }


            if (
                !File.Exists(
                    selectedFilePath
                )
            )
            {
                MessageBox.Show(
                    "The evidence file could not be found:\n\n" +
                    selectedFilePath,
                    "FORENXAI",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error
                );


                return;
            }


            // =================================================
            // UPDATE UI
            // =================================================

            StartAnalysisButton.IsEnabled =
                false;


            StartAnalysisButton.Content =
                "STARTING ANALYSIS...";


            StatusText.Text =
                "Sending evidence to Python backend...";


            StatusText.Foreground =
                new SolidColorBrush(
                    Colors.LightBlue
                );

            ShowAnalysisProgressDialog();


            // =================================================
            // GET EVIDENCE FILENAME
            // =================================================

            string fileName =
                Path.GetFileName(
                    selectedFilePath
                );


            if (
                string.IsNullOrWhiteSpace(
                    fileName
                )
            )
            {
                throw new Exception(
                    "Could not determine the evidence filename."
                );
            }


            // =================================================
            // SEND TO PYTHON BACKEND
            // =================================================

            await App.EnsureBackendAsync();

            AnalysisResponse? response =
                await backendApi
                    .StartAnalysisAsync(
                        caseId,
                        fileName
                    );


            if (
                response == null
            )
            {
                throw new Exception(
                    "The Python backend returned an empty response."
                );
            }


            // =================================================
            // DETERMINE CAPTURE QUALITY
            // =================================================

            bool emptyCapture =
                response.TotalPackets == 0
                ||
                response.TotalFlows == 0;


            bool lowFlowCapture =
                !emptyCapture
                &&
                response.TotalFlows < 50;


            // =================================================
            // EMPTY PACKET CAPTURE WARNING
            // =================================================

            if (
                emptyCapture
            )
            {
                StatusText.Text =
                    "Warning: Empty packet capture";


                StatusText.Foreground =
                    new SolidColorBrush(
                        Colors.Orange
                    );


                MessageBox.Show(
                    "FORENXAI detected an empty packet capture.\n\n" +

                    $"Total Packets: {response.TotalPackets:N0}\n" +
                    $"Total Flows: {response.TotalFlows:N0}\n\n" +

                    "No usable network flows were found. " +
                    "The analysis results may be unavailable " +
                    "or incomplete.",

                    "FORENXAI Evidence Warning",

                    MessageBoxButton.OK,

                    MessageBoxImage.Warning
                );
            }


            // =================================================
            // LOW FLOW COUNT WARNING
            // =================================================

            else if (
                lowFlowCapture
            )
            {
                StatusText.Text =
                    $"Warning: Only {response.TotalFlows:N0} flows detected";


                StatusText.Foreground =
                    new SolidColorBrush(
                        Colors.Orange
                    );


                MessageBox.Show(
                    "FORENXAI detected a small packet capture.\n\n" +

                    $"Total Packets: {response.TotalPackets:N0}\n" +
                    $"Total Flows: {response.TotalFlows:N0}\n\n" +

                    "Fewer than 50 network flows were extracted. " +
                    "The results can still be analyzed, but the " +
                    "capture may contain limited traffic for " +
                    "forensic interpretation.",

                    "FORENXAI Low Flow Warning",

                    MessageBoxButton.OK,

                    MessageBoxImage.Warning
                );
            }


            // =================================================
            // NORMAL CAPTURE
            // =================================================

            else
            {
                StatusText.Text =
                    "Analysis complete";


                StatusText.Foreground =
                    new SolidColorBrush(
                        Colors.LightGreen
                    );
            }


            // =================================================
            // ANALYSIS COMPLETE BUTTON
            // =================================================

            StartAnalysisButton.Content =
                "ANALYSIS COMPLETE";


            // =================================================
            // STORE CURRENT CASE IN MAIN WINDOW
            // =================================================

            if (
                Window.GetWindow(this)
                is MainWindow mainWindow
            )
            {
                mainWindow.SetCurrentAnalysis(response);
            }


            CompleteAnalysisProgressDialog(() =>
            {
                if (Window.GetWindow(this) is MainWindow dashboardWindow)
                {
                    dashboardWindow.ShowDashboard(response.CaseId);
                }
            });
        }


        // =====================================================
        // BACKEND CONNECTION ERROR
        // =====================================================

        catch (
            HttpRequestException ex
        )
        {
            CloseAnalysisProgressDialog();
            StatusText.Text =
                "Backend connection failed";


            StatusText.Foreground =
                new SolidColorBrush(
                    Colors.OrangeRed
                );


            StartAnalysisButton.Content =
                "START FORENSIC ANALYSIS";


            StartAnalysisButton.IsEnabled =
                true;


            MessageBox.Show(
                "FORENXAI could not connect to the Python backend.\n\n" +
                "Make sure Uvicorn is running.\n\n" +
                $"Details:\n{ex.Message}",
                "Backend Connection Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error
            );
        }


        // =====================================================
        // OTHER ERROR
        // =====================================================

        catch (
            Exception ex
        )
        {
            CloseAnalysisProgressDialog();
            StatusText.Text =
                "Analysis failed";


            StatusText.Foreground =
                new SolidColorBrush(
                    Colors.OrangeRed
                );


            StartAnalysisButton.Content =
                "START FORENSIC ANALYSIS";


            StartAnalysisButton.IsEnabled =
                true;


            MessageBox.Show(
                $"Could not start the forensic analysis.\n\n" +
                $"Error type: {ex.GetType().Name}\n\n" +
                $"Message: {ex.Message}\n\n" +
                $"Location:\n{ex.StackTrace}",
                "FORENXAI Analysis Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error
            );
        }
    }
}
