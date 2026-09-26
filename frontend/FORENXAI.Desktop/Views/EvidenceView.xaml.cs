using Microsoft.Win32;

using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

using FORENXAI.Desktop.Services;

namespace FORENXAI.Desktop.Views;


public partial class EvidenceView : UserControl
{
    private string? selectedFilePath;

    private string? caseDirectory;

    private string? caseId;


    private readonly BackendApiService backendApi;


    // =========================================================
    // CONSTRUCTOR
    // =========================================================

    public EvidenceView()
    {
        InitializeComponent();


        backendApi =
            new BackendApiService();
    }


    // =========================================================
    // BROWSE FOR PCAP / PCAPNG
    // =========================================================

    private void BrowsePcap_Click(
        object sender,
        RoutedEventArgs e)
    {
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
                mainWindow.SetCurrentCase(
                    response.CaseId
                );
            }


            // =================================================
            // SHOW COMPLETION MESSAGE
            // =================================================

            MessageBox.Show(
                $"FORENXAI analysis completed.\n\n" +

                $"Case ID: {response.CaseId}\n" +
                $"Evidence: {response.FileName}\n\n" +

                $"Total Packets: {response.TotalPackets:N0}\n" +
                $"Total Flows: {response.TotalFlows:N0}\n" +
                $"Total Bytes: {response.TotalBytes:N0}\n\n" +

                $"ML Flows: {response.MlTotalFlows:N0}\n" +
                $"Benign: {response.BenignFlows:N0}\n" +
                $"Threats: {response.ThreatFlows:N0}\n" +
                $"Threat Percentage: {response.ThreatPercentage:F2}%\n\n" +

                $"SHA-256:\n{response.Sha256}\n\n" +

                response.Message,

                "FORENXAI Analysis",

                MessageBoxButton.OK,

                MessageBoxImage.Information
            );


            // =================================================
            // AUTOMATICALLY OPEN DASHBOARD
            // =================================================

            if (
                Window.GetWindow(this)
                is MainWindow dashboardWindow
            )
            {
                dashboardWindow.ShowDashboard(
                    response.CaseId
                );
            }
        }


        // =====================================================
        // BACKEND CONNECTION ERROR
        // =====================================================

        catch (
            HttpRequestException ex
        )
        {
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