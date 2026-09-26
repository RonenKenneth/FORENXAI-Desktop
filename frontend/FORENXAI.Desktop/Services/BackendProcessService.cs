using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;

namespace FORENXAI.Desktop.Services;

public sealed class BackendProcessService : IDisposable
{
    private const string HealthUrl =
        "http://127.0.0.1:8000/health";

    private static readonly TimeSpan HealthTimeout =
        TimeSpan.FromSeconds(30);

    private static readonly TimeSpan HealthPollInterval =
        TimeSpan.FromMilliseconds(500);

    private readonly HttpClient httpClient;

    private Process? backendProcess;

    private bool ownsBackendProcess;


    // =========================================================
    // CONSTRUCTOR
    // =========================================================

    public BackendProcessService()
    {
        httpClient =
            new HttpClient
            {
                Timeout =
                    TimeSpan.FromSeconds(2)
            };
    }


    // =========================================================
    // ENSURE BACKEND IS RUNNING
    // =========================================================

    public async Task EnsureBackendRunningAsync()
    {
        if (
            await IsBackendHealthyAsync()
        )
        {
            ownsBackendProcess =
                false;

            return;
        }


        string backendExecutable =
            FindBackendExecutable();


        ProcessStartInfo startInfo =
            new ProcessStartInfo
            {
                FileName =
                    backendExecutable,

                WorkingDirectory =
                    Path.GetDirectoryName(
                        backendExecutable
                    )
                    ?? AppContext.BaseDirectory,

                UseShellExecute =
                    false,

                CreateNoWindow =
                    true,

                WindowStyle =
                    ProcessWindowStyle.Hidden
            };


        backendProcess =
            Process.Start(
                startInfo
            );


        if (
            backendProcess
            == null
        )
        {
            throw new InvalidOperationException(
                "FORENXAI.Backend.exe could not be started."
            );
        }


        ownsBackendProcess =
            true;


        try
        {
            await WaitForBackendHealthAsync();
        }
        catch
        {
            StopBackendIfOwned();

            throw;
        }
    }


    // =========================================================
    // HEALTH CHECK
    // =========================================================

    private async Task<bool> IsBackendHealthyAsync()
    {
        try
        {
            using HttpResponseMessage response =
                await httpClient
                    .GetAsync(
                        HealthUrl
                    );

            return response
                .IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }


    private async Task WaitForBackendHealthAsync()
    {
        Stopwatch stopwatch =
            Stopwatch.StartNew();


        while (
            stopwatch.Elapsed
            < HealthTimeout
        )
        {
            if (
                backendProcess?
                    .HasExited
                == true
            )
            {
                throw new InvalidOperationException(
                    "FORENXAI.Backend.exe exited before " +
                    "the backend became ready."
                );
            }


            if (
                await IsBackendHealthyAsync()
            )
            {
                return;
            }


            await Task.Delay(
                HealthPollInterval
            );
        }


        throw new TimeoutException(
            "The FORENXAI backend did not become healthy " +
            $"within {HealthTimeout.TotalSeconds:0} seconds."
        );
    }


    // =========================================================
    // BACKEND EXECUTABLE DISCOVERY
    // =========================================================

    private static string FindBackendExecutable()
    {
        List<string> candidates =
            new List<string>();


        string? configuredPath =
            Environment.GetEnvironmentVariable(
                "FORENXAI_BACKEND_EXE"
            );


        if (
            !string.IsNullOrWhiteSpace(
                configuredPath
            )
        )
        {
            candidates.Add(
                Path.GetFullPath(
                    configuredPath
                )
            );
        }


        candidates.Add(
            Path.Combine(
                AppContext.BaseDirectory,
                "backend",
                "FORENXAI.Backend.exe"
            )
        );


        candidates.Add(
            Path.Combine(
                AppContext.BaseDirectory,
                "FORENXAI.Backend.exe"
            )
        );


        DirectoryInfo? currentDirectory =
            new DirectoryInfo(
                AppContext.BaseDirectory
            );


        for (
            int level = 0;
            level < 8
            && currentDirectory != null;
            level++
        )
        {
            candidates.Add(
                Path.Combine(
                    currentDirectory.FullName,
                    "backend",
                    "dist",
                    "FORENXAI.Backend.exe"
                )
            );

            currentDirectory =
                currentDirectory.Parent;
        }


        foreach (
            string candidate
            in candidates
        )
        {
            if (
                File.Exists(
                    candidate
                )
            )
            {
                return candidate;
            }
        }


        throw new FileNotFoundException(
            "FORENXAI.Backend.exe could not be found.\n\n" +
            "Build the backend first, or set the " +
            "FORENXAI_BACKEND_EXE environment variable."
        );
    }


    // =========================================================
    // STOP BACKEND
    // =========================================================

    public void StopBackendIfOwned()
    {
        if (
            !ownsBackendProcess
            ||
            backendProcess
            == null
        )
        {
            return;
        }


        try
        {
            if (
                !backendProcess
                    .HasExited
            )
            {
                backendProcess.Kill(
                    entireProcessTree: true
                );

                backendProcess.WaitForExit(
                    5000
                );
            }
        }
        catch
        {
        }
        finally
        {
            ownsBackendProcess =
                false;

            backendProcess.Dispose();

            backendProcess =
                null;
        }
    }


    // =========================================================
    // DISPOSE
    // =========================================================

    public void Dispose()
    {
        httpClient.Dispose();

        backendProcess?
            .Dispose();
    }
}
