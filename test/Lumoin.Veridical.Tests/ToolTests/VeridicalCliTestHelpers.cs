using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Lumoin.Veridical.Tests.ToolTests;

/// <summary>The captured outcome of running the CLI as a subprocess.</summary>
/// <param name="ExitCode">The process exit code; zero indicates success.</param>
/// <param name="Stdout">The captured standard output.</param>
/// <param name="Stderr">The captured standard error.</param>
internal readonly record struct CliResult(int ExitCode, string Stdout, string Stderr);

/// <summary>
/// Shared infrastructure for the <c>veridical</c> tool tests: locating the built
/// executable and running it as a CLI subprocess or an MCP stdio server.
/// </summary>
internal static class VeridicalCliTestHelpers
{
    /// <summary>
    /// Returns the path to the built <c>veridical</c> executable, or <see langword="null"/>
    /// when it has not been built. The test project references the CLI project, so a
    /// normal build produces it; this still tolerates its absence (returns null) so the
    /// subprocess tests can report Inconclusive rather than fail.
    /// </summary>
    public static string? GetExecutablePath()
    {
        string basePath = AppContext.BaseDirectory;
        string repoRoot = Path.GetFullPath(Path.Combine(basePath, "../../../../.."));
        string extension = OperatingSystem.IsWindows() ? ".exe" : "";

        foreach(string configuration in new[] { "Debug", "Release" })
        {
            string path = Path.Combine(repoRoot, "src", "Lumoin.Veridical.Cli", "bin", configuration, "net10.0", $"Lumoin.Veridical.Cli{extension}");
            if(File.Exists(path))
            {
                return path;
            }
        }

        return null;
    }


    /// <summary>Runs the CLI executable with the given argument list and captures its result.</summary>
    public static async Task<CliResult> RunCliAsync(string executablePath, string[] arguments, CancellationToken cancellationToken = default)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = executablePath,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            }
        };

        foreach(string argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }

        process.Start();

        string stdout = await process.StandardOutput.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
        string stderr = await process.StandardError.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);

        return new CliResult(process.ExitCode, stdout, stderr);
    }


    /// <summary>Ensures an MCP server subprocess is terminated.</summary>
    public static async Task EnsureProcessTerminatedAsync(Process process, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(process);

        if(!process.HasExited)
        {
            process.Kill();
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        }
    }
}
