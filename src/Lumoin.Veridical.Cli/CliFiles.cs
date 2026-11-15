using System;
using System.IO;
using System.Security;

namespace Lumoin.Veridical.Cli;

/// <summary>
/// File and standard-input access shared by the command-line subcommands and the MCP tools. Secrets are
/// read only from files or standard input and are written only to a file the caller names, created
/// exclusively and readable by the owner alone where the platform supports it; they are never written to
/// standard output, standard error or a log.
/// </summary>
internal static class CliFiles
{
    /// <summary>The path that names standard input.</summary>
    public const string StandardInput = "-";


    /// <summary>
    /// Reads the whole text from a file path, or from standard input when the path is <c>-</c>. Returns
    /// <see langword="false"/> with a message naming <paramref name="what"/> when it cannot be read.
    /// </summary>
    /// <param name="path">The file path, or <c>-</c> for standard input.</param>
    /// <param name="what">What is being read, for the error message.</param>
    /// <param name="content">Receives the text, or the empty string on failure.</param>
    /// <param name="error">Receives the failure message, or the empty string on success.</param>
    /// <returns>Whether the input was read.</returns>
    public static bool TryRead(string path, string what, out string content, out string error)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(what);

        try
        {
            content = path == StandardInput ? Console.In.ReadToEnd() : File.ReadAllText(path);
            error = string.Empty;

            return true;
        }
        catch(Exception failure) when(failure is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException or SecurityException)
        {
            content = string.Empty;
            error = $"could not read the {what} ({failure.Message}).";

            return false;
        }
    }


    /// <summary>
    /// Writes a public output to <paramref name="path"/>, replacing an existing file.
    /// </summary>
    /// <param name="path">The file path.</param>
    /// <param name="content">The text to write.</param>
    /// <param name="what">What is being written, for the error message.</param>
    /// <param name="error">Receives the failure message, or the empty string on success.</param>
    /// <returns>Whether the file was written.</returns>
    public static bool TryWrite(string path, string content, string what, out string error)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(content);
        ArgumentNullException.ThrowIfNull(what);

        try
        {
            File.WriteAllText(path, content);
            error = string.Empty;

            return true;
        }
        catch(Exception failure) when(failure is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException or SecurityException)
        {
            error = $"could not write the {what} ({failure.Message}).";

            return false;
        }
    }


    /// <summary>
    /// Writes a secret output to <paramref name="path"/>. The file must not already exist, so a key is never
    /// silently replaced, and it is readable by the owner alone where the platform supports file modes.
    /// </summary>
    /// <param name="path">The file path.</param>
    /// <param name="content">The secret text to write.</param>
    /// <param name="what">What is being written, for the error message.</param>
    /// <param name="error">Receives the failure message, or the empty string on success.</param>
    /// <returns>Whether the file was written.</returns>
    public static bool TryWriteSecret(string path, string content, string what, out string error)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(content);
        ArgumentNullException.ThrowIfNull(what);

        try
        {
            var options = new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None
            };
            if(!OperatingSystem.IsWindows())
            {
                options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            }

            using var stream = new StreamWriter(path, options);
            stream.Write(content);
            error = string.Empty;

            return true;
        }
        catch(Exception failure) when(failure is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException or SecurityException)
        {
            error = $"could not write the {what} ({failure.Message}).";

            return false;
        }
    }
}
