using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.CommandLine;
using System.Threading.Tasks;

namespace Lumoin.Veridical.Cli;

/// <summary>
/// Entry point for the <c>veridical</c> tool. Runs as a command-line tool by
/// default, or as a Model Context Protocol (MCP) stdio server when invoked with
/// <c>-mcp</c>. Both surfaces forward to <see cref="VeridicalOperations"/>.
/// </summary>
internal static class Program
{
    /// <summary>Runs the tool. Returns the process exit code (zero on success).</summary>
    public static async Task<int> Main(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        if(args.Length == 1 && args[0] == "-mcp")
        {
            return await RunMcpServerAsync(args).ConfigureAwait(false);
        }

        return await RunCliAsync(args).ConfigureAwait(false);
    }


    private static async Task<int> RunMcpServerAsync(string[] args)
    {
        HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);

        builder.Services.AddMcpServer()
            .WithStdioServerTransport()
            .WithTools<VeridicalMcpServer>();

        //MCP speaks JSON-RPC over stdout, so logs must go to stderr to avoid
        //corrupting the protocol stream.
        builder.Logging.AddConsole(options =>
        {
            options.LogToStandardErrorThreshold = LogLevel.Trace;
        });

        await builder.Build().RunAsync().ConfigureAwait(false);

        return 0;
    }


    private static async Task<int> RunCliAsync(string[] args)
    {
        RootCommand rootCommand = new("A command line and MCP tool for Lumoin.Veridical.");

        rootCommand.Subcommands.Add(BuildInfoCommand());
        rootCommand.Subcommands.Add(BuildHashCommand());
        rootCommand.Subcommands.Add(BuildSelfTestCommand());

        return await rootCommand.Parse(args).InvokeAsync().ConfigureAwait(false);
    }


    private static Command BuildInfoCommand()
    {
        Command command = new("info", "Print platform and scalar-backend information.");
        command.SetAction(_ =>
        {
            Console.WriteLine(VeridicalOperations.Info());

            return 0;
        });

        return command;
    }


    private static Command BuildHashCommand()
    {
        Argument<string> inputArgument = new("input") { Description = "The input to hash (UTF-8 text, or hex with --hex)." };
        Option<bool> hexOption = new("--hex") { Description = "Interpret the input as a hex-encoded byte string." };

        Command command = new("hash", "Compute the BLAKE3-256 hash of an input.")
        {
            inputArgument,
            hexOption
        };

        command.SetAction(parseResult =>
        {
            string input = parseResult.GetValue(inputArgument) ?? string.Empty;
            bool hex = parseResult.GetValue(hexOption);

            if(hex)
            {
                byte[] bytes;
                try
                {
                    bytes = Convert.FromHexString(input);
                }
                catch(FormatException)
                {
                    Console.Error.WriteLine("Error: --hex input is not a valid hex string (even length, 0-9a-f).");

                    return 1;
                }

                Console.WriteLine(VeridicalOperations.HashBlake3(bytes));

                return 0;
            }

            Console.WriteLine(VeridicalOperations.HashBlake3Text(input));

            return 0;
        });

        return command;
    }


    private static Command BuildSelfTestCommand()
    {
        Command command = new("selftest", "Run the known-answer conformance vectors (exit non-zero on failure).");
        command.SetAction(_ =>
        {
            (bool ok, string report) = VeridicalOperations.RunSelfTest();
            Console.WriteLine(report);

            return ok ? 0 : 1;
        });

        return command;
    }
}
