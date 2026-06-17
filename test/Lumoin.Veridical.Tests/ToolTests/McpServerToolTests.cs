using Lumoin.Veridical.Cli;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace Lumoin.Veridical.Tests.ToolTests;

/// <summary>
/// Connects to the <c>veridical -mcp</c> server over stdio with the official MCP
/// client SDK, confirms the expected tools are registered, and calls them end to
/// end. Inconclusive when the executable has not been built.
/// </summary>
[TestClass]
internal sealed class McpServerToolTests
{
    //The MCP server runs as a spawned child process reached over stdio. On a loaded CI
    //runner the process can intermittently drop during the handshake before it is ready,
    //surfacing as ClientTransportClosedException ("MCP server process exited
    //unexpectedly"). The connect-and-run sequence is retried a few times so a transient
    //spawn race does not fail the suite; assertion failures inside the body are not retried.
    private const int McpConnectAttempts = 4;

    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    [TestCategory("McpClient")]
    public async Task McpClientConnectsListsToolsAndRunsSelfTest()
    {
        await WithMcpClientAsync(async client =>
        {
            var tools = await client.ListToolsAsync(cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            var toolNames = tools.Select(tool => tool.Name).ToList();

            Assert.IsGreaterThan(0, tools.Count);
            Assert.Contains(McpToolNames.Info, toolNames);
            Assert.Contains(McpToolNames.Hash, toolNames);
            Assert.Contains(McpToolNames.SelfTest, toolNames);

            var result = await client.CallToolAsync(
                McpToolNames.SelfTest,
                new Dictionary<string, object?>(),
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.Contains("All conformance vectors passed.", TextOf(result), StringComparison.Ordinal);
        }).ConfigureAwait(false);
    }


    [TestMethod]
    [TestCategory("McpClient")]
    public async Task McpHashToolMatchesKnownVector()
    {
        //BLAKE3-256 of the UTF-8 bytes of "hello".
        const string HelloHash = "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f";

        await WithMcpClientAsync(async client =>
        {
            var result = await client.CallToolAsync(
                McpToolNames.Hash,
                new Dictionary<string, object?> { ["text"] = "hello" },
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.Contains(HelloHash, TextOf(result), StringComparison.Ordinal);
        }).ConfigureAwait(false);
    }


    //Spawns the MCP server, runs the body against a connected client, and disposes the
    //client. Retries the whole connect-and-run sequence on a transient transport drop
    //(the spawned server process exiting before it is ready); assertion failures and any
    //other error propagate on the first occurrence.
    private async Task WithMcpClientAsync(Func<McpClient, Task> body)
    {
        string? executable = VeridicalCliTestHelpers.GetExecutablePath();
        if(executable is null)
        {
            Assert.Inconclusive("The veridical executable was not found; build the solution first.");
        }

        for(int attempt = 1; ; attempt++)
        {
            try
            {
                McpClient client = await McpClient.CreateAsync(CreateTransport(executable), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
                await using(client.ConfigureAwait(false))
                {
                    await body(client).ConfigureAwait(false);
                }

                return;
            }
            catch(Exception exception) when(attempt < McpConnectAttempts && IsTransientTransport(exception))
            {
                await Task.Delay(TimeSpan.FromMilliseconds(500 * attempt), TestContext.CancellationToken).ConfigureAwait(false);
            }
        }
    }


    //A dropped stdio transport or a server process that exited before the handshake
    //completed; both are transient spawn races on a loaded runner, not a protocol fault.
    private static bool IsTransientTransport(Exception exception)
    {
        return exception is ClientTransportClosedException
            || exception is IOException
            || exception.InnerException is IOException;
    }


    private static StdioClientTransport CreateTransport(string executable)
    {
        return new StdioClientTransport(new StdioClientTransportOptions
        {
            Name = "Veridical MCP Server",
            Command = executable,
            Arguments = ["-mcp"]
        });
    }


    //Concatenates the text content blocks of a tool-call result.
    private static string TextOf(CallToolResult result)
    {
        return string.Concat(result.Content.OfType<TextContentBlock>().Select(block => block.Text));
    }
}
