using Lumoin.Veridical.Cli;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using System;
using System.Collections.Generic;
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
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    [TestCategory("McpClient")]
    public async Task McpClientConnectsListsToolsAndRunsSelfTest()
    {
        string? executable = VeridicalCliTestHelpers.GetExecutablePath();
        if(executable is null)
        {
            Assert.Inconclusive("The veridical executable was not found; build the solution first.");
        }

        McpClient client = await McpClient.CreateAsync(CreateTransport(executable), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        await using(client.ConfigureAwait(false))
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
        }
    }


    [TestMethod]
    [TestCategory("McpClient")]
    public async Task McpHashToolMatchesKnownVector()
    {
        string? executable = VeridicalCliTestHelpers.GetExecutablePath();
        if(executable is null)
        {
            Assert.Inconclusive("The veridical executable was not found; build the solution first.");
        }

        //BLAKE3-256 of the UTF-8 bytes of "hello".
        const string HelloHash = "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f";

        McpClient client = await McpClient.CreateAsync(CreateTransport(executable), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        await using(client.ConfigureAwait(false))
        {
            var result = await client.CallToolAsync(
                McpToolNames.Hash,
                new Dictionary<string, object?> { ["text"] = "hello" },
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.Contains(HelloHash, TextOf(result), StringComparison.Ordinal);
        }
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
