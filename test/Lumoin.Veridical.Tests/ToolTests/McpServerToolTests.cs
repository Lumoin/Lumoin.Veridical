using Lumoin.Veridical.Cli;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;

namespace Lumoin.Veridical.Tests.ToolTests;

/// <summary>
/// Connects to the <c>veridical -mcp</c> server over stdio with the official MCP
/// client SDK, confirms the expected tools are registered, and calls them end to
/// end. Inconclusive when the executable has not been built.
/// </summary>
[TestClass]
internal sealed class McpServerToolTests
{
    /// <summary>
    /// The MCP server runs as a spawned child process reached over stdio. On a loaded CI runner the process
    /// can intermittently drop during the handshake before it is ready, surfacing as
    /// ClientTransportClosedException ("MCP server process exited unexpectedly"). The connect-and-run
    /// sequence is retried a few times so a transient spawn race does not fail the suite; assertion failures
    /// inside the body are not retried.
    /// </summary>
    private const int McpConnectAttempts = 4;


    /// <summary>
    /// The single legitimate deadline: a hang-guard, not a readiness timeout. A correctly behaving server
    /// answers in seconds, but a cold start contending with the all-cores parallel run can take a couple of
    /// minutes; this only fires when the server never answers at all, which is a real, deterministic failure
    /// rather than a load-sensitive flake. Pass/fail otherwise depends only on the server's responses, never
    /// on timing.
    /// </summary>
    private const int McpHangGuardMilliseconds = 300_000;


    /// <summary>
    /// The hang-guard of the tests that run a full Longfellow proof through the server. A Release proof of the
    /// reference token takes minutes of CPU, and the guard only has to catch a server that never answers.
    /// </summary>
    private const int McpProofHangGuardMilliseconds = 1_800_000;


    /// <summary>
    /// The SDK's initialization handshake carries its own 60-second deadline by default. A test's correctness
    /// must never depend on a wall-clock deadline, so it is disabled here: the cold-started server is waited
    /// for indefinitely, leaving the per-test [Timeout] hang-guard above (surfaced through
    /// TestContext.CancellationToken) as the only clock. The client also bounds its server/discover probe
    /// (five seconds by default) and, when that elapses, sends initialize on the same connection. A server
    /// that is merely slow to start still answers the probe afterwards and then holds the connection to the
    /// 2026-07-28 revision, which has no initialize, so the probe deadline is disabled too.
    /// </summary>
    private static McpClientOptions NoInitializationTimeout { get; } = new()
    {
        InitializationTimeout = Timeout.InfiniteTimeSpan,
        DiscoverProbeTimeout = Timeout.InfiniteTimeSpan
    };


    /// <summary>
    /// The context MSTest injects, whose cancellation token is observed by every awaited call so the
    /// hang-guard timeout cancels a stuck server.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Skips every test of the class under WebAssembly, where the runtime cannot start the executable as a child process.
    /// </summary>
    [TestInitialize]
    public void RequireSubprocessSupport() => RuntimeRequirements.RequireProcessSpawning();


    /// <summary>
    /// Connects an MCP client to the server, confirms the info, hash and self-test tools are listed, and runs
    /// the self-test tool to a passing result.
    /// </summary>
    [TestMethod]
    [TestCategory("McpClient")]
    [Timeout(McpHangGuardMilliseconds, CooperativeCancellation = true)]
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


    /// <summary>Calls the hash tool on the text <c>hello</c> and confirms the reply carries the known BLAKE3-256 digest.</summary>
    [TestMethod]
    [TestCategory("McpClient")]
    [Timeout(McpHangGuardMilliseconds, CooperativeCancellation = true)]
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


    /// <summary>Confirms the Longfellow JWT tools are listed and that malformed requests are answered with an error or a malformed report, not a transport fault.</summary>
    [TestMethod]
    [TestCategory("McpClient")]
    [Timeout(McpHangGuardMilliseconds, CooperativeCancellation = true)]
    public async Task McpLongfellowJwtToolsAreListedAndReportMalformedInput()
    {
        string tokenPath = VeridicalCliTestHelpers.WriteTemporaryFile("aaaa.bbbb.cccc~dddd.eeee.ffff");
        string proofPath = VeridicalCliTestHelpers.WriteTemporaryFile("not-hex!");
        string presentationPath = VeridicalCliTestHelpers.WriteTemporaryFile("a.b.cc");
        string missingPath = Path.Combine(Path.GetTempPath(), $"veridical-missing-{Guid.NewGuid():N}.txt");
        try
        {
            await WithMcpClientAsync(async client =>
            {
                var tools = await client.ListToolsAsync(cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
                var toolNames = tools.Select(tool => tool.Name).ToList();

                Assert.Contains(McpToolNames.LongfellowJwtProve, toolNames);
                Assert.Contains(McpToolNames.LongfellowJwtVerify, toolNames);

                var unprovable = await client.CallToolAsync(
                    McpToolNames.LongfellowJwtProve,
                    JwtProveArguments(tokenPath, missingPath),
                    cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
                Assert.StartsWith("Error:", TextOf(unprovable), StringComparison.Ordinal);
                Assert.DoesNotContain("aaaa.bbbb", TextOf(unprovable), StringComparison.Ordinal);

                var unreadable = await client.CallToolAsync(
                    McpToolNames.LongfellowJwtProve,
                    JwtProveArguments(missingPath, missingPath),
                    cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
                Assert.StartsWith("Error: could not read the token", TextOf(unreadable), StringComparison.Ordinal);

                var malformed = await client.CallToolAsync(
                    McpToolNames.LongfellowJwtVerify,
                    JwtVerifyArguments(proofPath, presentationPath, "given_name=Erika"),
                    cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
                Assert.StartsWith("MALFORMED:", TextOf(malformed), StringComparison.Ordinal);
            }).ConfigureAwait(false);
        }
        finally
        {
            File.Delete(tokenPath);
            File.Delete(proofPath);
            File.Delete(presentationPath);
        }
    }


    /// <summary>Proves the reference token through the MCP prove tool and verifies the proof file through the verify tool, then confirms a different attribute value is rejected.</summary>
    [TestMethod]
    [TestCategory("McpClient")]
    [TestCategory(TestCategories.Slow)]
    [Timeout(McpProofHangGuardMilliseconds, CooperativeCancellation = true)]
    public async Task McpLongfellowJwtProveThenVerifyRoundTrips()
    {
        string tokenPath = VeridicalCliTestHelpers.WriteTemporaryFile(LongfellowJwtTestVectors.ErikaToken.Token);
        string proofPath = Path.Combine(Path.GetTempPath(), $"veridical-proof-{Guid.NewGuid():N}.txt");
        try
        {
            await WithMcpClientAsync(async client =>
            {
                var prove = await client.CallToolAsync(
                    McpToolNames.LongfellowJwtProve,
                    JwtProveArguments(tokenPath, proofPath),
                    cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
                Assert.StartsWith("Wrote the proof", TextOf(prove), StringComparison.Ordinal);

                var valid = await client.CallToolAsync(
                    McpToolNames.LongfellowJwtVerify,
                    JwtVerifyArguments(proofPath, tokenPath, "given_name=Erika"),
                    cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
                Assert.StartsWith("VALID: proves given_name = Erika", TextOf(valid), StringComparison.Ordinal);

                var wrong = await client.CallToolAsync(
                    McpToolNames.LongfellowJwtVerify,
                    JwtVerifyArguments(proofPath, tokenPath, "given_name=Wrong"),
                    cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
                Assert.StartsWith("REJECTED:", TextOf(wrong), StringComparison.Ordinal);
            }).ConfigureAwait(false);
        }
        finally
        {
            File.Delete(tokenPath);
            File.Delete(proofPath);
        }
    }


    /// <summary>
    /// Generates a BBS key pair, signs, verifies, derives a selective-disclosure proof and verifies it through the
    /// MCP tools, and confirms that a changed message and a missing secret key file are reported as failures.
    /// </summary>
    [TestMethod]
    [TestCategory("McpClient")]
    [Timeout(McpHangGuardMilliseconds, CooperativeCancellation = true)]
    public async Task McpBbsToolsSignVerifyAndProveSelectiveDisclosure()
    {
        const string Messages = "alpha\nbeta\ngamma";
        string secretPath = Path.Combine(Path.GetTempPath(), $"veridical-test-{Guid.NewGuid():N}.key");
        try
        {
            await WithMcpClientAsync(async client =>
            {
                var tools = await client.ListToolsAsync(cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
                var toolNames = tools.Select(tool => tool.Name).ToList();
                Assert.Contains(McpToolNames.BbsKeyGenerate, toolNames);
                Assert.Contains(McpToolNames.BbsProofVerify, toolNames);

                var keyResult = await client.CallToolAsync(
                    McpToolNames.BbsKeyGenerate,
                    new Dictionary<string, object?> { ["secretKeyFile"] = secretPath },
                    cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
                string publicKey = TextOf(keyResult).Trim();
                Assert.AreEqual(192, publicKey.Length);

                var signResult = await client.CallToolAsync(
                    McpToolNames.BbsSign,
                    new Dictionary<string, object?> { ["messages"] = Messages, ["secretKeyFile"] = secretPath, ["publicKey"] = publicKey },
                    cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
                string signature = TextOf(signResult).Trim();

                var verifyResult = await client.CallToolAsync(
                    McpToolNames.BbsVerify,
                    new Dictionary<string, object?> { ["signature"] = signature, ["messages"] = Messages, ["publicKey"] = publicKey },
                    cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
                Assert.StartsWith("VALID", TextOf(verifyResult), StringComparison.Ordinal);

                var changedResult = await client.CallToolAsync(
                    McpToolNames.BbsVerify,
                    new Dictionary<string, object?> { ["signature"] = signature, ["messages"] = "alpha\nbeta\nchanged", ["publicKey"] = publicKey },
                    cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
                Assert.StartsWith("REJECTED", TextOf(changedResult), StringComparison.Ordinal);

                var proofResult = await client.CallToolAsync(
                    McpToolNames.BbsProofGenerate,
                    new Dictionary<string, object?> { ["signature"] = signature, ["messages"] = Messages, ["disclose"] = "0,2", ["publicKey"] = publicKey },
                    cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
                string proof = TextOf(proofResult).Trim();

                var proofVerify = await client.CallToolAsync(
                    McpToolNames.BbsProofVerify,
                    new Dictionary<string, object?> { ["proof"] = proof, ["disclosedMessages"] = "0=alpha\n2=gamma", ["publicKey"] = publicKey },
                    cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
                Assert.StartsWith("VALID", TextOf(proofVerify), StringComparison.Ordinal);

                var proofTampered = await client.CallToolAsync(
                    McpToolNames.BbsProofVerify,
                    new Dictionary<string, object?> { ["proof"] = proof, ["disclosedMessages"] = "0=alpha\n2=changed", ["publicKey"] = publicKey },
                    cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
                Assert.StartsWith("REJECTED", TextOf(proofTampered), StringComparison.Ordinal);

                var missingKey = await client.CallToolAsync(
                    McpToolNames.BbsSign,
                    new Dictionary<string, object?> { ["messages"] = Messages, ["secretKeyFile"] = secretPath + ".missing", ["publicKey"] = publicKey },
                    cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
                Assert.StartsWith("Error: could not read the secret key", TextOf(missingKey), StringComparison.Ordinal);
            }).ConfigureAwait(false);
        }
        finally
        {
            File.Delete(secretPath);
        }
    }


    private const string JwtSeed = "mcp-jwt";


    private static Dictionary<string, object?> JwtProveArguments(string tokenPath, string proofPath)
    {
        LongfellowJwtTestVectors.TokenVector vector = LongfellowJwtTestVectors.ErikaToken;

        return new Dictionary<string, object?>
        {
            ["tokenFile"] = tokenPath,
            ["issuerKeyX"] = vector.PkX,
            ["issuerKeyY"] = vector.PkY,
            ["attributes"] = "given_name=Erika",
            ["seed"] = JwtSeed,
            ["proofFile"] = proofPath
        };
    }


    private static Dictionary<string, object?> JwtVerifyArguments(string proofPath, string presentationPath, string attributes)
    {
        LongfellowJwtTestVectors.TokenVector vector = LongfellowJwtTestVectors.ErikaToken;

        return new Dictionary<string, object?>
        {
            ["proofFile"] = proofPath,
            ["presentationFile"] = presentationPath,
            ["issuerKeyX"] = vector.PkX,
            ["issuerKeyY"] = vector.PkY,
            ["attributes"] = attributes,
            ["seed"] = JwtSeed
        };
    }


    /// <summary>
    /// Spawns the MCP server, runs the body against a connected client, and disposes the client. Retries the
    /// whole connect-and-run sequence on a transient transport drop (the spawned server process exiting
    /// before it is ready); assertion failures and any other error propagate on the first occurrence.
    /// </summary>
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
                McpClient client = await McpClient.CreateAsync(
                    CreateTransport(executable),
                    NoInitializationTimeout,
                    cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
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


    /// <summary>
    /// A dropped stdio transport or a server process that exited before the handshake completed; both are
    /// transient spawn races on a loaded runner, not a protocol fault. An initialization timeout is
    /// deliberately NOT transient: the SDK's init deadline is disabled, so a timeout here would be a real
    /// fault to surface rather than retry.
    /// </summary>
    private static bool IsTransientTransport(Exception exception)
    {
        return exception is ClientTransportClosedException
            || exception is IOException
            || exception.InnerException is IOException;
    }


    /// <summary>Creates the stdio transport that spawns the Veridical executable in MCP server mode.</summary>
    private static StdioClientTransport CreateTransport(string executable)
    {
        return new StdioClientTransport(new StdioClientTransportOptions
        {
            Name = "Veridical MCP Server",
            Command = executable,
            Arguments = ["-mcp"]
        });
    }


    /// <summary>Concatenates the text content blocks of a tool-call result.</summary>
    private static string TextOf(CallToolResult result)
    {
        return string.Concat(result.Content.OfType<TextContentBlock>().Select(block => block.Text));
    }
}
