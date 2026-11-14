namespace Lumoin.Veridical.Tests.TestInfrastructure;

/// <summary>
/// Gates for tests that depend on a capability the browser-wasm runtime does not have. Each
/// helper throws <see cref="AssertInconclusiveException"/> with the cause when the test is running
/// under WebAssembly, so the test is reported as not executed there and runs unchanged on every
/// other host. They follow the pattern of <see cref="InstructionSetRequirements"/>: call from
/// <see cref="TestInitializeAttribute"/> or as the first line of a test method.
/// </summary>
internal static class RuntimeRequirements
{
    /// <summary>Throws <see cref="AssertInconclusiveException"/> under WebAssembly, where the runtime cannot start child processes.</summary>
    public static void RequireProcessSpawning()
    {
        if(OperatingSystem.IsBrowser())
        {
            Assert.Inconclusive("The browser-wasm runtime cannot start child processes; skipping the subprocess test.");
        }
    }


    /// <summary>
    /// Throws <see cref="AssertInconclusiveException"/> under WebAssembly for tests that generate hundreds
    /// of proofs to compare byte distributions statistically. The runtime is single threaded and interprets
    /// the library, so the sampling takes far longer than on a native host, and long runs of it
    /// reach an assertion inside the Mono interpreter that terminates the process.
    /// </summary>
    public static void RequireStatisticalSampleBudget()
    {
        if(OperatingSystem.IsBrowser())
        {
            Assert.Inconclusive("Statistical proof sampling exceeds the interpreter's budget under browser-wasm; skipping the sampling test.");
        }
    }


    /// <summary>
    /// Throws <see cref="AssertInconclusiveException"/> under WebAssembly for tests that prove or evaluate a
    /// large circuit end to end, such as a full signature-verification circuit or a hash-compression
    /// round chain, which does not finish within the stall limit on the single-threaded interpreter.
    /// </summary>
    public static void RequireProofThroughput()
    {
        if(OperatingSystem.IsBrowser())
        {
            Assert.Inconclusive("End-to-end circuit proving or evaluation exceeds the interpreter's budget under browser-wasm; skipping the circuit test.");
        }
    }
}
