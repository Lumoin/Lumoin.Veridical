using System.Reflection;
using Microsoft.Testing.Extensions;
using Microsoft.Testing.Platform.Builder;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Lumoin.Veridical.Tests.Wasm;

/// <summary>
/// Entry point that runs the MSTest tests of <c>Lumoin.Veridical.Tests</c> inside the
/// browser-wasm runtime. The command-line arguments are the Microsoft.Testing.Platform
/// arguments forwarded by <c>wwwroot/main.mjs</c>, and the returned value becomes the
/// process exit code.
/// </summary>
internal static class Program
{
    /// <summary>
    /// The simple name of the test assembly. The test classes are internal, so the assembly
    /// is resolved by name rather than through a type reference.
    /// </summary>
    private const string TestAssemblyName = "Lumoin.Veridical.Tests";


    /// <summary>
    /// Registers the test assembly with the Microsoft.Testing.Platform builder and runs it.
    /// </summary>
    /// <param name="args">The Microsoft.Testing.Platform command-line arguments.</param>
    /// <returns>The platform exit code; zero when every selected test passed.</returns>
    public static async Task<int> Main(string[] args)
    {
        Assembly testAssembly = Assembly.Load(TestAssemblyName);
        ITestApplicationBuilder builder = await TestApplication.CreateBuilderAsync(args).ConfigureAwait(false);
        builder.AddMSTest(() => [testAssembly]);
        builder.AddTrxReportProvider();

        using ITestApplication application = await builder.BuildAsync().ConfigureAwait(false);

        return await application.RunAsync().ConfigureAwait(false);
    }
}
