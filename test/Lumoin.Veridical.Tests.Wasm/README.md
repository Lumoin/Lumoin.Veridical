# Lumoin.Veridical.Tests.Wasm

Runs the MSTest tests of `Lumoin.Veridical.Tests` inside the browser-wasm .NET runtime (`dotnet.wasm`)
under Node, so the WebAssembly backends execute as WebAssembly rather than being skipped on the
host CPU. The process exit code is zero when every selected test passed.

The project references the test project, registers its assembly with Microsoft.Testing.Platform in
`Program.cs`, and `wwwroot/main.mjs` forwards the command-line arguments to it. The MSTest packages
come transitively from the test project, whose version is set by the `MSTest.Sdk` entry in
`global.json`, so the host and the tests cannot use different versions.

## Prerequisites

- The SDK from `global.json`.
- The `wasm-tools` workload: `dotnet workload install wasm-tools --include-previews`.
- For the ahead-of-time mode, the workload's Emscripten toolchain, which the workload installs.

## Publish and run

Both modes are trimmed publishes; the mode is chosen by the `RunAOTCompilation` property at publish time.

Interpreter (the default; faster to build, slower to run):

```
dotnet publish test/Lumoin.Veridical.Tests.Wasm -c Release -p:RunAOTCompilation=false
```

Ahead-of-time compiled (the libraries run as WebAssembly machine code; needs the workload's Emscripten toolchain):

```
dotnet publish test/Lumoin.Veridical.Tests.Wasm -c Release -p:RunAOTCompilation=true
```

Then run the published bundle with the Node that ships with the workload (under
`packs/Microsoft.NET.Runtime.Emscripten.*.Node.*`):

```
node --experimental-wasm-exnref test/Lumoin.Veridical.Tests.Wasm/bin/Release/net11.0/publish/wwwroot/main.mjs --output Detailed --filter "FullyQualifiedName~Blake3CrossBackendAgreementTests" --trx-out TestResults/wasm.trx
```

Everything after the script name is passed to Microsoft.Testing.Platform, except `--trx-out <path>`, which
`main.mjs` consumes: it makes the run write a TRX report inside the runtime's in-memory file system and, after
the run, copies that report to `<path>` on the host disk so per-test outcomes can be read. `--filter` takes
MSTest filter expressions over `FullyQualifiedName`; `--list-tests` does not enumerate tests in this runtime, so
use `--filter` to select them. The full suite is not intended to run here, because the runtime is single threaded.
Test data that the selected classes need is compiled into the test assembly; fixture files that other
classes read from disk are not staged into the virtual file system.

## CoreCLR on WebAssembly

.NET 11 browser apps run on Mono. CoreCLR on WebAssembly is experimental in .NET 11, and the host can be
published for it to see how far it gets:

```
dotnet publish test/Lumoin.Veridical.Tests.Wasm -c Release -p:UseMonoRuntime=false -p:RunAOTCompilation=false -p:PublishTrimmed=false
```

The trimming step is switched off because a trimmed CoreCLR publish of this host fails while generating the
native interop tables, which cannot map by-value `System.Guid` and `ComVariant` parameters. The published bundle is
run the same way as the Mono bundle. On this runtime `PackedSimd.IsSupported` is false, so the WebAssembly
backend tests report as not executed and only the portable paths are exercised. Libraries that cannot
initialise under Mono's eager type-initializer ordering, such as CsCheck, run under CoreCLR, which initialises
types lazily. The `coreclr` leg of the workflow is allowed to fail.
