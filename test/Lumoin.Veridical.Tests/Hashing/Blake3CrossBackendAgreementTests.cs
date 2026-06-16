using CsCheck;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Hashing.Internal;
using Lumoin.Veridical.Tests.Hashing.Blake3Vectors;
using System.Text;

namespace Lumoin.Veridical.Tests.Hashing;

/// <summary>
/// Cross-backend agreement tests for the accelerated BLAKE3 backends.
/// Each accelerated backend is exercised under the canonical test
/// vector set and against a CsCheck-driven random-input sweep; both
/// gates assert byte-faithful equality with the portable scalar
/// baseline. Tests skip via <see cref="Assert.Inconclusive(string)"/>
/// when the backend's instruction set is unavailable on the host CPU,
/// so the suite passes uniformly across the AVX2-only laptops,
/// AVX-512 servers, and ARM64 boxes the library targets.
/// </summary>
[TestClass]
internal sealed class Blake3CrossBackendAgreementTests
{
    private static readonly Blake3Backend PortableBackend = Blake3PortableBackend.GetBackend();
    private const long RandomSweepIterations = 100;


    public static IEnumerable<object[]> AllVectors =>
        Blake3CanonicalVectors.All.Select(v => new object[] { v });


    [TestMethod]
    [DynamicData(nameof(AllVectors))]
    public void Avx2HashModeMatchesCanonicalVector(Blake3HashVector vector)
    {
        if(!Blake3Avx2Backend.IsSupported)
        {
            Assert.Inconclusive("AVX2 is not supported on this host CPU; skipping the AVX2 conformance test.");
        }

        RunHashModeAgainstCanonical(Blake3Avx2Backend.GetBackend(), vector);
    }


    [TestMethod]
    [DynamicData(nameof(AllVectors))]
    public void Avx2KeyedHashModeMatchesCanonicalVector(Blake3HashVector vector)
    {
        if(!Blake3Avx2Backend.IsSupported)
        {
            Assert.Inconclusive("AVX2 is not supported on this host CPU; skipping the AVX2 conformance test.");
        }

        RunKeyedHashModeAgainstCanonical(Blake3Avx2Backend.GetBackend(), vector);
    }


    [TestMethod]
    [DynamicData(nameof(AllVectors))]
    public void Avx2DeriveKeyModeMatchesCanonicalVector(Blake3HashVector vector)
    {
        if(!Blake3Avx2Backend.IsSupported)
        {
            Assert.Inconclusive("AVX2 is not supported on this host CPU; skipping the AVX2 conformance test.");
        }

        RunDeriveKeyModeAgainstCanonical(Blake3Avx2Backend.GetBackend(), vector);
    }


    [TestMethod]
    [DynamicData(nameof(AllVectors))]
    public void Avx512HashModeMatchesCanonicalVector(Blake3HashVector vector)
    {
        if(!Blake3Avx512Backend.IsSupported)
        {
            Assert.Inconclusive("AVX-512F is not supported on this host CPU; skipping the AVX-512 conformance test.");
        }

        RunHashModeAgainstCanonical(Blake3Avx512Backend.GetBackend(), vector);
    }


    [TestMethod]
    [DynamicData(nameof(AllVectors))]
    public void Avx512KeyedHashModeMatchesCanonicalVector(Blake3HashVector vector)
    {
        if(!Blake3Avx512Backend.IsSupported)
        {
            Assert.Inconclusive("AVX-512F is not supported on this host CPU; skipping the AVX-512 conformance test.");
        }

        RunKeyedHashModeAgainstCanonical(Blake3Avx512Backend.GetBackend(), vector);
    }


    [TestMethod]
    [DynamicData(nameof(AllVectors))]
    public void Avx512DeriveKeyModeMatchesCanonicalVector(Blake3HashVector vector)
    {
        if(!Blake3Avx512Backend.IsSupported)
        {
            Assert.Inconclusive("AVX-512F is not supported on this host CPU; skipping the AVX-512 conformance test.");
        }

        RunDeriveKeyModeAgainstCanonical(Blake3Avx512Backend.GetBackend(), vector);
    }


    [TestMethod]
    [DynamicData(nameof(AllVectors))]
    public void NeonHashModeMatchesCanonicalVector(Blake3HashVector vector)
    {
        if(!Blake3NeonBackend.IsSupported)
        {
            Assert.Inconclusive("AArch64 NEON is not supported on this host CPU; skipping the NEON conformance test.");
        }

        RunHashModeAgainstCanonical(Blake3NeonBackend.GetBackend(), vector);
    }


    [TestMethod]
    [DynamicData(nameof(AllVectors))]
    public void NeonKeyedHashModeMatchesCanonicalVector(Blake3HashVector vector)
    {
        if(!Blake3NeonBackend.IsSupported)
        {
            Assert.Inconclusive("AArch64 NEON is not supported on this host CPU; skipping the NEON conformance test.");
        }

        RunKeyedHashModeAgainstCanonical(Blake3NeonBackend.GetBackend(), vector);
    }


    [TestMethod]
    [DynamicData(nameof(AllVectors))]
    public void NeonDeriveKeyModeMatchesCanonicalVector(Blake3HashVector vector)
    {
        if(!Blake3NeonBackend.IsSupported)
        {
            Assert.Inconclusive("AArch64 NEON is not supported on this host CPU; skipping the NEON conformance test.");
        }

        RunDeriveKeyModeAgainstCanonical(Blake3NeonBackend.GetBackend(), vector);
    }


    [TestMethod]
    [DynamicData(nameof(AllVectors))]
    public void WasmPackedSimdHashModeMatchesCanonicalVector(Blake3HashVector vector)
    {
        if(!Blake3WasmPackedSimdBackend.IsSupported)
        {
            Assert.Inconclusive("WebAssembly PackedSimd is not supported on this host; skipping the WASM conformance test.");
        }

        RunHashModeAgainstCanonical(Blake3WasmPackedSimdBackend.GetBackend(), vector);
    }


    [TestMethod]
    [DynamicData(nameof(AllVectors))]
    public void WasmPackedSimdKeyedHashModeMatchesCanonicalVector(Blake3HashVector vector)
    {
        if(!Blake3WasmPackedSimdBackend.IsSupported)
        {
            Assert.Inconclusive("WebAssembly PackedSimd is not supported on this host; skipping the WASM conformance test.");
        }

        RunKeyedHashModeAgainstCanonical(Blake3WasmPackedSimdBackend.GetBackend(), vector);
    }


    [TestMethod]
    [DynamicData(nameof(AllVectors))]
    public void WasmPackedSimdDeriveKeyModeMatchesCanonicalVector(Blake3HashVector vector)
    {
        if(!Blake3WasmPackedSimdBackend.IsSupported)
        {
            Assert.Inconclusive("WebAssembly PackedSimd is not supported on this host; skipping the WASM conformance test.");
        }

        RunDeriveKeyModeAgainstCanonical(Blake3WasmPackedSimdBackend.GetBackend(), vector);
    }


    [TestMethod]
    public void Avx2AgreesWithPortableOnRandomInputs()
    {
        if(!Blake3Avx2Backend.IsSupported)
        {
            Assert.Inconclusive("AVX2 is not supported on this host CPU; skipping the random sweep.");
        }

        SweepAgreement(Blake3Avx2Backend.GetBackend());
    }


    [TestMethod]
    public void Avx512AgreesWithPortableOnRandomInputs()
    {
        if(!Blake3Avx512Backend.IsSupported)
        {
            Assert.Inconclusive("AVX-512F is not supported on this host CPU; skipping the random sweep.");
        }

        SweepAgreement(Blake3Avx512Backend.GetBackend());
    }


    [TestMethod]
    public void NeonAgreesWithPortableOnRandomInputs()
    {
        if(!Blake3NeonBackend.IsSupported)
        {
            Assert.Inconclusive("AArch64 NEON is not supported on this host CPU; skipping the random sweep.");
        }

        SweepAgreement(Blake3NeonBackend.GetBackend());
    }


    [TestMethod]
    public void WasmPackedSimdAgreesWithPortableOnRandomInputs()
    {
        if(!Blake3WasmPackedSimdBackend.IsSupported)
        {
            Assert.Inconclusive("WebAssembly PackedSimd is not supported on this host; skipping the random sweep.");
        }

        SweepAgreement(Blake3WasmPackedSimdBackend.GetBackend());
    }


    private static void RunHashModeAgainstCanonical(Blake3Backend backend, Blake3HashVector vector)
    {
        byte[] input = BuildCanonicalInput(vector.InputLength);
        byte[] expected = Convert.FromHexString(vector.ExpectedHashHex);
        byte[] actual = new byte[expected.Length];

        using Blake3Hasher hasher = Blake3Hasher.Create(backend);
        hasher.Update(input);
        hasher.FinalizeXof(actual);

        CollectionAssert.AreEqual(expected, actual);
    }


    private static void RunKeyedHashModeAgainstCanonical(Blake3Backend backend, Blake3HashVector vector)
    {
        byte[] input = BuildCanonicalInput(vector.InputLength);
        byte[] keyBytes = Encoding.ASCII.GetBytes(Blake3CanonicalVectors.Key);
        byte[] expected = Convert.FromHexString(vector.ExpectedKeyedHashHex);
        byte[] actual = new byte[expected.Length];

        using Blake3Hasher hasher = Blake3Hasher.CreateKeyed(keyBytes, backend);
        hasher.Update(input);
        hasher.FinalizeXof(actual);

        CollectionAssert.AreEqual(expected, actual);
    }


    private static void RunDeriveKeyModeAgainstCanonical(Blake3Backend backend, Blake3HashVector vector)
    {
        byte[] keyMaterial = BuildCanonicalInput(vector.InputLength);
        byte[] expected = Convert.FromHexString(vector.ExpectedDeriveKeyHex);
        byte[] actual = new byte[expected.Length];

        using Blake3Hasher hasher = Blake3Hasher.CreateDeriveKey(
            Blake3CanonicalVectors.DeriveKeyContext, backend);
        hasher.Update(keyMaterial);
        hasher.FinalizeXof(actual);

        CollectionAssert.AreEqual(expected, actual);
    }


    /// <summary>
    /// Hashes random byte payloads of varying sizes via both the
    /// portable and the candidate backend; asserts byte equality. Sizes
    /// include lengths that exercise the chunk-parallel SIMD path
    /// (multi-chunk inputs).
    /// </summary>
    private static void SweepAgreement(Blake3Backend backend)
    {
        Gen<int> sizeGen = Gen.Int[0, 32768];
        Gen<byte[]> inputGen = sizeGen.SelectMany(size => Gen.Byte.Array[size]);

        inputGen.Sample(
            input => HashesAgree(backend, input),
            iter: RandomSweepIterations);
    }


    private static bool HashesAgree(Blake3Backend backend, byte[] input)
    {
        byte[] portableOut = new byte[Blake3Hasher.DefaultOutputSizeBytes];
        byte[] backendOut = new byte[Blake3Hasher.DefaultOutputSizeBytes];

        using(Blake3Hasher portableHasher = Blake3Hasher.Create(PortableBackend))
        {
            portableHasher.Update(input);
            portableHasher.Finalize(portableOut);
        }

        using(Blake3Hasher backendHasher = Blake3Hasher.Create(backend))
        {
            backendHasher.Update(input);
            backendHasher.Finalize(backendOut);
        }

        return portableOut.AsSpan().SequenceEqual(backendOut);
    }


    private static byte[] BuildCanonicalInput(int length)
    {
        byte[] input = new byte[length];
        for(int i = 0; i < length; i++)
        {
            input[i] = (byte)(i % 251);
        }

        return input;
    }
}