using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Hashing.Internal;
using Lumoin.Veridical.Tests.Hashing.Blake3Vectors;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System.Buffers;
using System.Text;

namespace Lumoin.Veridical.Tests.Hashing;

/// <summary>
/// Cross-backend agreement tests for the accelerated BLAKE3 backends.
/// Each accelerated backend is exercised under the canonical test
/// vector set and against a seeded random-input sweep; both
/// gates assert byte-faithful equality with the portable scalar
/// baseline. Tests skip via <see cref="Assert.Inconclusive(string)"/>
/// when the backend's instruction set is unavailable on the host CPU,
/// so the suite passes uniformly across the AVX2-only laptops,
/// AVX-512 servers, and ARM64 boxes the library targets.
/// </summary>
[TestClass]
internal sealed class Blake3CrossBackendAgreementTests
{
    /// <summary>The portable backend every accelerated backend is compared with.</summary>
    private static Blake3Backend PortableBackend { get; } = Blake3PortableBackend.GetBackend();

    /// <summary>The number of seeded random-size cases in the sweep.</summary>
    private const long RandomSweepIterations = 100;

    /// <summary>
    /// The largest payload size of the sweep: 32 chunks of 1024 bytes, enough for several steps of
    /// the widest (16-chunk) backend and its lane-remainder handling.
    /// </summary>
    private const int MaximumSweepSizeBytes = 32768;

    /// <summary>The seed of the size and content stream of the sweep; a failure message repeats it.</summary>
    private const ulong SweepSeed = 0xB1AC3B1AC3B1AC3UL;

    /// <summary>
    /// Payload sizes at the structural edges of BLAKE3, hashed before the random cases: the empty
    /// input, a single byte, the neighbourhoods of the 64-byte block, the 1024-byte chunk and the
    /// 4-chunk steps of the 4-wide SIMD backends, and powers of two up to the maximum so
    /// multi-chunk subtrees of every height are merged.
    /// </summary>
    private static int[] StructuralSizes { get; } =
    [
        0, 1, 63, 64, 65,
        1023, 1024, 1025,
        2048, 4095, 4096, 4097,
        8192, 16384, MaximumSweepSizeBytes,
    ];


    /// <summary>The canonical BLAKE3 test vectors, one data row each.</summary>
    public static IEnumerable<object[]> AllVectors =>
        Blake3CanonicalVectors.All.Select(v => new object[] { v });


    /// <summary>The AVX2 backend's hash mode digest matches the canonical vector.</summary>
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


    /// <summary>The AVX2 backend's keyed-hash mode digest matches the canonical vector.</summary>
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


    /// <summary>The AVX2 backend's derive-key mode digest matches the canonical vector.</summary>
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


    /// <summary>The AVX-512 backend's hash mode digest matches the canonical vector.</summary>
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


    /// <summary>The AVX-512 backend's keyed-hash mode digest matches the canonical vector.</summary>
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


    /// <summary>The AVX-512 backend's derive-key mode digest matches the canonical vector.</summary>
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


    /// <summary>The NEON backend's hash mode digest matches the canonical vector.</summary>
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


    /// <summary>The NEON backend's keyed-hash mode digest matches the canonical vector.</summary>
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


    /// <summary>The NEON backend's derive-key mode digest matches the canonical vector.</summary>
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


    /// <summary>The WASM PackedSimd backend's hash mode digest matches the canonical vector.</summary>
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


    /// <summary>The WASM PackedSimd backend's keyed-hash mode digest matches the canonical vector.</summary>
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


    /// <summary>The WASM PackedSimd backend's derive-key mode digest matches the canonical vector.</summary>
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


    /// <summary>The AVX2 backend digests agree with the portable backend over the structural and seeded random sizes.</summary>
    [TestMethod]
    public void Avx2AgreesWithPortableOnRandomInputs()
    {
        if(!Blake3Avx2Backend.IsSupported)
        {
            Assert.Inconclusive("AVX2 is not supported on this host CPU; skipping the random sweep.");
        }

        SweepAgreement(Blake3Avx2Backend.GetBackend());
    }


    /// <summary>The AVX-512 backend digests agree with the portable backend over the structural and seeded random sizes.</summary>
    [TestMethod]
    public void Avx512AgreesWithPortableOnRandomInputs()
    {
        if(!Blake3Avx512Backend.IsSupported)
        {
            Assert.Inconclusive("AVX-512F is not supported on this host CPU; skipping the random sweep.");
        }

        SweepAgreement(Blake3Avx512Backend.GetBackend());
    }


    /// <summary>The NEON backend digests agree with the portable backend over the structural and seeded random sizes.</summary>
    [TestMethod]
    public void NeonAgreesWithPortableOnRandomInputs()
    {
        if(!Blake3NeonBackend.IsSupported)
        {
            Assert.Inconclusive("AArch64 NEON is not supported on this host CPU; skipping the random sweep.");
        }

        SweepAgreement(Blake3NeonBackend.GetBackend());
    }


    /// <summary>The WASM PackedSimd backend digests agree with the portable backend over the structural and seeded random sizes.</summary>
    [TestMethod]
    public void WasmPackedSimdAgreesWithPortableOnRandomInputs()
    {
        if(!Blake3WasmPackedSimdBackend.IsSupported)
        {
            Assert.Inconclusive("WebAssembly PackedSimd is not supported on this host; skipping the random sweep.");
        }

        SweepAgreement(Blake3WasmPackedSimdBackend.GetBackend());
    }


    /// <summary>Hashes the canonical input of the vector in hash mode and compares the digest with the vector.</summary>
    private static void RunHashModeAgainstCanonical(Blake3Backend backend, Blake3HashVector vector)
    {
        byte[] input = BuildCanonicalInput(vector.InputLength);
        byte[] expected = Convert.FromHexString(vector.ExpectedHashHex);
        byte[] actual = new byte[expected.Length];

        using Blake3Hasher hasher = Blake3Hasher.Create(backend);
        hasher.Update(input);
        hasher.FinalizeXof(actual);

        Assert.AreSequenceEqual(expected, actual);
    }


    /// <summary>Hashes the canonical input of the vector in keyed-hash mode and compares the digest with the vector.</summary>
    private static void RunKeyedHashModeAgainstCanonical(Blake3Backend backend, Blake3HashVector vector)
    {
        byte[] input = BuildCanonicalInput(vector.InputLength);
        byte[] keyBytes = Encoding.ASCII.GetBytes(Blake3CanonicalVectors.Key);
        byte[] expected = Convert.FromHexString(vector.ExpectedKeyedHashHex);
        byte[] actual = new byte[expected.Length];

        using Blake3Hasher hasher = Blake3Hasher.CreateKeyed(keyBytes, backend);
        hasher.Update(input);
        hasher.FinalizeXof(actual);

        Assert.AreSequenceEqual(expected, actual);
    }


    /// <summary>Derives a key from the canonical key material of the vector and compares it with the vector.</summary>
    private static void RunDeriveKeyModeAgainstCanonical(Blake3Backend backend, Blake3HashVector vector)
    {
        byte[] keyMaterial = BuildCanonicalInput(vector.InputLength);
        byte[] expected = Convert.FromHexString(vector.ExpectedDeriveKeyHex);
        byte[] actual = new byte[expected.Length];

        using Blake3Hasher hasher = Blake3Hasher.CreateDeriveKey(
            Blake3CanonicalVectors.DeriveKeyContext, backend);
        hasher.Update(keyMaterial);
        hasher.FinalizeXof(actual);

        Assert.AreSequenceEqual(expected, actual);
    }


    /// <summary>
    /// Hashes payloads of varying sizes via both the portable and the candidate backend and
    /// asserts byte equality. The sizes are the structural edges of BLAKE3 followed by seeded
    /// random sizes in [0, 32768], and the content comes from a seeded stream, so a failure
    /// message reproduces the exact input. The sizes include lengths that exercise the
    /// chunk-parallel SIMD path (multi-chunk inputs).
    /// </summary>
    private static void SweepAgreement(Blake3Backend backend)
    {
        SeededByteStream stream = new(SweepSeed);
        using IMemoryOwner<byte> inputOwner = BaseMemoryPool.Shared.Rent(MaximumSweepSizeBytes);

        foreach(int size in StructuralSizes)
        {
            AssertAgreement(backend, stream, inputOwner.Memory.Span[..size], $"structural size {size}");
        }

        for(long iteration = 0; iteration < RandomSweepIterations; iteration++)
        {
            int size = stream.NextInt(0, MaximumSweepSizeBytes);
            AssertAgreement(backend, stream, inputOwner.Memory.Span[..size], $"random iteration {iteration}, size {size}");
        }
    }


    /// <summary>Fills the input from the stream and fails with the seed and case when the digests differ.</summary>
    private static void AssertAgreement(Blake3Backend backend, SeededByteStream stream, Span<byte> input, string where)
    {
        stream.Fill(input);
        if(!HashesAgree(backend, input))
        {
            Assert.Fail($"The backend digest differed from the portable digest at {where} (seed 0x{SweepSeed:X16}).");
        }
    }


    /// <summary>Hashes the input with the portable and the candidate backend and compares the digests.</summary>
    private static bool HashesAgree(Blake3Backend backend, ReadOnlySpan<byte> input)
    {
        using IMemoryOwner<byte> portableOwner = BaseMemoryPool.Shared.Rent(Blake3Hasher.DefaultOutputSizeBytes);
        using IMemoryOwner<byte> backendOwner = BaseMemoryPool.Shared.Rent(Blake3Hasher.DefaultOutputSizeBytes);
        Span<byte> portableOut = portableOwner.Memory.Span[..Blake3Hasher.DefaultOutputSizeBytes];
        Span<byte> backendOut = backendOwner.Memory.Span[..Blake3Hasher.DefaultOutputSizeBytes];

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

        return portableOut.SequenceEqual(backendOut);
    }


    /// <summary>Builds the canonical test input: the byte sequence 0, 1, ..., 250 repeated to the requested length.</summary>
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