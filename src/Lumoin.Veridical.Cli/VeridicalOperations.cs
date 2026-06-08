using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Hashing;
using System;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace Lumoin.Veridical.Cli;

/// <summary>
/// The operations behind the CLI subcommands and the MCP tools — one
/// implementation each, shared so the command-line and the agent surface never
/// drift. Operations are deterministic and self-contained (no file or network
/// I/O beyond what a caller passes in), which is what lets the self-test double
/// as a native-AOT conformance harness.
/// </summary>
internal static class VeridicalOperations
{
    private const int ScalarSize = Scalar.SizeBytes;

    //BLAKE3 of the empty input (256-bit), an official test vector — an absolute
    //anchor that the hashing codegen is correct on whatever target this runs on.
    private const string Blake3EmptyHash = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";


    /// <summary>A one-line description of the host OS, as the runtime reports it.</summary>
    public static string PlatformDescription => RuntimeInformation.OSDescription;


    /// <summary>
    /// Returns platform and backend information: the OS, the process architecture,
    /// and whether the scalar arithmetic for each wired curve is hardware-accelerated
    /// (a SIMD backend was selected) on this host.
    /// </summary>
    public static string Info()
    {
        var builder = new StringBuilder();
        builder.Append("OS:           ").AppendLine(PlatformDescription);
        builder.Append("Architecture: ").AppendLine(RuntimeInformation.ProcessArchitecture.ToString());
        builder.Append("Runtime:      ").AppendLine(RuntimeInformation.FrameworkDescription);

        using ScalarArithmeticBackend bls = Bls12Curve381ManagedScalarBackend.Create();
        using ScalarArithmeticBackend bn = Bn254ManagedScalarBackend.Create();

        builder.Append("BLS12-381 scalar backend: ").AppendLine(bls.IsHardwareAccelerated ? "SIMD (hardware-accelerated)" : "BigInteger reference");
        builder.Append("BN254 scalar backend:     ").Append(bn.IsHardwareAccelerated ? "SIMD (hardware-accelerated)" : "BigInteger reference");

        return builder.ToString();
    }


    /// <summary>Returns the lowercase-hex BLAKE3-256 digest of <paramref name="input"/>.</summary>
    public static string HashBlake3(ReadOnlySpan<byte> input)
    {
        Span<byte> digest = stackalloc byte[32];
        Blake3.Hash(input, digest);

        return Convert.ToHexStringLower(digest);
    }


    /// <summary>Returns the BLAKE3-256 digest of the UTF-8 bytes of <paramref name="text"/>.</summary>
    public static string HashBlake3Text(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        int byteCount = Encoding.UTF8.GetByteCount(text);
        Span<byte> bytes = byteCount <= 1024 ? stackalloc byte[byteCount] : new byte[byteCount];
        Encoding.UTF8.GetBytes(text, bytes);

        return HashBlake3(bytes);
    }


    /// <summary>
    /// Runs the known-answer conformance vectors and returns whether all passed plus
    /// a human-readable report. Designed to run under native AOT on every target RID:
    /// it validates that the AOT-compiled BLAKE3, field arithmetic, and the
    /// lane-interleaved batch multiply still compute the right answers.
    /// </summary>
    public static (bool Ok, string Report) RunSelfTest()
    {
        var report = new StringBuilder();
        bool ok = true;

        //BLAKE3 known-answer (empty input).
        string emptyHash = HashBlake3(ReadOnlySpan<byte>.Empty);
        bool blakeOk = string.Equals(emptyHash, Blake3EmptyHash, StringComparison.Ordinal);
        ok &= blakeOk;
        report.Append(Line(blakeOk, "BLAKE3 empty-input known-answer"));

        ok &= CheckCurve(Bls12Curve381ManagedScalarBackend.Create(), "BLS12-381", report);
        ok &= CheckCurve(Bn254ManagedScalarBackend.Create(), "BN254", report);

        report.AppendLine();
        report.Append(ok ? "All conformance vectors passed." : "CONFORMANCE FAILURE — see above.");

        return (ok, report.ToString());
    }


    //Runs the field-arithmetic and batch-multiply vectors for one curve's backend.
    private static bool CheckCurve(ScalarArithmeticBackend backend, string label, StringBuilder report)
    {
        using(backend)
        {
            CurveParameterSet curve = backend.Curve;
            bool accel = backend.IsHardwareAccelerated;
            string suffix = accel ? "SIMD" : "reference";

            //2 · 3 = 6 (small operands stay below the modulus, so the canonical
            //product is just the integer product — an absolute correctness anchor).
            Span<byte> two = ScalarOf(2);
            Span<byte> three = ScalarOf(3);
            Span<byte> six = ScalarOf(6);
            Span<byte> product = stackalloc byte[ScalarSize];
            backend.Multiply(two, three, product, curve);
            bool mulOk = product.SequenceEqual(six);

            //7 · 7⁻¹ = 1 (exercises the Fermat inversion ladder and the multiply).
            Span<byte> seven = ScalarOf(7);
            Span<byte> inverse = stackalloc byte[ScalarSize];
            backend.Invert(seven, inverse, curve);
            Span<byte> shouldBeOne = stackalloc byte[ScalarSize];
            backend.Multiply(seven, inverse, shouldBeOne, curve);
            bool invOk = shouldBeOne.SequenceEqual(ScalarOf(1));

            //Batch multiply ≡ element-wise single multiply. The count crosses the
            //lane-group boundary of every backend (AVX-512 octet + tail, AVX2 quartet
            //+ tail, NEON pair + tail), so this drives the lane-interleaved kernel and
            //its serial remainder and asserts they match the single-element path.
            bool batchOk = CheckBatchMultiply(backend, curve);

            bool curveOk = mulOk && invOk && batchOk;
            report.Append(Line(mulOk, $"{label} scalar multiply ({suffix})"));
            report.Append(Line(invOk, $"{label} scalar invert ({suffix})"));
            report.Append(Line(batchOk, $"{label} batch multiply ≡ single ({suffix})"));

            return curveOk;
        }
    }


    private static bool CheckBatchMultiply(ScalarArithmeticBackend backend, CurveParameterSet curve)
    {
        const int Count = 11;
        Span<byte> lefts = stackalloc byte[Count * ScalarSize];
        Span<byte> rights = stackalloc byte[Count * ScalarSize];
        Span<byte> batched = stackalloc byte[Count * ScalarSize];
        Span<byte> single = stackalloc byte[ScalarSize];

        for(int i = 0; i < Count; i++)
        {
            //Distinct small operands per slot; all below the modulus.
            WriteScalar(lefts.Slice(i * ScalarSize, ScalarSize), (ulong)((i * 7) + 1));
            WriteScalar(rights.Slice(i * ScalarSize, ScalarSize), (ulong)((i * 11) + 3));
        }

        backend.BatchMultiply(lefts, rights, batched, Count, curve);

        for(int i = 0; i < Count; i++)
        {
            backend.Multiply(lefts.Slice(i * ScalarSize, ScalarSize), rights.Slice(i * ScalarSize, ScalarSize), single, curve);
            if(!single.SequenceEqual(batched.Slice(i * ScalarSize, ScalarSize)))
            {
                return false;
            }
        }

        return true;
    }


    private static string Line(bool ok, string name) => $"  [{(ok ? "PASS" : "FAIL")}] {name}\n";


    //A canonical big-endian scalar carrying a small non-negative integer value.
    private static byte[] ScalarOf(ulong value)
    {
        byte[] bytes = new byte[ScalarSize];
        WriteScalar(bytes, value);

        return bytes;
    }


    private static void WriteScalar(Span<byte> destination, ulong value)
    {
        destination.Clear();
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(destination[(ScalarSize - sizeof(ulong))..], value);
    }
}
