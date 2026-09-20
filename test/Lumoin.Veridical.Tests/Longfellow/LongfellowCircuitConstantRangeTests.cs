using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Longfellow;
using System;
using System.Buffers;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Longfellow;

/// <summary>
/// Gates for the optional <see cref="LongfellowCanonicalRangeDelegate"/> parameter
/// added to <see cref="LongfellowCircuitReader.TryRead"/>. The delegate lets a
/// caller reject constant-table entries that lie outside the field's prime modulus
/// before they are stored in the circuit — closing the same non-canonical
/// second-encoding window as the R1CS and BBS canonicity checks. The guard is
/// opt-in at the reader layer (GF(2^128) needs none; every 16-byte pattern is
/// a valid field element), and wired on by
/// <see cref="LongfellowMdoc"/> via <c>LongfellowMdocBundles.InRangeFp256</c>
/// for the P-256 signature circuit.
/// </summary>
[TestClass]
internal sealed class LongfellowCircuitConstantRangeTests: IDisposable
{
    /// <summary>The independent compiler and circuit lifetime for this test.</summary>
    private LongfellowCircuitTestScope CircuitScope { get; } = new();

    /// <summary>Calls <see cref="Dispose"/> after each test, including when an assertion fails.</summary>
    [TestCleanup]
    public void DisposeCircuits()
    {
        Dispose();
    }


    /// <summary>Releases this test's compiler and circuit storage. Repeated calls have no effect.</summary>
    public void Dispose()
    {
        CircuitScope.Dispose();
    }


    /// <summary>The relative path from the test binary output directory to the gzipped circuit definition, matching the convention in LongfellowMdocFacadeTests.</summary>
    private const string RawGzipRelativePath = "../../../TestMaterial/Longfellow/mdoc-circuit-raw.gz";

    /// <summary>The number of bytes the Longfellow circuit wire format spends on its leading version byte.</summary>
    private const int LfFormatVersionBytes = 1;

    /// <summary>The number of header fields the Longfellow circuit wire format carries, in wire order: fieldId, nv, nc, npub_in, subfieldBoundary, ninputs, nl, numconst.</summary>
    private const int LfHeaderFieldCount = 8;

    /// <summary>The byte width of one Longfellow circuit header field on the wire (3 bytes).</summary>
    private const int LfBytesPerSizeT = LongfellowCircuitReader.BytesPerSizeT;

    /// <summary>The byte offset where the constant table begins on the wire: immediately after the header (1 + 8×3 = 25 bytes).</summary>
    private const int LfConstantTableOffset =
        LfFormatVersionBytes + LfHeaderFieldCount * LfBytesPerSizeT;

    /// <summary>
    /// The P-256 base field prime <c>p = ffffffff 00000001 00000000 00000000 00000000 ffffffff
    /// ffffffff ffffffff</c>, parsed with a leading zero digit so the 0xff high byte is not read
    /// as a negative sign by <see cref="NumberStyles.HexNumber"/> parsing.
    /// </summary>
    private static BigInteger Fp256Prime { get; } = BigInteger.Parse(
        "0ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        NumberStyles.HexNumber, CultureInfo.InvariantCulture);


    /// <summary>Verifies that the unmutated real P-256 signature circuit parses successfully when the Fp256 range guard is supplied, since all of its constant-table entries already lie below the base field prime.</summary>
    [TestMethod]
    public void RealSignatureCircuitParsesSuccessfullyWithRangeGuard()
    {
        //Baseline: the un-mutated real signature circuit must be accepted when
        //the Fp256 range guard is supplied — all of its constant-table entries
        //are below the P-256 base field prime by construction.
        byte[] rawBytes = LoadCircuitBytesOrSkip();

        bool ok = CircuitScope.TryRead(
            rawBytes,
            LongfellowMdocBundles.Point256FieldId,
            LongfellowMdocBundles.Point256ElementBytes,
            out _,
            out _,
            out _,
            LongfellowMdocBundles.InRangeFp256);

        Assert.IsTrue(ok, "The real signature circuit must parse successfully with the Fp256 range guard.");
    }


    /// <summary>Verifies that overwriting the first constant-table entry with the P-256 base field prime p makes the reader reject the circuit when the Fp256 range guard is supplied, since p is not strictly below p.</summary>
    [TestMethod]
    public void ConstantAtBaseFieldPrimeIsRejectedByRangeGuard()
    {
        //Mutation: overwrite the first constant (at LfConstantTableOffset) with
        //the P-256 base field prime p in the on-wire little-endian encoding.
        //The reader reverses to big-endian and calls InRangeFp256, which
        //evaluates p < p = false, causing TryRead to return false.
        byte[] mutated = LoadCircuitBytesOrSkip();
        WriteFirstConstantAsPrimeLittleEndian(mutated);

        bool parsed = CircuitScope.TryRead(
            mutated,
            LongfellowMdocBundles.Point256FieldId,
            LongfellowMdocBundles.Point256ElementBytes,
            out _,
            out _,
            out _,
            LongfellowMdocBundles.InRangeFp256);

        Assert.IsFalse(parsed,
            "A constant equal to the base field prime must be rejected by the range guard.");
    }


    /// <summary>Verifies that the same constant-table mutation (first constant set to p) is accepted when no range guard is supplied, confirming the guard is opt-in at the reader layer rather than always enforced.</summary>
    [TestMethod]
    public void ConstantAtBaseFieldPrimePassesWithoutRangeGuard()
    {
        //Documents that the range guard is opt-in at the reader layer: the same
        //mutated bytes (first constant = p) are accepted when no delegate is
        //supplied. The facade wires the guard on via LongfellowMdocBundles;
        //callers that do not care about field canonicity (e.g. GF(2^128) paths)
        //omit it without API change.
        byte[] mutated = LoadCircuitBytesOrSkip();
        WriteFirstConstantAsPrimeLittleEndian(mutated);

        //No range delegate — the default null argument.
        bool parsed = CircuitScope.TryRead(
            mutated,
            LongfellowMdocBundles.Point256FieldId,
            LongfellowMdocBundles.Point256ElementBytes,
            out _,
            out _,
            out _);

        Assert.IsTrue(parsed,
            "Without a range guard the circuit must be accepted even with a constant equal to p.");
    }


    /// <summary>Verifies that the mdoc facade's verify path wires the Fp256 range guard into circuit parsing: a signature circuit whose first constant equals the base field prime fails to parse and surfaces as an <see cref="ArgumentException"/> naming the signature circuit.</summary>
    [TestMethod]
    public void FacadeVerifyRejectsACircuitConstantAtTheBaseFieldPrime()
    {
        //Pins the FACADE wiring of the range guard: LongfellowMdoc.ParseCircuits
        //must pass LongfellowMdocBundles.InRangeFp256 for the signature circuit.
        //If a refactor drops that argument, the reader-level tests above stay
        //green (the guard is opt-in there) and only this test catches it.
        //ParseCircuits runs before any proof or statement content is touched,
        //so minimal zero-filled shapes suffice for the other arguments.
        byte[] mutated = LoadCircuitBytesOrSkip();
        WriteFirstConstantAsPrimeLittleEndian(mutated);
        LongfellowMdocCircuitSource circuits = LongfellowMdocCircuitSource.FromRawBytes(mutated);

        using IMemoryOwner<byte> proofOwner = BaseMemoryPool.Shared.Rent(LongfellowMdocProof.MinimumSizeBytes);
        proofOwner.Memory.Span.Clear();
        using LongfellowMdocProof proof = LongfellowMdocProof.FromCanonical(
            proofOwner.Memory.Span[..LongfellowMdocProof.MinimumSizeBytes], BaseMemoryPool.Shared);

        //The signature template is SignatureTemplateElementCount canonical P-256
        //base-field scalars of 32 bytes each (the class keeps that size private).
        LongfellowMdocZkSpec spec = LongfellowMdocZkSpec.Version7OneAttribute;
        int hashTemplateBytes = spec.HashTemplateElementCount * LongfellowMdocStatement.HashTemplateElementBytes;
        int signatureTemplateBytes = LongfellowMdocStatement.SignatureTemplateElementCount * WellKnownCurves.P256ScalarSizeBytes;
        using IMemoryOwner<byte> templateOwner = BaseMemoryPool.Shared.Rent(hashTemplateBytes + signatureTemplateBytes);
        templateOwner.Memory.Span.Clear();
        LongfellowMdocStatement statement = LongfellowMdocStatement.FromComponents(
            spec,
            templateOwner.Memory[..hashTemplateBytes],
            templateOwner.Memory.Slice(hashTemplateBytes, signatureTemplateBytes));

        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
            _ = LongfellowMdoc.Verify(proof, statement, circuits, ReadOnlySpan<byte>.Empty, BaseMemoryPool.Shared));
        Assert.Contains("signature circuit could not be parsed", ex.Message, StringComparison.Ordinal);
    }


    /// <summary>Overwrites the circuit's first constant-table entry, in place, with the P-256 base field prime p encoded little-endian on the wire.</summary>
    private static void WriteFirstConstantAsPrimeLittleEndian(byte[] circuit)
    {
        //p occupies the full 32-byte element width (its top byte is 0xff), so
        //TryWriteBytes fills the span exactly; the assert pins that premise.
        Span<byte> primeBigEndian = stackalloc byte[LongfellowMdocBundles.Point256ElementBytes];
        Fp256Prime.TryWriteBytes(primeBigEndian, out int written, isUnsigned: true, isBigEndian: true);
        Assert.AreEqual(LongfellowMdocBundles.Point256ElementBytes, written, "p must fill the element width exactly.");

        //Reverse BE -> LE into the first constant's slot.
        for(int i = 0; i < LongfellowMdocBundles.Point256ElementBytes; i++)
        {
            circuit[LfConstantTableOffset + i] =
                primeBigEndian[LongfellowMdocBundles.Point256ElementBytes - 1 - i];
        }
    }


    /// <summary>Loads and decompresses the real signature circuit fixture, marking the test inconclusive rather than failing when the fixture file is not present.</summary>
    private static byte[] LoadCircuitBytesOrSkip()
    {
        if(!File.Exists(RawGzipRelativePath))
        {
            Assert.Inconclusive(
                $"Circuit fixture '{RawGzipRelativePath}' not found; it is committed under TestMaterial/Longfellow (see the facade tests for provenance).");
        }

        using var input = new MemoryStream(File.ReadAllBytes(RawGzipRelativePath));
        using var gz = new GZipStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        gz.CopyTo(output);

        return output.ToArray();
    }
}
