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
internal sealed class LongfellowCircuitConstantRangeTests
{
    //Relative path from the test binary output directory to the gzipped circuit
    //definition, matching the convention in LongfellowMdocFacadeTests.
    private const string RawGzipRelativePath = "../../../TestMaterial/Longfellow/mdoc-circuit-raw.gz";

    //The Longfellow circuit serialisation format (BytesPerSizeT = 3):
    //  1 version byte
    //  8 header fields × BytesPerSizeT bytes each
    //= 1 + 8 × 3 = 25 bytes before the first constant entry.
    //
    //The eight header fields, in wire order:
    //  fieldId, nv, nc, npub_in, subfieldBoundary, ninputs, nl, numconst
    private const int LfFormatVersionBytes = 1;
    private const int LfHeaderFieldCount = 8;
    private const int LfBytesPerSizeT = LongfellowCircuitReader.BytesPerSizeT; //= 3

    //Byte offset where the constant table begins (immediately after the header).
    private const int LfConstantTableOffset =
        LfFormatVersionBytes + LfHeaderFieldCount * LfBytesPerSizeT; //= 25

    //The P-256 base field prime:
    //p = ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff ffffffff
    //Leading "0" keeps the 0xff high byte from being parsed as negative.
    private static readonly BigInteger Fp256Prime = BigInteger.Parse(
        "0ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        NumberStyles.HexNumber, CultureInfo.InvariantCulture);


    [TestMethod]
    public void RealSignatureCircuitParsesSuccessfullyWithRangeGuard()
    {
        //Baseline: the un-mutated real signature circuit must be accepted when
        //the Fp256 range guard is supplied — all of its constant-table entries
        //are below the P-256 base field prime by construction.
        byte[] rawBytes = LoadCircuitBytesOrSkip();

        bool ok = LongfellowCircuitReader.TryRead(
            rawBytes,
            LongfellowMdocBundles.Point256FieldId,
            LongfellowMdocBundles.Point256ElementBytes,
            out _,
            out _,
            out _,
            LongfellowMdocBundles.InRangeFp256);

        Assert.IsTrue(ok, "The real signature circuit must parse successfully with the Fp256 range guard.");
    }


    [TestMethod]
    public void ConstantAtBaseFieldPrimeIsRejectedByRangeGuard()
    {
        //Mutation: overwrite the first constant (at LfConstantTableOffset) with
        //the P-256 base field prime p in the on-wire little-endian encoding.
        //The reader reverses to big-endian and calls InRangeFp256, which
        //evaluates p < p = false, causing TryRead to return false.
        byte[] mutated = LoadCircuitBytesOrSkip();
        WriteFirstConstantAsPrimeLittleEndian(mutated);

        bool parsed = LongfellowCircuitReader.TryRead(
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
        bool parsed = LongfellowCircuitReader.TryRead(
            mutated,
            LongfellowMdocBundles.Point256FieldId,
            LongfellowMdocBundles.Point256ElementBytes,
            out _,
            out _,
            out _);

        Assert.IsTrue(parsed,
            "Without a range guard the circuit must be accepted even with a constant equal to p.");
    }


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
