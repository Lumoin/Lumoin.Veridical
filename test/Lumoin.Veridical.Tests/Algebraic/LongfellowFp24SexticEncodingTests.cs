using Lumoin.Base;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The gates for the FIPS 204 sextic circuit-field binding of the Ligero seam: the coordinate-0
/// <c>of_scalar</c> embedding, the per-coordinate <c>fits</c> predicate, the profile's limb-0-first
/// little-endian wire framing (the reference <c>fp24_6.h to_bytes_field</c> order), the
/// per-coordinate rejection sampler's draw pattern, the base-field subfield-run codec, and the
/// pooled-profile disposal contract.
/// </summary>
[TestClass]
internal sealed class LongfellowFp24SexticEncodingTests
{
    /// <summary>The canonical scalar container width.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The FIPS 204 prime modulus.</summary>
    private const uint Modulus = 8380417;

    /// <summary>The extension degree.</summary>
    private const int LimbCount = 6;

    /// <summary>One coordinate's width in bytes inside the canonical container.</summary>
    private const int LimbBytes = 4;

    /// <summary>The byte offset of coordinate 0 inside the canonical container.</summary>
    private const int LimbZeroOffset = ScalarSize - LimbBytes;

    /// <summary>The sextic on-wire element width: six 4-byte little-endian coordinates.</summary>
    private const int ElementBytes = LimbCount * LimbBytes;

    /// <summary>The bytes one coordinate draw consumes (the reference's 23-exact-bit sample).</summary>
    private const int LimbSampleBytes = 3;

    /// <summary>The prime profiles' third evaluation point coordinate.</summary>
    private const uint ThirdEvaluationPoint = 2;

    /// <summary>The first byte the base-field membership test checks: coordinate 5's most significant byte, just past the zero prefix.</summary>
    private const int UpperCoordinatesFirstOffset = ScalarSize - (LimbCount * LimbBytes);

    /// <summary>The last byte the base-field membership test checks: coordinate 1's least significant byte, just before coordinate 0.</summary>
    private const int UpperCoordinatesLastOffset = LimbZeroOffset - 1;

    /// <summary>The pool every gate rents from.</summary>
    private static BaseMemoryPool Pool { get; } = BaseMemoryPool.Shared;


    /// <summary>Pins <c>of_scalar</c>: the integer lands in coordinate 0 reduced modulo the prime, every other byte zero.</summary>
    [TestMethod]
    public void OfScalarEmbedsIntoCoordinateZeroReduced()
    {
        Span<byte> element = stackalloc byte[ScalarSize];
        LongfellowFp24SexticEncoding.OfScalar(ThirdEvaluationPoint, element);
        Assert.AreEqual(ThirdEvaluationPoint, BinaryPrimitives.ReadUInt32BigEndian(element.Slice(LimbZeroOffset, LimbBytes)), "The coordinate must land in limb 0.");
        for(int i = 0; i < LimbZeroOffset; i++)
        {
            Assert.AreEqual((byte)0, element[i], $"Byte {i} above coordinate 0 must stay zero.");
        }

        LongfellowFp24SexticEncoding.OfScalar(Modulus + 1, element);
        Assert.AreEqual(1u, BinaryPrimitives.ReadUInt32BigEndian(element.Slice(LimbZeroOffset, LimbBytes)), "A coordinate at or above the modulus must reduce.");
    }


    /// <summary>Pins the <c>fits</c> predicate: every coordinate strictly below the prime and the zero prefix intact.</summary>
    [TestMethod]
    public void InRangeAcceptsFieldElementsAndRejectsOverflowsAndPrefixNoise()
    {
        Span<byte> element = stackalloc byte[ScalarSize];
        for(int limb = 0; limb < LimbCount; limb++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(element.Slice(LimbZeroOffset - (limb * LimbBytes), LimbBytes), Modulus - 1);
        }

        Assert.IsTrue(LongfellowFp24SexticEncoding.InRange(element), "Maximal coordinates below the prime must be accepted.");

        BinaryPrimitives.WriteUInt32BigEndian(element.Slice(LimbZeroOffset - (3 * LimbBytes), LimbBytes), Modulus);
        Assert.IsFalse(LongfellowFp24SexticEncoding.InRange(element), "A coordinate reaching the modulus must be rejected.");

        BinaryPrimitives.WriteUInt32BigEndian(element.Slice(LimbZeroOffset - (3 * LimbBytes), LimbBytes), 0);
        element[0] = 1;
        Assert.IsFalse(LongfellowFp24SexticEncoding.InRange(element), "A dirtied zero prefix must be rejected.");
    }


    /// <summary>
    /// Pins the profile's wire framing to the reference order — six 4-byte little-endian coordinates,
    /// limb 0 first — and the round trip through <c>of_bytes_field</c> with its out-of-range rejection.
    /// </summary>
    [TestMethod]
    public void TheProfileFramesElementsLimbZeroFirstLittleEndianAndRoundTrips()
    {
        using LongfellowFieldProfile profile = LongfellowFp24SexticEncoding.CreateProfile(Pool);
        Assert.AreEqual(ElementBytes, profile.ElementBytes, "The sextic wire width must be 24 bytes.");

        //Coordinates 1..6 in limbs 0..5: the wire must read 01 00 00 00 | 02 00 00 00 | … limb 0 first.
        Span<byte> element = stackalloc byte[ScalarSize];
        for(int limb = 0; limb < LimbCount; limb++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(element.Slice(LimbZeroOffset - (limb * LimbBytes), LimbBytes), (uint)(limb + 1));
        }

        Span<byte> wire = stackalloc byte[ElementBytes];
        profile.ToBytesField(element, wire);
        for(int limb = 0; limb < LimbCount; limb++)
        {
            Assert.AreEqual((uint)(limb + 1), BinaryPrimitives.ReadUInt32LittleEndian(wire.Slice(limb * LimbBytes, LimbBytes)), $"Wire coordinate {limb} must be little-endian in reference order.");
        }

        Span<byte> restored = stackalloc byte[ScalarSize];
        Assert.IsTrue(profile.TryFromBytesField(wire, restored), "The wire bytes must decode.");
        Assert.AreSequenceEqual(element.ToArray(), restored.ToArray(), "The wire round trip must reproduce the canonical element.");

        //An out-of-range coordinate on the wire is the reference's of_bytes_field nullopt.
        BinaryPrimitives.WriteUInt32LittleEndian(wire.Slice(2 * LimbBytes, LimbBytes), Modulus);
        Assert.IsFalse(profile.TryFromBytesField(wire, restored), "An out-of-range wire coordinate must be rejected.");
    }


    /// <summary>
    /// Pins the sampler's reference draw pattern: three bytes per coordinate, 23-bit mask, a rejected
    /// draw consumes its bytes and redraws only that coordinate, and every accepted coordinate is below
    /// the prime.
    /// </summary>
    [TestMethod]
    public void TheSamplerFollowsTheReferenceDrawPatternAndRejectsPerCoordinate()
    {
        //A scripted stream: the first 3-byte draw masks to 0x7FFFFF ≥ q and must be rejected; the next
        //draw yields 1; the remaining five coordinates draw zero. Total consumption: seven draws.
        var script = new Queue<byte>([0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        int consumed = 0;
        LongfellowRandomByteSource source = destination =>
        {
            for(int i = 0; i < destination.Length; i++)
            {
                destination[i] = script.Dequeue();
                consumed++;
            }
        };

        Span<byte> element = stackalloc byte[ScalarSize];
        LongfellowFp24SexticEncoding.SampleElement(source, element);

        Assert.AreEqual((LimbCount + 1) * LimbSampleBytes, consumed, "One rejection plus six acceptances must consume seven 3-byte draws.");
        Assert.AreEqual(1u, BinaryPrimitives.ReadUInt32BigEndian(element.Slice(LimbZeroOffset, LimbBytes)), "The accepted redraw must land in coordinate 0.");
        for(int limb = 1; limb < LimbCount; limb++)
        {
            Assert.AreEqual(0u, BinaryPrimitives.ReadUInt32BigEndian(element.Slice(LimbZeroOffset - (limb * LimbBytes), LimbBytes)), $"Coordinate {limb} must hold its zero draw.");
        }

        //A deterministic counter stream: every sampled coordinate must satisfy the fits predicate.
        byte counter = 0;
        LongfellowRandomByteSource counterSource = destination =>
        {
            for(int i = 0; i < destination.Length; i++)
            {
                destination[i] = counter;
                counter += 31;
            }
        };

        LongfellowFp24SexticEncoding.SampleElement(counterSource, element);
        Assert.IsTrue(LongfellowFp24SexticEncoding.InRange(element), "A sampled element must be a field element.");
    }


    /// <summary>Pins the sextic subfield-run codec: the base-field membership predicate, the 4-byte coordinate-0 framing, and the decode's <c>fits</c> guard.</summary>
    [TestMethod]
    public void TheCodecCompressesBaseFieldElementsAndGuardsDecoding()
    {
        using LongfellowFieldProfile profile = LongfellowFp24SexticEncoding.CreateProfile(Pool);
        using LongfellowSubfieldRunCodec codec = LongfellowSubfieldRunCodec.ForFp24Sextic(profile);
        Assert.AreEqual(LimbBytes, codec.SubFieldBytes, "The sextic subfield element is one 4-byte coordinate.");

        Span<byte> element = stackalloc byte[ScalarSize];
        BinaryPrimitives.WriteUInt32BigEndian(element.Slice(LimbZeroOffset, LimbBytes), Modulus - 1);
        Assert.IsTrue(codec.InSubfield(element), "A coordinate-0-only element lies in the base field.");

        Span<byte> subfieldBytes = stackalloc byte[LimbBytes];
        codec.ToBytesSubfield(element, subfieldBytes);
        Assert.AreEqual(Modulus - 1, BinaryPrimitives.ReadUInt32LittleEndian(subfieldBytes), "The subfield framing is coordinate 0 little-endian.");

        Span<byte> restored = stackalloc byte[ScalarSize];
        Assert.IsTrue(codec.OfBytesSubfield(subfieldBytes, restored), "The subfield bytes must decode.");
        Assert.AreSequenceEqual(element.ToArray(), restored.ToArray(), "The subfield round trip must reproduce the element.");

        BinaryPrimitives.WriteUInt32BigEndian(element.Slice(LimbZeroOffset - (2 * LimbBytes), LimbBytes), 1);
        Assert.IsFalse(codec.InSubfield(element), "A nonzero upper coordinate leaves the base field.");

        //The membership test's byte range is pinned at both ends: the first checked byte (coordinate 5's
        //most significant) and the last (coordinate 1's least significant) must each break membership
        //alone, so a shrunken range at either boundary cannot slip through.
        element.Clear();
        BinaryPrimitives.WriteUInt32BigEndian(element.Slice(LimbZeroOffset, LimbBytes), Modulus - 1);
        element[UpperCoordinatesFirstOffset] = 1;
        Assert.IsFalse(codec.InSubfield(element), "A dirty first checked byte (coordinate 5) must leave the base field.");

        element[UpperCoordinatesFirstOffset] = 0;
        element[UpperCoordinatesLastOffset] = 1;
        Assert.IsFalse(codec.InSubfield(element), "A dirty last checked byte (coordinate 1) must leave the base field.");
        element[UpperCoordinatesLastOffset] = 0;
        Assert.IsTrue(codec.InSubfield(element), "The cleaned element must re-enter the base field.");

        BinaryPrimitives.WriteUInt32LittleEndian(subfieldBytes, Modulus);
        Assert.IsFalse(codec.OfBytesSubfield(subfieldBytes, restored), "An out-of-range subfield coordinate must be rejected.");
    }


    /// <summary>Pins the profile's third evaluation point to <c>of_scalar(2)</c> and the pooled-constant disposal contract.</summary>
    [TestMethod]
    public void TheThirdEvaluationPointIsTwoAndDisposalRevokesTheConstants()
    {
        LongfellowFieldProfile profile = LongfellowFp24SexticEncoding.CreateProfile(Pool);
        Span<byte> expected = stackalloc byte[ScalarSize];
        LongfellowFp24SexticEncoding.OfScalar(ThirdEvaluationPoint, expected);

        Span<byte> actual = stackalloc byte[ScalarSize];
        profile.CopyThirdEvaluationPoint(actual);
        Assert.AreSequenceEqual(expected.ToArray(), actual.ToArray(), "The third evaluation point must be of_scalar(2).");

        profile.Dispose();
        using IMemoryOwner<byte> targetOwner = Pool.Rent(ScalarSize);
        Memory<byte> target = targetOwner.Memory[..ScalarSize];
        Assert.ThrowsExactly<ObjectDisposedException>(() => profile.CopyThirdEvaluationPoint(target.Span), "A disposed profile must revoke its constants.");
    }
}
