using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The <c>sample</c> mask-then-reject seam — the field's challenge-element
/// draw, google/longfellow-zk's <c>fp_generic.h::sample</c> (<c>lib/algebra/fp_generic.h:360-371</c>)
/// dispatched from <c>RandomEngine::elt(F)</c> (<c>lib/random/random.h:39-41</c>). The byte-stream
/// consumption of this draw is load-bearing: a different bytes-per-attempt or a byte-reuse-on-reject would
/// diverge every subsequent challenge in the Fp256 signature transcript, so these gates pin it directly.
/// </summary>
/// <remarks>
/// <para>
/// Two production fields. GF(2^128) has <c>exact_bits_ == 128</c>, so <c>sample</c> draws one 16-byte block
/// and never rejects (every 16-byte sequence is a valid element); the gate asserts the result coincides
/// byte-for-byte with <c>of_bytes_field</c> over those same 16 bytes and that exactly 16 bytes are consumed.
/// The P-256 base field has <c>exact_bits_ == 256</c> (the modulus's top byte is <c>0xff</c>), so each
/// attempt draws 32 bytes, the mask-to-256-bits is a no-op, and the loop redraws a fresh 32-byte block while
/// the value reaches the modulus; the gate scripts a first block at <c>p</c> (rejected) then a block below
/// <c>p</c> (accepted) and asserts 64 bytes consumed with the second block returned, and cross-checks a
/// BigInteger oracle of the reference loop.
/// </para>
/// <para>
/// The MAC key <c>a_v = generate_mac_key</c> is deliberately NOT a <c>sample</c> draw — it is a raw 16-byte
/// <c>of_bytes_field</c> read (<c>t.bytes(buf, kBytes)</c>, <c>mdoc_zk.cc:277-282</c>) that never rejects;
/// the gate confirms <see cref="LongfellowTranscript.SqueezeFieldElementBytes(System.Span{byte})"/> consumes exactly 16 PRF
/// bytes and maps through <c>of_bytes_field</c>, distinct from the <c>sample</c> path.
/// </para>
/// </remarks>
[TestClass]
internal sealed class LongfellowSampleTests
{
    /// <summary>The in-memory canonical scalar width in bytes.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The GF(2^128) field's <c>sample</c> draw width in bytes (<c>exact_bits_ == 128</c>).</summary>
    private const int GfSampleBytes = 16;

    /// <summary>The P-256 base field's <c>sample</c> draw width in bytes (<c>exact_bits_ == 256</c>).</summary>
    private const int Fp256SampleBytes = 32;

    /// <summary>The transcript version this gate's fixtures initialise their transcripts with.</summary>
    private const int TranscriptVersion = 6;

    /// <summary>The fixed transcript seed distinguishing this gate's transcripts from every other test's.</summary>
    private static byte[] TranscriptSeed { get; } = Encoding.ASCII.GetBytes("sample-gate");

    /// <summary>The P-256 base-field prime, read from the BigInteger reference backend.</summary>
    private static BigInteger Prime { get; } = P256BaseFieldReference.FieldOrder;

    /// <summary>The validated GF(2^128) addition delegate this gate's FFT depends on.</summary>
    private static ScalarAddDelegate GfAdd { get; } = Gf2k128Backend.GetAdd();

    /// <summary>The validated GF(2^128) subtraction delegate this gate's FFT depends on.</summary>
    private static ScalarSubtractDelegate GfSubtract { get; } = Gf2k128Backend.GetSubtract();

    /// <summary>The validated GF(2^128) multiplication delegate this gate's FFT depends on.</summary>
    private static ScalarMultiplyDelegate GfMultiply { get; } = Gf2k128Backend.GetMultiply();

    /// <summary>The validated GF(2^128) inversion delegate this gate's FFT depends on.</summary>
    private static ScalarInvertDelegate GfInvert { get; } = Gf2k128Backend.GetInvert();

    /// <summary>The Fp256 field profile: <c>of_scalar(u)</c> reduces <c>u</c> mod <c>p</c>; the <c>fits</c> predicate is the <c>&lt; p</c> comparison.</summary>
    private static LongfellowFieldProfile Fp256Profile { get; } = LongfellowFieldProfile.ForFp256(OfScalar, InRange, BaseMemoryPool.Shared);


    /// <summary>Disposes the class-lifetime Fp256 profile.</summary>
    [ClassCleanup]
    public static void ClassCleanup()
    {
        Fp256Profile.Dispose();
    }


    /// <summary>
    /// Asserts the GF(2^128) <c>sample</c> draw consumes exactly one 16-byte block and coincides
    /// byte-for-byte with <c>of_bytes_field</c> over that same block, since <c>exact_bits_ == 128</c>
    /// means every 16-byte sequence is a valid element and the loop never rejects.
    /// </summary>
    [TestMethod]
    public void GfSampleCoincidesWithOfBytesFieldAndConsumesSixteenBytes()
    {
        using Lch14AdditiveFft fft = NewFft();
        using LongfellowFieldProfile profile = LongfellowFieldProfile.ForGf2k128(fft, BaseMemoryPool.Shared);

        //A fixed 16-byte little-endian block; both paths must produce the same canonical element.
        byte[] block = new byte[GfSampleBytes];
        for(int i = 0; i < GfSampleBytes; i++)
        {
            block[i] = (byte)(0x11 + (3 * i));
        }

        int consumed = 0;
        LongfellowRandomByteSource source = destination =>
        {
            block.AsSpan(0, destination.Length).CopyTo(destination);
            consumed += destination.Length;
        };

        Span<byte> sampled = stackalloc byte[ScalarSize];
        profile.SampleElement(source, sampled);

        Span<byte> viaOfBytes = stackalloc byte[ScalarSize];
        profile.FromBytesField(block, viaOfBytes);

        Assert.AreEqual(GfSampleBytes, consumed, "GF sample draws exactly one 16-byte block (exact_bits == 128, never rejects).");
        Assert.IsTrue(sampled.SequenceEqual(viaOfBytes), "GF sample must coincide with of_bytes_field over the same 16 bytes.");
    }


    /// <summary>
    /// Asserts the P-256 base-field <c>sample</c> draw rejects an at-modulus first block, redraws a fresh
    /// 32-byte block rather than reusing the rejected one, and that the accepted value matches a BigInteger
    /// oracle of the reference reject loop.
    /// </summary>
    [TestMethod]
    public void Fp256SampleRejectsAnOutOfRangeBlockAndRedraws()
    {
        //First 32-byte block encodes p (>= modulus, rejected); second encodes p - 5 (accepted). The loop
        //must consume 64 bytes total and return the second block — no reuse of the first.
        byte[] first = LittleEndian32(Prime);
        byte[] second = LittleEndian32(Prime - 5);

        int consumed = 0;
        LongfellowRandomByteSource source = destination =>
        {
            ReadOnlySpan<byte> block = consumed == 0 ? first : second;
            block[..destination.Length].CopyTo(destination);
            consumed += destination.Length;
        };

        Span<byte> sampled = stackalloc byte[ScalarSize];
        Fp256Profile.SampleElement(source, sampled);

        Assert.AreEqual(2 * Fp256SampleBytes, consumed, "An at-modulus first block is rejected, so the loop draws a fresh second 32-byte block (64 total).");
        Assert.AreEqual(Prime - 5, ReadCanonicalBigEndian(sampled), "The accepted element is the second block (the first is not reused).");

        //The BigInteger oracle of fp_generic.h::sample over the same scripted stream.
        Assert.AreEqual(SampleOracle(first, second), ReadCanonicalBigEndian(sampled), "The reject loop must match the reference's sample oracle.");
    }


    /// <summary>
    /// Asserts the P-256 base-field <c>sample</c> draw accepts an in-range first block immediately,
    /// consuming exactly 32 bytes and returning that block unchanged.
    /// </summary>
    [TestMethod]
    public void Fp256SampleAcceptsAnInRangeFirstBlockImmediately()
    {
        //A first block below the modulus is accepted on the first attempt; exactly 32 bytes are consumed.
        byte[] inRange = LittleEndian32(Prime - 1);

        int consumed = 0;
        LongfellowRandomByteSource source = destination =>
        {
            inRange.AsSpan(0, destination.Length).CopyTo(destination);
            consumed += destination.Length;
        };

        Span<byte> sampled = stackalloc byte[ScalarSize];
        Fp256Profile.SampleElement(source, sampled);

        Assert.AreEqual(Fp256SampleBytes, consumed, "An in-range first block is accepted immediately (one 32-byte draw).");
        Assert.AreEqual(Prime - 1, ReadCanonicalBigEndian(sampled), "p - 1 is the largest in-range element and must be returned.");
    }


    /// <summary>
    /// Asserts the mask to <c>exact_bits_ == 256</c> is a no-op over the full 32-byte draw: an all-<c>0xFE</c>
    /// block, already below the modulus, round-trips through <c>sample</c> with every byte preserved.
    /// </summary>
    [TestMethod]
    public void Fp256SampleMaskToExactBitsIsANoOpForTheFullThirtyTwoBytes()
    {
        //exact_bits_ == 256 spans the whole 32-byte draw, so the mask preserves every byte: an all-0xFE
        //block (< p, since p's top byte is 0xff) round-trips through sample unchanged.
        byte[] block = new byte[Fp256SampleBytes];
        block.AsSpan().Fill(0xFE);
        BigInteger value = ReadLittleEndian32(block);
        Assert.IsLessThan(Prime, value, "The 0xFE block must be below the modulus for this gate to isolate the mask.");

        LongfellowRandomByteSource source = destination => block.AsSpan(0, destination.Length).CopyTo(destination);

        Span<byte> sampled = stackalloc byte[ScalarSize];
        Fp256Profile.SampleElement(source, sampled);

        Assert.AreEqual(value, ReadCanonicalBigEndian(sampled), "The mask to 256 bits is a no-op: every byte of the 32-byte draw is kept.");
    }


    /// <summary>
    /// Asserts the MAC key draw <c>a_v = generate_mac_key</c> is a raw 16-byte <c>of_bytes_field</c> read
    /// through <see cref="LongfellowTranscript.SqueezeFieldElementBytes(System.Span{byte})"/>, not a
    /// <c>sample</c> draw: it must agree with an explicit <c>SqueezeBytes(16)</c> plus <c>of_bytes_field</c>
    /// on an identically-seeded transcript, and consume exactly 16 PRF bytes, leaving both transcripts'
    /// read pointers in lockstep for the next draw.
    /// </summary>
    [TestMethod]
    public void TheMacKeyDrawIsOfBytesFieldSixteenBytesNotSample()
    {
        //generate_mac_key (a_v) reads 16 raw PRF bytes through of_bytes_field, never the sample reject
        //loop. Two identically-seeded transcripts: one squeezes via SqueezeFieldElementBytes (the a_v
        //path), the other via SqueezeBytes(16) + FromBytesField. The canonical elements must match AND a
        //subsequent draw must be byte-identical, proving SqueezeFieldElementBytes consumed exactly 16 bytes.
        using Lch14AdditiveFft fft = NewFft();
        using LongfellowFieldProfile profile = LongfellowFieldProfile.ForGf2k128(fft, BaseMemoryPool.Shared);

        using LongfellowTranscript transcriptA = NewTranscript();
        using LongfellowTranscript transcriptB = NewTranscript();

        Span<byte> avBytes = stackalloc byte[GfSampleBytes];
        transcriptA.SqueezeFieldElementBytes(avBytes);
        Span<byte> avCanonical = stackalloc byte[ScalarSize];
        profile.FromBytesField(avBytes, avCanonical);

        Span<byte> rawBytes = stackalloc byte[GfSampleBytes];
        transcriptB.SqueezeBytes(rawBytes);
        Span<byte> rawCanonical = stackalloc byte[ScalarSize];
        profile.FromBytesField(rawBytes, rawCanonical);

        Assert.IsTrue(avCanonical.SequenceEqual(rawCanonical), "a_v = of_bytes_field over 16 raw PRF bytes (generate_mac_key), not sample.");

        //The PRF read pointers must be in lockstep: the next 16 bytes are identical from both transcripts.
        Span<byte> nextA = stackalloc byte[GfSampleBytes];
        Span<byte> nextB = stackalloc byte[GfSampleBytes];
        transcriptA.SqueezeBytes(nextA);
        transcriptB.SqueezeBytes(nextB);
        Assert.IsTrue(nextA.SequenceEqual(nextB), "SqueezeFieldElementBytes consumes exactly 16 PRF bytes (no reject loop).");
    }


    /// <summary>
    /// The BigInteger oracle of <c>fp_generic.h::sample</c>: reads each little-endian 32-byte block as an
    /// integer (the mask to 256 bits is a no-op), accepting the first below the modulus.
    /// </summary>
    /// <param name="blocks">The scripted stream of 32-byte little-endian blocks, in draw order.</param>
    /// <returns>The first block's value that falls below <see cref="Prime"/>.</returns>
    /// <exception cref="InvalidOperationException">When no block in <paramref name="blocks"/> falls below <see cref="Prime"/>.</exception>
    private static BigInteger SampleOracle(params byte[][] blocks)
    {
        foreach(byte[] block in blocks)
        {
            BigInteger value = ReadLittleEndian32(block);
            if(value < Prime)
            {
                return value;
            }
        }

        throw new InvalidOperationException("The scripted stream never produced an in-range block.");
    }


    /// <summary><c>of_scalar(u)</c>: the integer <paramref name="coordinate"/> reduced mod <c>p</c> as a canonical big-endian scalar.</summary>
    /// <param name="coordinate">The integer coordinate <c>u</c> to reduce.</param>
    /// <param name="destination">Receives the canonical big-endian scalar.</param>
    private static void OfScalar(uint coordinate, Span<byte> destination) =>
        WriteCanonicalBigEndian(new BigInteger(coordinate) % Prime, destination);


    /// <summary><c>fits(an)</c>: whether the canonical big-endian integer is below the modulus.</summary>
    /// <param name="canonical">The canonical big-endian encoding to test.</param>
    /// <returns><see langword="true"/> when <paramref name="canonical"/>'s value is below <see cref="Prime"/>.</returns>
    private static bool InRange(ReadOnlySpan<byte> canonical) => ReadCanonicalBigEndian(canonical) < Prime;


    /// <summary>Encodes <paramref name="value"/> as a 32-byte little-endian block for scripting a <c>sample</c> byte stream.</summary>
    /// <param name="value">The value to encode; must fit in <see cref="ScalarSize"/> canonical bytes.</param>
    /// <returns>A new 32-byte little-endian buffer holding <paramref name="value"/>.</returns>
    private static byte[] LittleEndian32(BigInteger value)
    {
        Span<byte> canonical = stackalloc byte[ScalarSize];
        WriteCanonicalBigEndian(value, canonical);
        byte[] littleEndian = new byte[Fp256SampleBytes];
        for(int i = 0; i < Fp256SampleBytes; i++)
        {
            littleEndian[i] = canonical[ScalarSize - 1 - i];
        }

        return littleEndian;
    }


    /// <summary>Reads a little-endian byte block as an unsigned integer.</summary>
    /// <param name="littleEndian">The little-endian encoded bytes.</param>
    /// <returns>The decoded unsigned value.</returns>
    private static BigInteger ReadLittleEndian32(ReadOnlySpan<byte> littleEndian) => new(littleEndian, isUnsigned: true, isBigEndian: false);


    /// <summary>Reads a canonical big-endian byte block as an unsigned integer.</summary>
    /// <param name="bytes">The canonical big-endian encoded bytes.</param>
    /// <returns>The decoded unsigned value.</returns>
    private static BigInteger ReadCanonicalBigEndian(ReadOnlySpan<byte> bytes) => new(bytes, isUnsigned: true, isBigEndian: true);


    /// <summary>Writes <paramref name="value"/> into <paramref name="destination"/> as a zero-padded canonical big-endian integer.</summary>
    /// <param name="value">The unsigned value to encode.</param>
    /// <param name="destination">The fixed-width destination; cleared and left-padded with zero bytes as needed.</param>
    /// <exception cref="InvalidOperationException">When <paramref name="value"/> does not fit in <paramref name="destination"/>.</exception>
    private static void WriteCanonicalBigEndian(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        if(!value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("The value did not fit in the canonical span.");
        }

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }


    /// <summary>Builds the production-parameter additive FFT that GF(2^128) field profiles in this gate depend on.</summary>
    /// <returns>A new <see cref="Lch14AdditiveFft"/> over <see cref="Lch14Subfield.Production16"/>.</returns>
    private static Lch14AdditiveFft NewFft() =>
        new(Lch14Subfield.Production16, GfAdd, GfSubtract, GfMultiply, GfInvert, CurveParameterSet.None, BaseMemoryPool.Shared);


    /// <summary>Builds a transcript seeded identically to every other transcript this gate creates, so their PRF streams are comparable.</summary>
    /// <returns>A new <see cref="LongfellowTranscript"/> seeded with <see cref="TranscriptSeed"/> and <see cref="TranscriptVersion"/>.</returns>
    private static LongfellowTranscript NewTranscript() =>
        new(TranscriptSeed, TranscriptVersion, GfSampleBytes, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());


    /// <summary>The transcript's block-cipher backend: AES-256 in ECB mode over a single block.</summary>
    /// <param name="key">The 256-bit AES key.</param>
    /// <param name="input">The single plaintext block.</param>
    /// <param name="output">Receives the single ciphertext block.</param>
    private static void Aes256Ecb(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output)
    {
        using Aes aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.EncryptEcb(input, output, PaddingMode.None);
    }
}
