using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Argument validation for <see cref="FiatShamirTranscript"/>: <see cref="FiatShamirTranscript.Initialise"/>,
/// <c>AbsorbBytes</c> and <c>SqueezeBytes</c> reject a <see langword="null"/> hash function name, hash delegate,
/// squeeze delegate or pool with an <see cref="ArgumentNullException"/> naming that parameter before any delegate
/// runs, and <see cref="FiatShamirTranscript.Initialise"/> rejects a hash function name outside the seven algorithm
/// families the transcript admits (BLAKE3, SHA-256, SHA-512, SHA3-256, SHA3-512, SHAKE128 and SHAKE256) with an
/// <see cref="ArgumentException"/> before the state buffer is rented and before the hash delegate runs.
/// </summary>
[TestClass]
internal sealed class FiatShamirTranscriptValidationTests
{
    /// <summary>A hash function name that none of the <see cref="WellKnownHashAlgorithms"/> recognition predicates accepts under any spelling or casing.</summary>
    private const string UnrecognisedHashFunctionName = "MD5";

    /// <summary>The parameter name the unrecognised-hash guard reports.</summary>
    private const string HashFunctionParameterName = "hashFunction";

    /// <summary>The leading sentence of the unrecognised-hash guard's message, naming the rejected input; neither the null-argument checks nor a hash backend produce this text.</summary>
    private const string UnrecognisedHashMessageFragment = $"Hash function '{UnrecognisedHashFunctionName}' is not in WellKnownHashAlgorithms.";

    /// <summary>The parameter name the null hash delegate checks of <see cref="FiatShamirTranscript.Initialise"/>, <c>AbsorbBytes</c> and <c>SqueezeBytes</c> report.</summary>
    private const string HashParameterName = "hash";

    /// <summary>The parameter name the null squeeze delegate check of <c>SqueezeBytes</c> reports.</summary>
    private const string SqueezeParameterName = "squeeze";

    /// <summary>The parameter name the null pool check of <see cref="FiatShamirTranscript.Initialise"/> reports.</summary>
    private const string PoolParameterName = "pool";

    /// <summary>The width of the squeeze destination, one full BLAKE3 output.</summary>
    private const int SqueezeByteCount = 32;

    /// <summary>Zero XOF calls, because the null hash guard must reject before the squeeze delegate runs.</summary>
    private const int NoSqueezeCalls = 0;

    /// <summary>The fixed-output BLAKE3 transcript hash backend.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();

    /// <summary>The XOF-mode BLAKE3 transcript squeeze backend.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();

    /// <summary>The protocol-identifying label the validation transcripts are initialised under.</summary>
    private static FiatShamirDomainLabel DomainLabel { get; } = new("veridical.test.validation.v1");

    /// <summary>The operation label the rejected absorbs and squeezes are issued under.</summary>
    private static FiatShamirOperationLabel OperationLabel { get; } = new("test.validation.operation");


    /// <summary>
    /// Pins that <see cref="FiatShamirTranscript.Initialise"/> rejects a hash function name no
    /// <see cref="WellKnownHashAlgorithms"/> predicate recognises with an <see cref="ArgumentException"/>
    /// that reports the <c>hashFunction</c> parameter and a message naming the rejected input. The name,
    /// the hash delegate and the pool are all non-null, so no null-argument check answers first, and the
    /// exact exception type excludes the <see cref="NotSupportedException"/> the BLAKE3 backend raises
    /// when it is handed a name it does not implement.
    /// </summary>
    [TestMethod]
    public void InitialiseRejectsUnrecognisedHashFunction()
    {
        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => FiatShamirTranscript.Initialise(DomainLabel, ReadOnlySpan<byte>.Empty, UnrecognisedHashFunctionName, Hash, BaseMemoryPool.Shared).Dispose(),
            "A hash function name outside the recognised algorithms must reject.");

        Assert.AreEqual(HashFunctionParameterName, exception.ParamName, "The rejection must name the hashFunction parameter.");
        Assert.Contains(UnrecognisedHashMessageFragment, exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// Pins that <see cref="FiatShamirTranscript.Initialise"/> rejects a <see langword="null"/> hash function name with an
    /// <see cref="ArgumentNullException"/> that reports the <c>hashFunction</c> parameter. The hash delegate and the pool
    /// are non-null, so no other null check answers. The unrecognised-name check reports the same parameter name with the
    /// base <see cref="ArgumentException"/>, so the exact exception type is what separates the null check from it.
    /// </summary>
    [TestMethod]
    public void InitialiseRejectsNullHashFunction()
    {
        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(
            () => FiatShamirTranscript.Initialise(DomainLabel, ReadOnlySpan<byte>.Empty, null!, Hash, BaseMemoryPool.Shared).Dispose(),
            "A null hash function name must reject as a null argument.");

        Assert.AreEqual(HashFunctionParameterName, exception.ParamName, "The rejection must name the hashFunction parameter.");
    }


    /// <summary>
    /// Pins that <see cref="FiatShamirTranscript.Initialise"/> rejects a <see langword="null"/> hash delegate with an
    /// <see cref="ArgumentNullException"/> that reports the <c>hash</c> parameter, instead of renting the state buffer
    /// and failing when the initial-state hash is invoked. The hash function name is BLAKE3 and the pool is non-null, so
    /// neither the other null checks nor the unrecognised-name check answers.
    /// </summary>
    [TestMethod]
    public void InitialiseRejectsNullHashDelegate()
    {
        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(
            () => FiatShamirTranscript.Initialise(DomainLabel, ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, null!, BaseMemoryPool.Shared).Dispose(),
            "A null hash delegate must reject as a null argument.");

        Assert.AreEqual(HashParameterName, exception.ParamName, "The rejection must name the hash parameter.");
    }


    /// <summary>
    /// Pins that <see cref="FiatShamirTranscript.Initialise"/> rejects a <see langword="null"/> pool with an
    /// <see cref="ArgumentNullException"/> that reports the <c>pool</c> parameter, instead of failing at the first rental.
    /// The hash function name is BLAKE3 and the hash delegate is non-null, so neither the other null checks nor the
    /// unrecognised-name check answers.
    /// </summary>
    [TestMethod]
    public void InitialiseRejectsNullPool()
    {
        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(
            () => FiatShamirTranscript.Initialise(DomainLabel, ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, null!).Dispose(),
            "A null pool must reject as a null argument.");

        Assert.AreEqual(PoolParameterName, exception.ParamName, "The rejection must name the pool parameter.");
    }


    /// <summary>
    /// Pins that <c>AbsorbBytes</c> rejects a <see langword="null"/> hash delegate with an
    /// <see cref="ArgumentNullException"/> that reports the <c>hash</c> parameter, instead of assembling the absorb input
    /// and failing when the absorb hash is invoked. The transcript is live, so the absorb's own transcript check passes
    /// and the hash delegate is the only null argument.
    /// </summary>
    [TestMethod]
    public void AbsorbBytesRejectsNullHashDelegate()
    {
        using FiatShamirTranscript transcript = FiatShamirTranscript.Initialise(DomainLabel, ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);

        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(
            () => transcript.AbsorbBytes(OperationLabel, ReadOnlySpan<byte>.Empty, null!),
            "A null hash delegate must reject the absorb as a null argument.");

        Assert.AreEqual(HashParameterName, exception.ParamName, "The rejection must name the hash parameter.");
    }


    /// <summary>
    /// Pins that <c>SqueezeBytes</c> rejects a <see langword="null"/> squeeze delegate with an
    /// <see cref="ArgumentNullException"/> that reports the <c>squeeze</c> parameter, instead of assembling the challenge
    /// input and failing when the XOF is invoked. The transcript and the hash delegate are non-null, so the squeeze
    /// delegate is the only null argument.
    /// </summary>
    [TestMethod]
    public void SqueezeBytesRejectsNullSqueezeDelegate()
    {
        using FiatShamirTranscript transcript = FiatShamirTranscript.Initialise(DomainLabel, ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);
        using IMemoryOwner<byte> destinationOwner = BaseMemoryPool.Shared.Rent(SqueezeByteCount);

        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(
            () => transcript.SqueezeBytes(OperationLabel, destinationOwner.Memory.Span[..SqueezeByteCount], null!, Hash),
            "A null squeeze delegate must reject the squeeze as a null argument.");

        Assert.AreEqual(SqueezeParameterName, exception.ParamName, "The rejection must name the squeeze parameter.");
    }


    /// <summary>
    /// Pins that <c>SqueezeBytes</c> rejects a <see langword="null"/> hash delegate with an
    /// <see cref="ArgumentNullException"/> that reports the <c>hash</c> parameter before the XOF runs, instead of writing
    /// challenge bytes into the destination and failing only at the chained state-update hash. The transcript and the
    /// squeeze delegate are non-null, so the hash delegate is the only null argument. The recording squeeze delegate's
    /// zero call count pins that rejection precedes the XOF invocation.
    /// </summary>
    [TestMethod]
    public void SqueezeBytesRejectsNullHashDelegate()
    {
        using FiatShamirTranscript transcript = FiatShamirTranscript.Initialise(DomainLabel, ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);
        using IMemoryOwner<byte> destinationOwner = BaseMemoryPool.Shared.Rent(SqueezeByteCount);
        int squeezeCalls = NoSqueezeCalls;
        FiatShamirSqueezeDelegate recordingSqueeze = (ReadOnlySpan<byte> input, Span<byte> output, string hashFunction) =>
        {
            squeezeCalls++;
            Squeeze(input, output, hashFunction);
        };

        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(
            () => transcript.SqueezeBytes(OperationLabel, destinationOwner.Memory.Span[..SqueezeByteCount], recordingSqueeze, null!),
            "A null hash delegate must reject the squeeze as a null argument.");

        Assert.AreEqual(HashParameterName, exception.ParamName, "The rejection must name the hash parameter.");
        Assert.AreEqual(NoSqueezeCalls, squeezeCalls, "A null hash delegate must be rejected before the squeeze delegate runs.");
    }
}
