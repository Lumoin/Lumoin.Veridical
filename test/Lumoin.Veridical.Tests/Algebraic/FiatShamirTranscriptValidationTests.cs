using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Argument validation for <see cref="FiatShamirTranscript.Initialise"/>: a hash function name outside
/// the seven algorithm families the transcript admits (BLAKE3, SHA-256, SHA-512, SHA3-256, SHA3-512,
/// SHAKE128 and SHAKE256) is rejected with an <see cref="ArgumentException"/> before the state buffer
/// is rented and before the hash delegate runs.
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

    /// <summary>The fixed-output BLAKE3 transcript hash backend.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();

    /// <summary>The protocol-identifying label the validation transcripts are initialised under.</summary>
    private static FiatShamirDomainLabel DomainLabel { get; } = new("veridical.test.validation.v1");


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
}
