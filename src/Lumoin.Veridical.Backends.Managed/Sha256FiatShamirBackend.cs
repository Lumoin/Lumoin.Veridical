using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Hashing;
using System;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// The SHA-256 backend for the Fiat-Shamir transcript, wrapping the
/// library's own managed <see cref="Sha256Hasher"/>. Supplies both the
/// one-shot snapshot hash (for the leaf-hash and Merkle paths that stay
/// one-shot) and the forkable incremental seam the Longfellow transcript
/// uses to snapshot its absorbed stream in one pass. Mirrors
/// <see cref="Blake3FiatShamirBackend"/>.
/// </summary>
/// <remarks>
/// <para>
/// The incremental seam is the wiring point where the value-struct fork is
/// realised: <see cref="GetIncrementalFactory"/> returns a factory that
/// produces an <see cref="ILongfellowIncrementalHash"/> over a running
/// <see cref="Sha256Hasher"/>, and <see cref="ILongfellowIncrementalHash.Fork"/>
/// is a plain value copy of that hasher (the reference's
/// <c>SHA256 tmp; tmp.CopyState(sha_);</c>). The forked-then-finalized
/// digest is byte-identical to <see cref="GetHash"/> over the same bytes, so
/// the transcript's challenge stream is unchanged.
/// </para>
/// </remarks>
public static class Sha256FiatShamirBackend
{
    /// <summary>Returns the one-shot fixed-output hash delegate (32-byte SHA-256).</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1024", Justification = "Delegate-factory method following the established Get* backend convention.")]
    public static FiatShamirHashDelegate GetHash() => Hash;


    /// <summary>Returns the factory that produces a fresh forkable incremental SHA-256 for the Longfellow transcript snapshot.</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1024", Justification = "Delegate-factory method following the established Get* backend convention.")]
    public static LongfellowIncrementalHashFactory GetIncrementalFactory() => CreateIncremental;


    private static void Hash(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction)
    {
        EnsureSha256(hashFunction);
        Sha256.HashData(input, output);
    }


    private static IncrementalSha256 CreateIncremental() =>
        new(Sha256Hasher.CreateAutoSelected());


    private static void EnsureSha256(string hashFunction)
    {
        if(!WellKnownHashAlgorithms.IsSha256(hashFunction))
        {
            throw new NotSupportedException(
                $"Sha256FiatShamirBackend does not implement '{hashFunction}'; only SHA-256 is supported by this backend.");
        }
    }


    //The Core seam over the value-struct Sha256Hasher. The hasher is a VALUE field, so Fork() is a plain
    //value copy that duplicates the entire inline state — the reference's CopyState. FinalizeInto consumes
    //the fork's partial block; because callers fork before finalizing, the running state stays undisturbed.
    private sealed class IncrementalSha256: ILongfellowIncrementalHash
    {
        private Sha256Hasher hasher;


        public IncrementalSha256(Sha256Hasher hasher) => this.hasher = hasher;


        public void Update(ReadOnlySpan<byte> data) => hasher.Update(data);


        public ILongfellowIncrementalHash Fork() => new IncrementalSha256(hasher);


        public void FinalizeInto(Span<byte> digest) => hasher.Finalize(digest);
    }
}
