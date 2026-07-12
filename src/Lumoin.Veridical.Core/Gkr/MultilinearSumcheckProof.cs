using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Gkr;

/// <summary>
/// A multilinear sumcheck proof: the per-round univariate polynomials and the prover's claimed
/// final evaluation, backed by one pooled buffer the proof owns (dispose to return it). Each
/// round contributes a degree-1 polynomial sent as its two values <c>s(0), s(1)</c> (32 bytes
/// each, canonical field elements), concatenated in <see cref="RoundPolynomials"/> in round
/// order. <see cref="FinalValue"/> is the prover's <c>f(r)</c> after binding all
/// <see cref="VariableCount"/> variables to the Fiat-Shamir challenges — the value a verifier
/// (or the next GKR layer / a commitment opening) checks against an independent evaluation of
/// <c>f</c> at the challenge point.
/// </summary>
public sealed class MultilinearSumcheckProof: IDisposable
{
    private const int ScalarSize = Scalar.SizeBytes;

    private readonly IMemoryOwner<byte> buffer;


    /// <summary>The number of variables, equal to the number of sumcheck rounds the proof carries.</summary>
    public int VariableCount { get; }

    /// <summary>The round polynomials: <c>VariableCount</c> pairs <c>s(0), s(1)</c>, 32 bytes each.</summary>
    public ReadOnlyMemory<byte> RoundPolynomials => buffer.Memory[..(VariableCount * 2 * ScalarSize)];

    /// <summary>The prover's <c>f(r)</c> at the challenge point, 32 bytes.</summary>
    public ReadOnlyMemory<byte> FinalValue => buffer.Memory.Slice(VariableCount * 2 * ScalarSize, ScalarSize);


    internal MultilinearSumcheckProof(IMemoryOwner<byte> buffer, int variableCount)
    {
        this.buffer = buffer;
        VariableCount = variableCount;
    }


    /// <summary>The pooled buffer size for a proof of the given shape.</summary>
    public static int GetBufferSizeBytes(int variableCount) => (variableCount * 2 * ScalarSize) + ScalarSize;


    /// <summary>
    /// Builds a proof from its raw parts, copying them into a pooled buffer — the
    /// deserialization entry, also used by tests to construct tampered proofs.
    /// </summary>
    public static MultilinearSumcheckProof FromParts(
        ReadOnlySpan<byte> roundPolynomials,
        ReadOnlySpan<byte> finalValue,
        int variableCount,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(roundPolynomials.Length != variableCount * 2 * ScalarSize || finalValue.Length != ScalarSize)
        {
            throw new ArgumentException($"A {variableCount}-round proof needs {variableCount * 2 * ScalarSize} round bytes and a {ScalarSize}-byte final value.", nameof(roundPolynomials));
        }

        IMemoryOwner<byte> buffer = pool.Rent(GetBufferSizeBytes(variableCount));
        roundPolynomials.CopyTo(buffer.Memory.Span);
        finalValue.CopyTo(buffer.Memory.Span[roundPolynomials.Length..]);

        return new MultilinearSumcheckProof(buffer, variableCount);
    }


    /// <inheritdoc/>
    public void Dispose() => buffer.Dispose();
}
