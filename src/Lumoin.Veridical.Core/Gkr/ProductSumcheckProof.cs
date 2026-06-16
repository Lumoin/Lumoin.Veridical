using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Gkr;

/// <summary>
/// A product sumcheck proof for <c>H = Σ_{x∈{0,1}^v} Π_k f_k(x)</c> over <see cref="FactorCount"/>
/// multilinear factors, backed by one pooled buffer the proof owns (dispose to return it). Each
/// of the <see cref="VariableCount"/> rounds contributes a univariate polynomial of degree
/// <see cref="FactorCount"/>, sent as its <c>FactorCount + 1</c> evaluations at the points
/// <c>0, 1, …, FactorCount</c> (32 bytes each), concatenated in round order in
/// <see cref="RoundPolynomials"/>. <see cref="FinalValues"/> holds each factor's evaluation
/// <c>f_k(r)</c> at the Fiat-Shamir point — the product of which the protocol reduces the sum to,
/// and which an outer protocol (the next GKR layer or a commitment opening) binds to the real
/// factors.
/// </summary>
public sealed class ProductSumcheckProof: IDisposable
{
    private const int ScalarSize = Scalar.SizeBytes;

    private readonly IMemoryOwner<byte> buffer;


    public int VariableCount { get; }

    public int FactorCount { get; }

    /// <summary>The round polynomials: per round, <c>FactorCount + 1</c> evaluations of 32 bytes.</summary>
    public ReadOnlyMemory<byte> RoundPolynomials => buffer.Memory[..(VariableCount * (FactorCount + 1) * ScalarSize)];

    /// <summary>Each factor's evaluation at the challenge point, 32 bytes per factor.</summary>
    public ReadOnlyMemory<byte> FinalValues => buffer.Memory.Slice(VariableCount * (FactorCount + 1) * ScalarSize, FactorCount * ScalarSize);


    internal ProductSumcheckProof(IMemoryOwner<byte> buffer, int variableCount, int factorCount)
    {
        this.buffer = buffer;
        VariableCount = variableCount;
        FactorCount = factorCount;
    }


    /// <summary>The pooled buffer size for a proof of the given shape.</summary>
    public static int GetBufferSizeBytes(int variableCount, int factorCount) =>
        (variableCount * (factorCount + 1) * ScalarSize) + (factorCount * ScalarSize);


    /// <summary>
    /// Builds a proof from its raw parts, copying them into a pooled buffer — the
    /// deserialization entry, also used by tests to construct tampered proofs.
    /// </summary>
    public static ProductSumcheckProof FromParts(
        ReadOnlySpan<byte> roundPolynomials,
        ReadOnlySpan<byte> finalValues,
        int variableCount,
        int factorCount,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(roundPolynomials.Length != variableCount * (factorCount + 1) * ScalarSize || finalValues.Length != factorCount * ScalarSize)
        {
            throw new ArgumentException($"A {variableCount}-round, degree-{factorCount} proof needs {variableCount * (factorCount + 1) * ScalarSize} round bytes and {factorCount * ScalarSize} final-value bytes.", nameof(roundPolynomials));
        }

        IMemoryOwner<byte> buffer = pool.Rent(GetBufferSizeBytes(variableCount, factorCount));
        roundPolynomials.CopyTo(buffer.Memory.Span);
        finalValues.CopyTo(buffer.Memory.Span[roundPolynomials.Length..]);

        return new ProductSumcheckProof(buffer, variableCount, factorCount);
    }


    public void Dispose() => buffer.Dispose();
}
