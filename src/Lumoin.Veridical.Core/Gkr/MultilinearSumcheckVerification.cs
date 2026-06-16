using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Gkr;

/// <summary>
/// The outcome of verifying a sumcheck, backed by one pooled buffer the verification owns
/// (dispose to return it): whether every round was internally consistent,
/// the Fiat-Shamir challenge <see cref="Point"/> the variables were bound to (one 32-byte field
/// element per variable, in round order — most-significant table bit first), and the
/// <see cref="FinalClaim"/> the protocol reduced the original sum to. The caller completes the
/// proof by checking the underlying polynomial at <see cref="Point"/> (via an oracle, the next
/// GKR layer, or a commitment opening) equals <see cref="FinalClaim"/>.
/// </summary>
public sealed class MultilinearSumcheckVerification: IDisposable
{
    private const int ScalarSize = Scalar.SizeBytes;

    private readonly IMemoryOwner<byte> buffer;


    public bool Accepted { get; }

    public int VariableCount { get; }

    /// <summary>The challenge point, one 32-byte element per variable in round order.</summary>
    public ReadOnlyMemory<byte> Point => buffer.Memory[..(VariableCount * ScalarSize)];

    /// <summary>The reduced claim the polynomial must take at <see cref="Point"/>, 32 bytes.</summary>
    public ReadOnlyMemory<byte> FinalClaim => buffer.Memory.Slice(VariableCount * ScalarSize, ScalarSize);


    internal MultilinearSumcheckVerification(IMemoryOwner<byte> buffer, bool accepted, int variableCount)
    {
        this.buffer = buffer;
        Accepted = accepted;
        VariableCount = variableCount;
    }


    /// <summary>The pooled buffer size for a verification of the given shape.</summary>
    public static int GetBufferSizeBytes(int variableCount) => (variableCount * ScalarSize) + ScalarSize;


    public void Dispose() => buffer.Dispose();
}
