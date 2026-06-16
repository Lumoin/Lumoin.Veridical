using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Gkr;

/// <summary>
/// The prover-side outcome of a product sumcheck: the <see cref="Proof"/> to ship, plus the
/// Fiat-Shamir <see cref="ChallengePoint"/> the variables were bound to (one 32-byte field
/// element per round, in round order — the same point the verifier reconstructs). The prover
/// needs the point locally to continue a larger protocol — in GKR the layer prover evaluates the
/// next layer's equality tables at this point — while the proof itself stays point-free.
/// Ownership: <see cref="Proof"/> transfers to the caller (dispose it with the proof's own
/// lifetime); disposing this result returns only the challenge-point buffer.
/// </summary>
public sealed class ProductSumcheckProverResult: IDisposable
{
    private const int ScalarSize = Scalar.SizeBytes;

    private readonly IMemoryOwner<byte> pointBuffer;


    public ProductSumcheckProof Proof { get; }

    /// <summary>The challenge point, one 32-byte element per round in round order.</summary>
    public ReadOnlyMemory<byte> ChallengePoint => pointBuffer.Memory[..(Proof.VariableCount * ScalarSize)];


    internal ProductSumcheckProverResult(ProductSumcheckProof proof, IMemoryOwner<byte> pointBuffer)
    {
        Proof = proof;
        this.pointBuffer = pointBuffer;
    }


    public void Dispose() => pointBuffer.Dispose();
}
