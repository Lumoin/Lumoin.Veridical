using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Gkr;

/// <summary>
/// One layer of a data-parallel GKR proof: the copy-variable rounds (degree-3 polynomials, four
/// 32-byte evaluations each, in round order) that bind the copy index once across all copies,
/// followed by the hand sumcheck over the folded per-copy wires. The copy-round buffer is pooled
/// and owned by this proof; the hand proof's ownership moves in with it.
/// </summary>
internal sealed class GkrDataParallelLayerProof: IDisposable
{
    private const int ScalarSize = Scalar.SizeBytes;
    private const int CopyRoundEvaluations = 4;

    private readonly IMemoryOwner<byte> copyRoundBuffer;


    public int CopyRoundCount { get; }

    /// <summary>The copy-variable round polynomials: per round, four 32-byte evaluations at 0..3.</summary>
    public ReadOnlyMemory<byte> CopyRoundPolynomials => copyRoundBuffer.Memory[..(CopyRoundCount * CopyRoundEvaluations * ScalarSize)];

    /// <summary>The hand sumcheck over the copy-folded wires.</summary>
    public ProductSumcheckProof HandProof { get; }


    internal GkrDataParallelLayerProof(IMemoryOwner<byte> copyRoundBuffer, int copyRoundCount, ProductSumcheckProof handProof)
    {
        this.copyRoundBuffer = copyRoundBuffer;
        CopyRoundCount = copyRoundCount;
        HandProof = handProof;
    }


    /// <summary>The pooled copy-round buffer size for the given round count.</summary>
    public static int GetCopyRoundBufferSizeBytes(int copyRoundCount) => copyRoundCount * CopyRoundEvaluations * ScalarSize;


    /// <summary>
    /// Builds a layer proof from raw copy-round bytes and a hand proof (whose ownership moves
    /// in) — the deserialization entry, also used by tests to construct tampered proofs.
    /// </summary>
    public static GkrDataParallelLayerProof FromParts(
        ReadOnlySpan<byte> copyRoundPolynomials,
        int copyRoundCount,
        ProductSumcheckProof handProof,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(handProof);
        ArgumentNullException.ThrowIfNull(pool);
        if(copyRoundPolynomials.Length != GetCopyRoundBufferSizeBytes(copyRoundCount))
        {
            throw new ArgumentException($"{copyRoundCount} copy rounds need {GetCopyRoundBufferSizeBytes(copyRoundCount)} bytes; received {copyRoundPolynomials.Length}.", nameof(copyRoundPolynomials));
        }

        IMemoryOwner<byte> buffer = pool.Rent(GetCopyRoundBufferSizeBytes(copyRoundCount));
        copyRoundPolynomials.CopyTo(buffer.Memory.Span);

        return new GkrDataParallelLayerProof(buffer, copyRoundCount, handProof);
    }


    public void Dispose()
    {
        copyRoundBuffer.Dispose();
        HandProof.Dispose();
    }
}


/// <summary>
/// A data-parallel GKR proof: one <see cref="GkrDataParallelLayerProof"/> per circuit layer,
/// output layer first, each owned by this proof (dispose to return the pooled storage).
/// </summary>
internal sealed class GkrDataParallelProof: IDisposable
{
    public GkrDataParallelLayerProof[] LayerProofs { get; }


    internal GkrDataParallelProof(GkrDataParallelLayerProof[] layerProofs)
    {
        LayerProofs = layerProofs;
    }


    public void Dispose()
    {
        foreach(GkrDataParallelLayerProof layerProof in LayerProofs)
        {
            layerProof.Dispose();
        }
    }
}


/// <summary>
/// The prover-side outcome of a data-parallel GKR run: the <see cref="Proof"/> to ship plus the
/// final input-claim points — the copy point <c>r_c</c> and the two hand points the last layer's
/// wire claims address the input table at. A committed-witness wrapper opens the witness
/// commitment at exactly these tensor points. Ownership: <see cref="Proof"/> transfers to the
/// caller; disposing this result returns only the point buffer.
/// </summary>
internal sealed class GkrDataParallelProverResult: IDisposable
{
    private const int ScalarSize = Scalar.SizeBytes;

    private readonly IMemoryOwner<byte> pointBuffer;
    private readonly int copyCoordinates;
    private readonly int wireCoordinates;


    public GkrDataParallelProof Proof { get; }

    /// <summary>The final copy point r_c, eq convention, log2(copyCount) coordinates.</summary>
    public ReadOnlyMemory<byte> CopyPoint => pointBuffer.Memory[..(copyCoordinates * ScalarSize)];

    /// <summary>The left input-claim wire point, eq convention, log2(inputCount) coordinates.</summary>
    public ReadOnlyMemory<byte> InputLeftPoint => pointBuffer.Memory.Slice(copyCoordinates * ScalarSize, wireCoordinates * ScalarSize);

    /// <summary>The right input-claim wire point, eq convention, log2(inputCount) coordinates.</summary>
    public ReadOnlyMemory<byte> InputRightPoint => pointBuffer.Memory.Slice((copyCoordinates + wireCoordinates) * ScalarSize, wireCoordinates * ScalarSize);


    internal GkrDataParallelProverResult(GkrDataParallelProof proof, IMemoryOwner<byte> pointBuffer, int copyCoordinates, int wireCoordinates)
    {
        Proof = proof;
        this.pointBuffer = pointBuffer;
        this.copyCoordinates = copyCoordinates;
        this.wireCoordinates = wireCoordinates;
    }


    public void Dispose() => pointBuffer.Dispose();
}
