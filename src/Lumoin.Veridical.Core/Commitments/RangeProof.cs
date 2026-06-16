using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// A Bulletproofs range proof (Bünz et al, IEEE S&amp;P 2018, §4.2): attests
/// that a Pedersen-committed value lies in <c>[0, 2^n)</c> without revealing
/// it. Produced by <see cref="BulletproofRangeProver"/>, verified by
/// <see cref="BulletproofRangeVerifier"/> against the commitment and a
/// <see cref="RangeProofKey"/>.
/// </summary>
/// <remarks>
/// <para>
/// Buffer layout, in order — a pure function of the bit width and curve, no
/// length prefixes:
/// </para>
/// <list type="number">
///   <item><description><c>A</c> — the bit-decomposition commitment: one compressed G1 point.</description></item>
///   <item><description><c>S</c> — the blinding-vector commitment: one compressed G1 point.</description></item>
///   <item><description><c>T₁</c>, <c>T₂</c> — the <c>t(X)</c> coefficient commitments: one compressed G1 point each.</description></item>
///   <item><description><c>τ_x</c>, <c>μ</c>, <c>t̂</c> — three canonical scalars.</description></item>
///   <item><description>The two-vector IPA: <c>log₂(n)</c> <c>(L, R)</c> point pairs, then the final <c>(a, b)</c> scalar pair.</description></item>
/// </list>
/// </remarks>
public sealed class RangeProof: SensitiveMemory
{
    private const int ScalarSize = Scalar.SizeBytes;

    //The four leading commitment points: A, S, T1, T2.
    private const int LeadingPointCount = 4;

    //The three mid-section scalars: tau_x, mu, t-hat.
    private const int MidScalarCount = 3;

    private int G1Size => WellKnownCurves.GetG1CompressedSizeBytes(Curve);


    /// <summary>The range width <c>n</c> in bits.</summary>
    //Matches RangeProofKey.MaximumVectorLength: a 64-value aggregation at the
    //full 64-bit width, the largest proof vector the IPA folds.
    private const int MaximumVectorLength = 4096;

    public int BitWidth { get; }

    /// <summary>The number of IPA rounds (<c>log₂(BitWidth)</c>).</summary>
    public int IpaRoundCount => BitOperations.Log2((uint)BitWidth);

    /// <summary>The curve identifying the scalar field and group.</summary>
    public CurveParameterSet Curve { get; }


    internal RangeProof(IMemoryOwner<byte> owner, int bitWidth, CurveParameterSet curve, Tag tag)
        : base(owner, GetBufferSizeBytes(bitWidth, curve), tag)
    {
        BitWidth = bitWidth;
        Curve = curve;
    }


    /// <summary>
    /// Reconstructs a proof from its canonical wire bytes. Copies the bytes
    /// into a fresh pool-rented buffer; the caller retains ownership of
    /// <paramref name="bytes"/>.
    /// </summary>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="bitWidth"/> is not a power of two in <c>[2, 64]</c>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="bytes"/> does not have the exact expected length.</exception>
    public static RangeProof FromBytes(ReadOnlySpan<byte> bytes, int bitWidth, CurveParameterSet curve, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        int expected = GetBufferSizeBytes(bitWidth, curve);
        if(bytes.Length != expected)
        {
            throw new ArgumentException(
                $"A range proof for bit width {bitWidth} must be {expected} bytes; received {bytes.Length}.",
                nameof(bytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(expected);
        bytes.CopyTo(owner.Memory.Span[..expected]);

        return new RangeProof(owner, bitWidth, curve, ComposeTag(curve));
    }


    /// <summary>Returns the bit-decomposition commitment <c>A</c> bytes.</summary>
    public ReadOnlySpan<byte> GetABytes() => AsReadOnlySpan().Slice(0, G1Size);

    /// <summary>Returns the blinding-vector commitment <c>S</c> bytes.</summary>
    public ReadOnlySpan<byte> GetSBytes() => AsReadOnlySpan().Slice(G1Size, G1Size);

    /// <summary>Returns the <c>T₁</c> commitment bytes.</summary>
    public ReadOnlySpan<byte> GetT1Bytes() => AsReadOnlySpan().Slice(2 * G1Size, G1Size);

    /// <summary>Returns the <c>T₂</c> commitment bytes.</summary>
    public ReadOnlySpan<byte> GetT2Bytes() => AsReadOnlySpan().Slice(3 * G1Size, G1Size);

    /// <summary>Returns the canonical bytes of <c>τ_x</c>.</summary>
    public ReadOnlySpan<byte> GetTauXBytes() => AsReadOnlySpan().Slice(LeadingPointCount * G1Size, ScalarSize);

    /// <summary>Returns the canonical bytes of <c>μ</c>.</summary>
    public ReadOnlySpan<byte> GetMuBytes() => AsReadOnlySpan().Slice((LeadingPointCount * G1Size) + ScalarSize, ScalarSize);

    /// <summary>Returns the canonical bytes of <c>t̂</c>.</summary>
    public ReadOnlySpan<byte> GetTHatBytes() => AsReadOnlySpan().Slice((LeadingPointCount * G1Size) + (2 * ScalarSize), ScalarSize);

    /// <summary>Returns the embedded IPA round pairs.</summary>
    public ReadOnlySpan<byte> GetIpaRoundPairBytes() =>
        AsReadOnlySpan().Slice(IpaSectionStart(), IpaRoundCount * 2 * G1Size);

    /// <summary>Returns the embedded IPA final <c>a</c> scalar.</summary>
    public ReadOnlySpan<byte> GetIpaFinalABytes() =>
        AsReadOnlySpan().Slice(IpaSectionStart() + (IpaRoundCount * 2 * G1Size), ScalarSize);

    /// <summary>Returns the embedded IPA final <c>b</c> scalar.</summary>
    public ReadOnlySpan<byte> GetIpaFinalBBytes() =>
        AsReadOnlySpan().Slice(IpaSectionStart() + (IpaRoundCount * 2 * G1Size) + ScalarSize, ScalarSize);


    /// <summary>Returns the total wire-format byte size for the supplied dimensions.</summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="bitWidth"/> is not a power of two in <c>[2, 64]</c>.</exception>
    public static int GetBufferSizeBytes(int bitWidth, CurveParameterSet curve)
    {
        if(bitWidth < 2 || bitWidth > MaximumVectorLength || !BitOperations.IsPow2(bitWidth))
        {
            throw new ArgumentOutOfRangeException(
                nameof(bitWidth),
                $"The proof vector length must be a power of two in [2, {MaximumVectorLength}]; received {bitWidth}.");
        }

        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(curve);
        int ipaRoundCount = BitOperations.Log2((uint)bitWidth);

        return (LeadingPointCount * g1Size)
            + (MidScalarCount * ScalarSize)
            + (ipaRoundCount * 2 * g1Size)
            + (2 * ScalarSize);
    }


    private int IpaSectionStart() => (LeadingPointCount * G1Size) + (MidScalarCount * ScalarSize);


    private static Tag ComposeTag(CurveParameterSet curve)
    {
        return Tag.Create(
            (typeof(AlgebraicRole), (object)AlgebraicRole.ZkProof),
            (typeof(CurveParameterSet), (object)curve));
    }


    internal static Tag ComposeProofTag(CurveParameterSet curve) => ComposeTag(curve);
}
