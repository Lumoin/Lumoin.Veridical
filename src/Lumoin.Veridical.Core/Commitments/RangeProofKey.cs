using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// The Bulletproofs range proof's public key material: two independent
/// Pedersen generator families <c>G_0…G_{n−1}</c> and <c>H_0…H_{n−1}</c>
/// (one slot per bit of the range width <c>n</c>), the value generator
/// <c>g</c>, the blinding generator <c>h</c>, and the inner-product value
/// generator <c>u</c>. All derived deterministically from a seed via
/// RFC 9380 hash-to-curve, so prover and verifier reconstruct byte-identical
/// keys without out-of-band transmission.
/// </summary>
/// <remarks>
/// <para>
/// Realised as two <see cref="HyraxCommitmentKey"/> derivations with
/// domain-separated seeds: the <c>G</c> family's key also supplies <c>g</c>
/// (its value generator) and <c>h</c> (its blinding generator); the <c>H</c>
/// family's key supplies <c>u</c> (its value generator). The five roles are
/// pairwise independent because every point is a distinct hash-to-curve
/// image.
/// </para>
/// </remarks>
public sealed class RangeProofKey: IDisposable
{
    //Seed suffixes domain-separating the two generator families.
    private const string GeneratorFamilyGSuffix = ".range-g";
    private const string GeneratorFamilyHSuffix = ".range-h";

    private HyraxCommitmentKey? generatorFamilyG;
    private HyraxCommitmentKey? generatorFamilyH;


    //Bounds the derived generator material (2 · length + 4 points): 4096
    //covers a 64-value aggregation at the full 64-bit width while keeping the
    //largest key under a megabyte.
    private const int MaximumVectorLength = 4096;

    /// <summary>The generator-vector length: the range width <c>n</c> for a single-value proof (the proof attests <c>v ∈ [0, 2^n)</c>, <c>n ≤ 64</c>), <c>n · m</c> for an aggregated one. A power of two (the inner-product argument's requirement).</summary>
    public int BitWidth { get; }

    /// <summary>The curve identifying the underlying group.</summary>
    public CurveParameterSet Curve { get; }


    private RangeProofKey(HyraxCommitmentKey generatorFamilyG, HyraxCommitmentKey generatorFamilyH, int bitWidth, CurveParameterSet curve)
    {
        this.generatorFamilyG = generatorFamilyG;
        this.generatorFamilyH = generatorFamilyH;
        BitWidth = bitWidth;
        Curve = curve;
    }


    /// <summary>
    /// Derives a range-proof key for the requested bit width from
    /// <paramref name="seed"/>. Two callers supplying the same seed, bit
    /// width, and curve receive byte-identical keys.
    /// </summary>
    /// <param name="bitWidth">The generator-vector length; a power of two in <c>[2, 4096]</c>. A single-value range proof uses its bit width <c>n ≤ 64</c> directly; an aggregated proof uses <c>n · m</c>.</param>
    /// <param name="seed">The protocol-identifying seed string.</param>
    /// <param name="curve">The curve.</param>
    /// <param name="hashToCurve">The backend hash-to-curve implementation.</param>
    /// <param name="pool">The pool to rent the backing buffers from.</param>
    /// <returns>The derived key; the caller owns its disposal.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="bitWidth"/> is not a power of two in <c>[2, 4096]</c>.</exception>
    public static RangeProofKey Derive(
        int bitWidth,
        string seed,
        CurveParameterSet curve,
        G1HashToCurveDelegate hashToCurve,
        SensitiveMemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(seed);
        ArgumentNullException.ThrowIfNull(hashToCurve);
        ArgumentNullException.ThrowIfNull(pool);
        if(bitWidth < 2 || bitWidth > MaximumVectorLength || !BitOperations.IsPow2(bitWidth))
        {
            throw new ArgumentOutOfRangeException(
                nameof(bitWidth),
                $"The key vector length must be a power of two in [2, {MaximumVectorLength}] (the inner-product argument folds by halving); received {bitWidth}.");
        }

        HyraxCommitmentKey familyG = HyraxCommitmentKey.Derive(bitWidth, seed + GeneratorFamilyGSuffix, curve, hashToCurve, pool);
        try
        {
            HyraxCommitmentKey familyH = HyraxCommitmentKey.Derive(bitWidth, seed + GeneratorFamilyHSuffix, curve, hashToCurve, pool);

            return new RangeProofKey(familyG, familyH, bitWidth, curve);
        }
        catch
        {
            familyG.Dispose();
            throw;
        }
    }


    /// <summary>Returns the canonical compressed bytes of <c>G_i</c>.</summary>
    public ReadOnlySpan<byte> GetGeneratorG(int index) => FamilyG.GetGenerator(index);

    /// <summary>Returns the canonical compressed bytes of <c>H_i</c>.</summary>
    public ReadOnlySpan<byte> GetGeneratorH(int index) => FamilyH.GetGenerator(index);

    /// <summary>Returns the value generator <c>g</c> (the <c>v</c> slot of <c>V = v·g + γ·h</c>).</summary>
    public ReadOnlySpan<byte> GetValueGenerator() => FamilyG.GetValueGenerator();

    /// <summary>Returns the blinding generator <c>h</c>.</summary>
    public ReadOnlySpan<byte> GetBlindingGenerator() => FamilyG.GetBlindingGenerator();

    /// <summary>Returns the inner-product value generator <c>u</c>.</summary>
    public ReadOnlySpan<byte> GetInnerProductGenerator() => FamilyH.GetValueGenerator();


    /// <summary>
    /// Commits a value under a caller-supplied blinding scalar:
    /// <c>V = v·g + γ·h</c>. The commitment is what a consumer stores or
    /// publishes; the blinding is the secret opening material the proof
    /// consumes.
    /// </summary>
    /// <param name="value">The committed value; must satisfy <c>value &lt; 2^BitWidth</c>.</param>
    /// <param name="blinding">The blinding scalar <c>γ</c>, canonical bytes.</param>
    /// <param name="destination">Receives the compressed commitment point; exactly one G1 point wide.</param>
    /// <param name="g1Msm">The G1 MSM backend.</param>
    /// <param name="pool">The pool for scratch buffers.</param>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="value"/> does not fit the bit width.</exception>
    /// <exception cref="ArgumentException">When a span argument has the wrong length.</exception>
    public void CommitValue(
        ulong value,
        ReadOnlySpan<byte> blinding,
        Span<byte> destination,
        G1MultiScalarMultiplyDelegate g1Msm,
        SensitiveMemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(g1Msm);
        ArgumentNullException.ThrowIfNull(pool);
        ThrowIfValueOutOfRange(value);

        int scalarSize = Scalar.SizeBytes;
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
        if(blinding.Length != scalarSize)
        {
            throw new ArgumentException($"The blinding must be exactly {scalarSize} bytes (one canonical scalar); received {blinding.Length}.", nameof(blinding));
        }

        if(destination.Length != g1Size)
        {
            throw new ArgumentException($"The destination must be exactly {g1Size} bytes (one compressed G1 point); received {destination.Length}.", nameof(destination));
        }

        const int OperandCount = 2;
        using IMemoryOwner<byte> pointsOwner = pool.Rent(OperandCount * g1Size);
        using IMemoryOwner<byte> scalarsOwner = pool.Rent(OperandCount * scalarSize);
        Span<byte> points = pointsOwner.Memory.Span[..(OperandCount * g1Size)];
        Span<byte> scalars = scalarsOwner.Memory.Span[..(OperandCount * scalarSize)];

        GetValueGenerator().CopyTo(points[..g1Size]);
        GetBlindingGenerator().CopyTo(points.Slice(g1Size, g1Size));
        WriteValueScalar(value, scalars[..scalarSize]);
        blinding.CopyTo(scalars.Slice(scalarSize, scalarSize));

        g1Msm(points, scalars, OperandCount, destination, Curve);
    }


    /// <summary>Throws when <paramref name="value"/> does not fit the key's bit width — the prover-side range guard.</summary>
    /// <exception cref="ArgumentOutOfRangeException">When the value is out of range.</exception>
    public void ThrowIfValueOutOfRange(ulong value)
    {
        if(BitWidth < 64 && (value >> BitWidth) != 0UL)
        {
            throw new ArgumentOutOfRangeException(
                nameof(value),
                $"The value must lie in [0, 2^{BitWidth}); received {value}.");
        }
    }


    /// <summary>Writes a <see cref="ulong"/> as a canonical big-endian scalar (zero-extended).</summary>
    internal static void WriteValueScalar(ulong value, Span<byte> destination)
    {
        destination.Clear();
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(destination[^sizeof(ulong)..], value);
    }


    internal HyraxCommitmentKey FamilyG => generatorFamilyG ?? throw new ObjectDisposedException(nameof(RangeProofKey));

    internal HyraxCommitmentKey FamilyH => generatorFamilyH ?? throw new ObjectDisposedException(nameof(RangeProofKey));


    /// <inheritdoc/>
    public void Dispose()
    {
        generatorFamilyG?.Dispose();
        generatorFamilyG = null;
        generatorFamilyH?.Dispose();
        generatorFamilyH = null;
    }
}
