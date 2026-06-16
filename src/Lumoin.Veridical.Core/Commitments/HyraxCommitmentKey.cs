using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Text;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// Hyrax's commitment-scheme public key: a vector of generator G1
/// points plus a blinding generator <c>H</c> and an IPA value generator
/// <c>U</c>. All three are derived deterministically from a seed via
/// RFC 9380 hash-to-curve, so prover and verifier reconstruct
/// byte-identical keys from the same seed and vector length without
/// any out-of-band transmission.
/// </summary>
/// <remarks>
/// <para>
/// Buffer layout, in canonical 48-byte compressed G1 form, in order:
/// </para>
/// <list type="number">
///   <item><description><c>G_0, G_1, ..., G_{vectorLength - 1}</c>: the Pedersen vector generators.</description></item>
///   <item><description><c>H</c>: the Pedersen blinding generator.</description></item>
///   <item><description><c>U</c>: the IPA value generator. Independent of <c>H</c> so the IPA's binding generator is structurally distinct from the Pedersen blinding generator.</description></item>
/// </list>
/// <para>
/// Hash-to-curve inputs for the three categories, with
/// <c>seed = WellKnownHyraxDomainLabels.CanonicalSeedV1</c> for the
/// reference protocol:
/// </para>
/// <list type="bullet">
///   <item><description><c>G_i</c>: UTF-8(seed) || UTF-8(".generator") || i as 4-byte big-endian.</description></item>
///   <item><description><c>H</c>: UTF-8(seed) || UTF-8(".blinding").</description></item>
///   <item><description><c>U</c>: UTF-8(seed) || UTF-8(".value").</description></item>
/// </list>
/// <para>
/// The DST passed to hash-to-curve is
/// <see cref="WellKnownHyraxDomainLabels.CommitmentKeyDst"/>. Every
/// resulting point lies in the prime-order subgroup of G1 by the
/// hash-to-curve construction (RFC 9380 §3, cofactor clearing
/// included). The derivation is byte-exact reproducible: two callers
/// supplying the same seed, vector length, and curve receive
/// byte-identical buffers.
/// </para>
/// </remarks>
public sealed class HyraxCommitmentKey: SensitiveMemory
{
    /// <summary>The number of Pedersen vector generators (<c>G_0..G_{VectorLength - 1}</c>).</summary>
    public int VectorLength { get; }

    /// <summary>The curve identifying the underlying group.</summary>
    public CurveParameterSet Curve { get; }

    /// <summary>The seed used to derive this key. Two keys with the same seed, vector length, and curve are byte-identical.</summary>
    public string Seed { get; }


    /// <summary>
    /// Constructs a commitment key over a buffer the caller has
    /// already populated. The instance takes ownership of
    /// <paramref name="owner"/>.
    /// </summary>
    internal HyraxCommitmentKey(
        IMemoryOwner<byte> owner,
        int vectorLength,
        CurveParameterSet curve,
        string seed,
        Tag tag)
        : base(owner, GetBufferSizeBytes(vectorLength, curve), tag)
    {
        VectorLength = vectorLength;
        Curve = curve;
        Seed = seed;
    }


    /// <summary>
    /// Derives a Hyrax commitment key with the requested vector length
    /// by repeated hash-to-curve from the supplied seed.
    /// </summary>
    /// <param name="vectorLength">The number of Pedersen vector generators to derive. Must be positive.</param>
    /// <param name="seed">The protocol-identifying seed string. Use <see cref="WellKnownHyraxDomainLabels.CanonicalSeedV1"/> for the batch-E reference.</param>
    /// <param name="curve">The curve. Currently only <see cref="CurveParameterSet.Bls12Curve381"/> is supported.</param>
    /// <param name="hashToCurve">The backend hash-to-curve implementation.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <returns>A commitment key wrapping the derived generators, the blinding generator <c>H</c>, and the value generator <c>U</c>.</returns>
    /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="vectorLength"/> is non-positive.</exception>
    /// <exception cref="ArgumentException">When <paramref name="curve"/> is not BLS12-381.</exception>
    public static HyraxCommitmentKey Derive(
        int vectorLength,
        string seed,
        CurveParameterSet curve,
        G1HashToCurveDelegate hashToCurve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(seed);
        ArgumentNullException.ThrowIfNull(hashToCurve);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(vectorLength);

        WellKnownCurves.ThrowIfCurveNotWired(curve);

        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(curve);
        int totalSize = GetBufferSizeBytes(vectorLength, curve);
        IMemoryOwner<byte> owner = pool.Rent(totalSize);
        Span<byte> buffer = owner.Memory.Span[..totalSize];

        byte[] seedBytes = Encoding.UTF8.GetBytes(seed);
        byte[] generatorSuffix = Encoding.UTF8.GetBytes(WellKnownHyraxDomainLabels.GeneratorSuffix);
        byte[] blindingSuffix = Encoding.UTF8.GetBytes(WellKnownHyraxDomainLabels.BlindingSuffix);
        byte[] valueSuffix = Encoding.UTF8.GetBytes(WellKnownHyraxDomainLabels.ValueSuffix);
        byte[] dst = Encoding.UTF8.GetBytes(WellKnownHyraxDomainLabels.CommitmentKeyDst);

        //Vector generators G_0..G_{vectorLength-1}: hash-to-curve over
        //seed || ".generator" || i_BE for each i.
        int generatorInputLength = seedBytes.Length + generatorSuffix.Length + sizeof(int);
        using IMemoryOwner<byte> generatorInputOwner = pool.Rent(generatorInputLength);
        Span<byte> generatorInput = generatorInputOwner.Memory.Span[..generatorInputLength];
        seedBytes.CopyTo(generatorInput);
        generatorSuffix.CopyTo(generatorInput[seedBytes.Length..]);
        Span<byte> generatorIndexSlot = generatorInput.Slice(seedBytes.Length + generatorSuffix.Length, sizeof(int));

        for(int i = 0; i < vectorLength; i++)
        {
            BinaryPrimitives.WriteInt32BigEndian(generatorIndexSlot, i);
            Span<byte> destination = buffer.Slice(i * g1Size, g1Size);
            //The inbound tag here is just a placeholder — the per-generator
            //provenance is captured by the commitment key's own Tag, not by
            //the individual generator slots.
            _ = hashToCurve(generatorInput, dst, destination, curve, Tag.Empty);
        }

        //Blinding generator H: hash-to-curve over seed || ".blinding".
        int blindingInputLength = seedBytes.Length + blindingSuffix.Length;
        using IMemoryOwner<byte> blindingInputOwner = pool.Rent(blindingInputLength);
        Span<byte> blindingInput = blindingInputOwner.Memory.Span[..blindingInputLength];
        seedBytes.CopyTo(blindingInput);
        blindingSuffix.CopyTo(blindingInput[seedBytes.Length..]);
        Span<byte> blindingDestination = buffer.Slice(vectorLength * g1Size, g1Size);
        _ = hashToCurve(blindingInput, dst, blindingDestination, curve, Tag.Empty);

        //Value generator U: hash-to-curve over seed || ".value".
        int valueInputLength = seedBytes.Length + valueSuffix.Length;
        using IMemoryOwner<byte> valueInputOwner = pool.Rent(valueInputLength);
        Span<byte> valueInput = valueInputOwner.Memory.Span[..valueInputLength];
        seedBytes.CopyTo(valueInput);
        valueSuffix.CopyTo(valueInput[seedBytes.Length..]);
        Span<byte> valueDestination = buffer.Slice((vectorLength + 1) * g1Size, g1Size);
        _ = hashToCurve(valueInput, dst, valueDestination, curve, Tag.Empty);

        Tag tag = Tag.Create(
            (typeof(AlgebraicRole), (object)AlgebraicRole.CommitmentKey),
            (typeof(CurveParameterSet), (object)curve),
            (typeof(CommitmentScheme), (object)CommitmentScheme.Hyrax),
            (typeof(string), (object)seed));

        return new HyraxCommitmentKey(owner, vectorLength, curve, seed, tag);
    }


    /// <summary>
    /// Returns the canonical 48-byte compressed bytes of the
    /// <c>i</c>'th vector generator <c>G_i</c>.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="index"/> is outside <c>[0, VectorLength)</c>.</exception>
    public ReadOnlySpan<byte> GetGenerator(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(index, VectorLength);

        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
        return AsReadOnlySpan().Slice(index * g1Size, g1Size);
    }


    /// <summary>Returns the canonical compressed bytes of the Pedersen blinding generator <c>H</c>.</summary>
    public ReadOnlySpan<byte> GetBlindingGenerator()
    {
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
        return AsReadOnlySpan().Slice(VectorLength * g1Size, g1Size);
    }


    /// <summary>Returns the canonical compressed bytes of the IPA value generator <c>U</c>.</summary>
    public ReadOnlySpan<byte> GetValueGenerator()
    {
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
        return AsReadOnlySpan().Slice((VectorLength + 1) * g1Size, g1Size);
    }


    /// <summary>
    /// Returns the total byte size of a commitment key buffer for the
    /// supplied vector length, including the blinding and value
    /// generators.
    /// </summary>
    public static int GetBufferSizeBytes(int vectorLength, CurveParameterSet curve)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(vectorLength);

        return (vectorLength + 2) * WellKnownCurves.GetG1CompressedSizeBytes(curve);
    }
}