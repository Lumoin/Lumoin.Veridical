using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Numerics;

namespace Lumoin.Veridical.Core.Commitments.Whir;

/// <summary>
/// One committed mask group of the hiding WHIR path: <c>width</c> univariate
/// mask polynomials over the scalar field, each encoded under the group's
/// zero-knowledge mask code and committed together as one interleaved oracle,
/// so a single Merkle path authenticates every member's value at an opened
/// position. The masked sumcheck (eprint 2026/391 Construction 6.3,
/// steps 1-2) commits one group of <c>k</c> freshly sampled masks per fold
/// batch; a code-switch round (Construction 9.7) commits a width-one group
/// whose message is the folded oracle randomness followed by the private
/// out-of-domain pad; the masked base case (Construction 7.2) commits one
/// fresh blind group per carried group.
/// </summary>
/// <remarks>
/// <para>
/// The mask coefficients and their encoding randomness are prover-only
/// witnesses: the coefficients feed the round-polynomial assembly and the
/// code-switch composition's auxiliary claims, and the base case reveals
/// blinded combinations of the raw randomness. Both live in pooled memory and
/// are scrubbed by the pool on disposal.
/// </para>
/// <para>
/// The interleaved leaf at position <c>z</c> holds every mask's codeword
/// value at <c>z</c>, padded with zero elements to the next power-of-two row
/// width — the leaf digest is a binary fold, and the deterministic padding
/// lets both endpoints recompute identical digests from <c>k</c> revealed
/// values.
/// </para>
/// </remarks>
public sealed class ZkWhirMaskGroup: IDisposable
{
    /// <summary>The byte size of one field element.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>
    /// The member-count cap: the cube scale <c>2^(k-1)</c> and the round
    /// scales <c>2^(k-j)</c> are injected through a 32-bit canonical write,
    /// and every admissible schedule sits far below this, so the cap is a
    /// loud guard, not a working bound.
    /// </summary>
    private const int MaximumMaskCount = 32;

    //The tree field backs the disposal-guarded public accessor below and the
    //disposed flag mutates on disposal; both are the articulable field cases.
    private readonly MerkleTree tree;
    private bool disposed;


    /// <summary>The pooled mask coefficients, <c>MaskCount · MessageLength</c> elements; scrubbed by the pool on disposal.</summary>
    private IMemoryOwner<byte> CoefficientsOwner { get; }

    /// <summary>The pooled encoding randomness, <c>MaskCount · RandomnessLength</c> elements; scrubbed by the pool on disposal.</summary>
    private IMemoryOwner<byte> EncodingRandomnessOwner { get; }

    /// <summary>The pooled interleaved leaves the spot-check openings reveal from.</summary>
    private IMemoryOwner<byte> LeavesOwner { get; }


    /// <summary>The mask code every mask in the batch is encoded under.</summary>
    public WhirMaskCodeShape Shape { get; }

    /// <summary>The number of masks — the fold batch's sumcheck round count <c>k</c>.</summary>
    public int MaskCount { get; }

    /// <summary>The interleaved leaf row width: <c>MaskCount</c> rounded up to a power of two, zero-padded.</summary>
    public int PaddedRowWidth { get; }

    /// <summary>The curve whose scalar field the masks live in.</summary>
    public CurveParameterSet Curve { get; }

    /// <summary>The batch's mask oracle tree; its root is the public commitment.</summary>
    public MerkleTree Tree
    {
        get
        {
            ObjectDisposedException.ThrowIf(disposed, this);

            return tree;
        }
    }

    /// <summary>
    /// The interleaved codeword in leaf order: position <c>z</c> occupies
    /// <c>PaddedRowWidth</c> elements of which the first
    /// <c>MaskCount</c> carry the masks' values at <c>z</c> — the buffer the
    /// spot-check openings reveal from.
    /// </summary>
    public ReadOnlySpan<byte> InterleavedLeaves
    {
        get
        {
            ObjectDisposedException.ThrowIf(disposed, this);

            return LeavesOwner.Memory.Span[..(Shape.DomainSize * PaddedRowWidth * ScalarSize)];
        }
    }


    private ZkWhirMaskGroup(
        WhirMaskCodeShape shape,
        int maskCount,
        int paddedRowWidth,
        CurveParameterSet curve,
        IMemoryOwner<byte> coefficientsOwner,
        IMemoryOwner<byte> encodingRandomnessOwner,
        IMemoryOwner<byte> leavesOwner,
        MerkleTree tree)
    {
        Shape = shape;
        MaskCount = maskCount;
        PaddedRowWidth = paddedRowWidth;
        Curve = curve;
        CoefficientsOwner = coefficientsOwner;
        EncodingRandomnessOwner = encodingRandomnessOwner;
        LeavesOwner = leavesOwner;
        this.tree = tree;
    }


    /// <summary>
    /// Samples, encodes and commits one batch of sumcheck masks: every mask
    /// coefficient and every encoding-randomness element is drawn fresh from
    /// <paramref name="maskRandom"/>, each mask is encoded under the batch's
    /// mask code, and the interleaved codewords are committed as one Merkle
    /// tree.
    /// </summary>
    /// <param name="shape">The mask code shape, from <see cref="WhirZkParameters.SumcheckMaskShape"/>.</param>
    /// <param name="maskCount">The mask count <c>k</c>, the fold batch's round count; at least 1.</param>
    /// <param name="encoder">The coset encoder routing the mask encodes.</param>
    /// <param name="merkleHash">The two-to-one Merkle compression.</param>
    /// <param name="maskRandom">The entropy-sourced sampler for the mask coefficients and encoding randomness.</param>
    /// <param name="curve">The curve whose scalar field the masks live in.</param>
    /// <param name="pool">The pool every buffer rents from.</param>
    /// <returns>The committed batch; the caller owns its disposal.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="maskCount"/> is not positive.</exception>
    public static ZkWhirMaskGroup Create(
        WhirMaskCodeShape shape,
        int maskCount,
        WhirCosetEncoder encoder,
        MerkleHashDelegate merkleHash,
        ScalarRandomDelegate maskRandom,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(encoder);
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(maskRandom);
        ArgumentNullException.ThrowIfNull(pool);
        ValidateGroupShape(maskCount, curve);

        int coefficientsLength = maskCount * shape.MessageLength * ScalarSize;
        IMemoryOwner<byte>? coefficientsOwner = null;
        try
        {
            coefficientsOwner = pool.Rent(coefficientsLength);
            FillWithScalars(coefficientsOwner.Memory.Span[..coefficientsLength], maskRandom, curve);
        }
        catch
        {
            coefficientsOwner?.Dispose();
            throw;
        }

        return CreateCore(shape, maskCount, coefficientsOwner, encoder, merkleHash, maskRandom, curve, pool);
    }


    /// <summary>
    /// Encodes and commits a group whose messages the caller supplies — the
    /// code-switch masks, whose message is the folded oracle randomness
    /// followed by the fresh out-of-domain pad, and any group whose message
    /// is protocol-derived rather than freshly sampled. The encoding
    /// randomness is still drawn fresh from <paramref name="maskRandom"/>.
    /// </summary>
    /// <param name="shape">The group's mask code shape.</param>
    /// <param name="maskCount">The member count; at least 1.</param>
    /// <param name="messages">The member messages, <c>maskCount · MessageLength</c> concatenated elements; copied into pooled storage.</param>
    /// <param name="encoder">The coset encoder routing the mask encodes.</param>
    /// <param name="merkleHash">The two-to-one Merkle compression.</param>
    /// <param name="maskRandom">The entropy-sourced sampler for the encoding randomness.</param>
    /// <param name="curve">The curve whose scalar field the masks live in.</param>
    /// <param name="pool">The pool every buffer rents from.</param>
    /// <returns>The committed group; the caller owns its disposal.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="maskCount"/> is out of range.</exception>
    /// <exception cref="ArgumentException">When <paramref name="messages"/> does not match the shape.</exception>
    public static ZkWhirMaskGroup CreateFromMessages(
        WhirMaskCodeShape shape,
        int maskCount,
        ReadOnlySpan<byte> messages,
        WhirCosetEncoder encoder,
        MerkleHashDelegate merkleHash,
        ScalarRandomDelegate maskRandom,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(encoder);
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(maskRandom);
        ArgumentNullException.ThrowIfNull(pool);
        ValidateGroupShape(maskCount, curve);

        int coefficientsLength = maskCount * shape.MessageLength * ScalarSize;
        if(messages.Length != coefficientsLength)
        {
            throw new ArgumentException(
                $"The messages must carry {maskCount * shape.MessageLength} elements ({coefficientsLength} bytes); received {messages.Length}.",
                nameof(messages));
        }

        IMemoryOwner<byte>? coefficientsOwner = null;
        try
        {
            coefficientsOwner = pool.Rent(coefficientsLength);
            messages.CopyTo(coefficientsOwner.Memory.Span[..coefficientsLength]);
        }
        catch
        {
            coefficientsOwner?.Dispose();
            throw;
        }

        return CreateCore(shape, maskCount, coefficientsOwner, encoder, merkleHash, maskRandom, curve, pool);
    }


    /// <summary>
    /// Validates the member count and curve wiring shared by both factories.
    /// </summary>
    private static void ValidateGroupShape(int maskCount, CurveParameterSet curve)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maskCount);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(maskCount, MaximumMaskCount);
        WellKnownCurves.ThrowIfCurveNotWired(curve);
    }


    /// <summary>
    /// Encodes the pooled messages, samples the encoding randomness, commits
    /// the interleaved codewords and assembles the group. Takes ownership of
    /// <paramref name="coefficientsOwner"/> on every path.
    /// </summary>
    private static ZkWhirMaskGroup CreateCore(
        WhirMaskCodeShape shape,
        int maskCount,
        IMemoryOwner<byte> coefficientsOwner,
        WhirCosetEncoder encoder,
        MerkleHashDelegate merkleHash,
        ScalarRandomDelegate maskRandom,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        int coefficientsLength = maskCount * shape.MessageLength * ScalarSize;
        int randomnessLength = maskCount * shape.RandomnessLength * ScalarSize;
        int paddedRowWidth = (int)BitOperations.RoundUpToPowerOf2((uint)maskCount);
        int leavesLength = shape.DomainSize * paddedRowWidth * ScalarSize;

        IMemoryOwner<byte>? encodingRandomnessOwner = null;
        IMemoryOwner<byte>? leavesOwner = null;
        MerkleTree? tree = null;
        try
        {
            Span<byte> coefficients = coefficientsOwner.Memory.Span[..coefficientsLength];

            encodingRandomnessOwner = pool.Rent(randomnessLength);
            Span<byte> encodingRandomness = encodingRandomnessOwner.Memory.Span[..randomnessLength];
            FillWithScalars(encodingRandomness, maskRandom, curve);

            leavesOwner = pool.Rent(leavesLength);
            Span<byte> leaves = leavesOwner.Memory.Span[..leavesLength];
            leaves.Clear();

            //Encode each mask into natural order, then scatter position z of
            //mask j into row z, column j of the interleaved leaf matrix.
            using IMemoryOwner<byte> naturalOwner = pool.Rent(shape.DomainSize * ScalarSize);
            Span<byte> natural = naturalOwner.Memory.Span[..(shape.DomainSize * ScalarSize)];
            for(int mask = 0; mask < maskCount; mask++)
            {
                encoder.EncodeWithRandomness(
                    coefficients.Slice(mask * shape.MessageLength * ScalarSize, shape.MessageLength * ScalarSize),
                    encodingRandomness.Slice(mask * shape.RandomnessLength * ScalarSize, shape.RandomnessLength * ScalarSize),
                    shape.DomainSizeLog2,
                    natural);
                for(int position = 0; position < shape.DomainSize; position++)
                {
                    natural.Slice(position * ScalarSize, ScalarSize)
                        .CopyTo(leaves.Slice(((position * paddedRowWidth) + mask) * ScalarSize, ScalarSize));
                }
            }

            using IMemoryOwner<byte> digestsOwner = pool.Rent(shape.DomainSize * ScalarSize);
            Span<byte> digests = digestsOwner.Memory.Span[..(shape.DomainSize * ScalarSize)];
            WhirCosetLeaf.ComputeLeafDigests(leaves, shape.DomainSize, paddedRowWidth, merkleHash, digests, pool);
            tree = MerkleTree.Build(digests, shape.DomainSize, merkleHash, pool);

            return new ZkWhirMaskGroup(shape, maskCount, paddedRowWidth, curve, coefficientsOwner, encodingRandomnessOwner, leavesOwner, tree);
        }
        catch
        {
            tree?.Dispose();
            leavesOwner?.Dispose();
            encodingRandomnessOwner?.Dispose();
            coefficientsOwner.Dispose();
            throw;
        }
    }


    /// <summary>
    /// The coefficient vector of mask <paramref name="maskIndex"/> —
    /// <c>ℓ_zk</c> elements, a prover-only witness.
    /// </summary>
    /// <param name="maskIndex">The mask index in <c>0..MaskCount-1</c>.</param>
    /// <returns>The coefficients in ascending degree order.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When the index is out of range.</exception>
    public ReadOnlySpan<byte> MaskCoefficients(int maskIndex)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ArgumentOutOfRangeException.ThrowIfNegative(maskIndex);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(maskIndex, MaskCount);

        return CoefficientsOwner.Memory.Span.Slice(maskIndex * Shape.MessageLength * ScalarSize, Shape.MessageLength * ScalarSize);
    }


    /// <summary>
    /// The encoding-randomness vector of mask <paramref name="maskIndex"/> —
    /// <c>t_zk</c> elements, a prover-only witness the base case's blinded
    /// reveals combine.
    /// </summary>
    /// <param name="maskIndex">The mask index in <c>0..MaskCount-1</c>.</param>
    /// <returns>The randomness elements in ascending degree order.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When the index is out of range.</exception>
    public ReadOnlySpan<byte> EncodingRandomness(int maskIndex)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ArgumentOutOfRangeException.ThrowIfNegative(maskIndex);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(maskIndex, MaskCount);

        return EncodingRandomnessOwner.Memory.Span.Slice(maskIndex * Shape.RandomnessLength * ScalarSize, Shape.RandomnessLength * ScalarSize);
    }


    /// <summary>
    /// Writes the endpoint sum <c>s_j(0) + s_j(1) = 2·c_0 + Σ_(i≥1) c_i</c>
    /// of one mask.
    /// </summary>
    /// <param name="maskIndex">The mask index in <c>0..MaskCount-1</c>.</param>
    /// <param name="destination">Receives the sum, one element.</param>
    /// <param name="add">Scalar-add backend.</param>
    /// <exception cref="ArgumentOutOfRangeException">When the index is out of range.</exception>
    public void WriteEndpointSum(int maskIndex, Span<byte> destination, ScalarAddDelegate add)
    {
        ArgumentNullException.ThrowIfNull(add);

        ReadOnlySpan<byte> mask = MaskCoefficients(maskIndex);

        //2·c_0 + Σ_(i≥1) c_i = c_0 + Σ_(i≥0) c_i.
        mask[..ScalarSize].CopyTo(destination);
        for(int i = 0; i < Shape.MessageLength; i++)
        {
            add(destination, mask.Slice(i * ScalarSize, ScalarSize), destination, Curve);
        }
    }


    /// <summary>
    /// Writes the mask total
    /// <c>μ̃ = 2^(k-1) · Σ_j (s_j(0) + s_j(1))</c> — the sum of every mask's
    /// evaluations over the batch's Boolean cube, sent on the transcript
    /// before any challenge.
    /// </summary>
    /// <param name="destination">Receives the total, one element.</param>
    /// <param name="add">Scalar-add backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    public void WriteMaskTotal(Span<byte> destination, ScalarAddDelegate add, ScalarMultiplyDelegate multiply)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(multiply);
        ObjectDisposedException.ThrowIf(disposed, this);

        Span<byte> endpointSum = stackalloc byte[ScalarSize];
        destination[..ScalarSize].Clear();
        for(int mask = 0; mask < MaskCount; mask++)
        {
            WriteEndpointSum(mask, endpointSum, add);
            add(destination, endpointSum, destination, Curve);
        }

        Span<byte> scale = stackalloc byte[ScalarSize];
        WriteCanonicalUInt(1u << (MaskCount - 1), scale);
        multiply(destination, scale, destination, Curve);
    }


    /// <summary>
    /// Evaluates one mask at a point by Horner's rule.
    /// </summary>
    /// <param name="maskIndex">The mask index in <c>0..MaskCount-1</c>.</param>
    /// <param name="point">The evaluation point, one element.</param>
    /// <param name="destination">Receives the value, one element.</param>
    /// <param name="add">Scalar-add backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <exception cref="ArgumentOutOfRangeException">When the index is out of range.</exception>
    public void EvaluateMask(
        int maskIndex,
        ReadOnlySpan<byte> point,
        Span<byte> destination,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(multiply);

        ReadOnlySpan<byte> mask = MaskCoefficients(maskIndex);

        mask[((Shape.MessageLength - 1) * ScalarSize)..].CopyTo(destination);
        for(int i = Shape.MessageLength - 2; i >= 0; i--)
        {
            multiply(destination, point, destination, Curve);
            add(destination, mask.Slice(i * ScalarSize, ScalarSize), destination, Curve);
        }
    }


    /// <summary>
    /// Writes the mask residual <c>Σ_j s_j(γ_j)</c> for the batch's sampled
    /// challenges — the mask part of the final masked-sumcheck target, the
    /// closed form of the live/past/future recurrence the round polynomials
    /// carry (eprint 2026/391 Construction 6.3).
    /// </summary>
    /// <param name="challenges">The per-round challenges <c>γ_1..γ_k</c>, <c>MaskCount</c> elements.</param>
    /// <param name="destination">Receives the residual, one element.</param>
    /// <param name="add">Scalar-add backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <exception cref="ArgumentException">When <paramref name="challenges"/> does not carry <c>MaskCount</c> elements.</exception>
    public void WriteMaskResidual(
        ReadOnlySpan<byte> challenges,
        Span<byte> destination,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(multiply);
        ObjectDisposedException.ThrowIf(disposed, this);
        if(challenges.Length != MaskCount * ScalarSize)
        {
            throw new ArgumentException(
                $"The challenges must carry {MaskCount} elements ({MaskCount * ScalarSize} bytes); received {challenges.Length}.",
                nameof(challenges));
        }

        Span<byte> value = stackalloc byte[ScalarSize];
        destination[..ScalarSize].Clear();
        for(int mask = 0; mask < MaskCount; mask++)
        {
            EvaluateMask(mask, challenges.Slice(mask * ScalarSize, ScalarSize), value, add, multiply);
            add(destination, value, destination, Curve);
        }
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        disposed = true;
        tree.Dispose();
        LeavesOwner.Dispose();
        EncodingRandomnessOwner.Dispose();
        CoefficientsOwner.Dispose();
    }


    /// <summary>
    /// Fills a buffer with freshly sampled canonical scalars, one delegate
    /// call per element.
    /// </summary>
    private static void FillWithScalars(Span<byte> destination, ScalarRandomDelegate random, CurveParameterSet curve)
    {
        for(int offset = 0; offset < destination.Length; offset += ScalarSize)
        {
            _ = random(destination.Slice(offset, ScalarSize), curve, WellKnownAlgebraicTags.ScalarFor(curve));
        }
    }


    /// <summary>
    /// Writes a small integer as a canonical big-endian field element.
    /// </summary>
    private static void WriteCanonicalUInt(uint value, Span<byte> destination)
    {
        destination.Clear();
        BinaryPrimitives.WriteUInt32BigEndian(destination[(ScalarSize - sizeof(uint))..], value);
    }
}
