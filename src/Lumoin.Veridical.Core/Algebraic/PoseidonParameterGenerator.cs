using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Deterministic Poseidon parameter generation per the reference Grain-LFSR
/// procedure (the <c>generate_parameters_grain</c> script of the Poseidon
/// authors). Generating for BN254 at circomlib's round counts reproduces
/// circomlib's constants byte-for-byte. Both supported curves use this
/// generator, which derives constants for any accepted width and round
/// counts without embedded constant tables.
/// </summary>
/// <remarks>
/// <para>
/// The Grain stream uses an 80-bit LFSR seeded with the parameter descriptor —
/// 2 bits field type (1 = prime field), 4 bits S-box type (0 = <c>x^α</c>),
/// 12 bits field size <c>n</c>, 12 bits <c>t</c>, 10 bits <c>R_F</c>, 10
/// bits <c>R_P</c>, then 30 one-bits — each sub-field most-significant-bit
/// first. Feedback <c>b_{i+80} = b_{i+62} ⊕ b_{i+51} ⊕ b_{i+38} ⊕ b_{i+23}
/// ⊕ b_{i+13} ⊕ b_i</c>; the first 160 bits are discarded; output bits are
/// then taken pairwise (emit the second bit when the first is 1, discard it
/// otherwise). A field element samples <c>n</c> filtered bits MSB-first and
/// rejects values ≥ the modulus. Round constants are drawn sequentially,
/// <c>(R_F + R_P) · t</c> of them; the MDS matrix is the Cauchy matrix
/// <c>M[i][j] = (x_i + y_j)^{−1}</c> whose <c>2t</c> points continue the
/// same stream — drawn as raw <c>n</c>-bit values without rejection
/// sampling, reduced once mod the modulus (the reference script's
/// <c>create_mds_p</c> takes them unrejected).
/// </para>
/// </remarks>
public static class PoseidonParameterGenerator
{
    /// <summary>The canonical byte width of one scalar, used for the modulus, sampled elements and MDS entries.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The number of bits in one byte of the canonical big-endian modulus.</summary>
    private const int BitsPerByte = 8;

    /// <summary>The 80-bit register width specified by the reference Grain LFSR procedure.</summary>
    private const int LfsrStateBits = 80;

    /// <summary>The 160 initial raw bits discarded to warm up the register as the reference Grain procedure requires.</summary>
    private const int DiscardedWarmupBits = 160;

    /// <summary>The two-bit field-type slot in the reference Grain parameter descriptor.</summary>
    private const int FieldTypeBits = 2;

    /// <summary>The four-bit S-box-type slot in the reference Grain parameter descriptor.</summary>
    private const int SboxTypeBits = 4;

    /// <summary>The twelve-bit modulus-bit-length slot in the reference Grain parameter descriptor.</summary>
    private const int FieldSizeBits = 12;

    /// <summary>The twelve-bit state-width slot in the reference Grain parameter descriptor.</summary>
    private const int StateWidthBits = 12;

    /// <summary>The ten-bit full-round-count slot in the reference Grain parameter descriptor.</summary>
    private const int FullRoundsBits = 10;

    /// <summary>The ten-bit partial-round-count slot in the reference Grain parameter descriptor.</summary>
    private const int PartialRoundsBits = 10;

    /// <summary>The thirty one-bits that complete the reference Grain descriptor's 80-bit initial register state.</summary>
    private const int TrailingOneBits = 30;

    /// <summary>The reference Grain descriptor's code of one for a prime field.</summary>
    private const int PrimeFieldCode = 1;

    /// <summary>The reference Grain descriptor's code of zero for the power S-box <c>x^α</c>.</summary>
    private const int PowerSboxCode = 0;

    /// <summary>The maximum consecutive rejections <see cref="SampleFieldElement"/> tolerates before treating the draw as non-terminating: the bit length is derived from the modulus, so the modulus is at least <c>2^(n-1)</c> and each draw is accepted with probability at least one half, so <c>k</c> consecutive rejections have probability at most <c>2^-k</c>.</summary>
    private const int MaximumFieldElementRejectionAttempts = 128;

    /// <summary>The maximum consecutive gate/candidate pairs <see cref="NextFilteredBit"/> draws before treating the draw as non-terminating: the Grain construction intends the gate bit to be an even chance — not a proven property of this file — so the same one-half-per-draw tail bounds <c>k</c> consecutive misses to at most <c>2^-k</c>.</summary>
    private const int MaximumFilteredBitAttempts = 128;


    /// <summary>
    /// Generates the parameter set for a <paramref name="stateWidth"/>-wide
    /// Poseidon over <paramref name="curve"/>'s scalar field. The Grain descriptor and samplers use the bit
    /// length derived from the scalar-field order supplied by <see cref="WellKnownCurves"/>.
    /// </summary>
    /// <remarks>
    /// The curve supplies the scalar-field order for the round constants and Cauchy MDS entries, and the
    /// addition and inversion backends operate over that same curve.
    /// </remarks>
    /// <param name="stateWidth">The state width <c>t</c>; at least 2.</param>
    /// <param name="fullRounds">The full round count <c>R_F</c>; positive and even.</param>
    /// <param name="partialRounds">The partial round count <c>R_P</c>; positive.</param>
    /// <param name="curve">The curve the parameters are for.</param>
    /// <param name="add">Scalar-addition backend (sums the Cauchy points).</param>
    /// <param name="invert">Scalar-inversion backend (builds the Cauchy MDS entries).</param>
    /// <param name="pool">The pool supplying temporary generation buffers.</param>
    /// <returns>The generated parameters.</returns>
    /// <exception cref="ArgumentNullException">When a delegate argument or the pool is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When a numeric argument is out of range.</exception>
    /// <exception cref="ArgumentException">When <paramref name="curve"/> has no wired scalar-field order in <see cref="WellKnownCurves"/>.</exception>
    public static PoseidonParameters Generate(
        int stateWidth,
        int fullRounds,
        int partialRounds,
        CurveParameterSet curve,
        ScalarAddDelegate add,
        ScalarInvertDelegate invert,
        BaseMemoryPool pool)
    {
        ReadOnlySpan<byte> modulus = WellKnownCurves.GetScalarFieldOrderBytes(curve);

        return GenerateOverModulus(stateWidth, fullRounds, partialRounds, modulus, curve, add, invert, pool);
    }


    /// <summary>
    /// Generates parameters with Grain sampling over a nonzero modulus whose bit length supplies the descriptor
    /// and draw width, independently of the curve's scalar-field order.
    /// </summary>
    /// <remarks>
    /// This entry supports draw-by-draw checks over narrow moduli. The modulus governs sampling and reduction;
    /// the caller supplies the addition and inversion behavior, and the result carries the requested curve tag.
    /// </remarks>
    /// <param name="stateWidth">The state width <c>t</c>; at least 2.</param>
    /// <param name="fullRounds">The full round count <c>R_F</c>; positive and even.</param>
    /// <param name="partialRounds">The partial round count <c>R_P</c>; positive.</param>
    /// <param name="modulus">The nonzero sampling modulus, canonical big-endian and one scalar wide.</param>
    /// <param name="curve">The curve tag passed to the backends and carried by the parameters.</param>
    /// <param name="add">Scalar-addition backend (sums the Cauchy points).</param>
    /// <param name="invert">Scalar-inversion backend (builds the Cauchy MDS entries).</param>
    /// <param name="pool">The pool supplying temporary generation buffers.</param>
    /// <returns>The generated parameters.</returns>
    /// <exception cref="ArgumentNullException">When a delegate argument or the pool is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When a numeric argument is out of range.</exception>
    /// <exception cref="ArgumentException">When the modulus is not one scalar wide or is zero.</exception>
    internal static PoseidonParameters GenerateOverModulus(
        int stateWidth,
        int fullRounds,
        int partialRounds,
        ReadOnlySpan<byte> modulus,
        CurveParameterSet curve,
        ScalarAddDelegate add,
        ScalarInvertDelegate invert,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfLessThan(stateWidth, 2);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(fullRounds);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(partialRounds);
        if((fullRounds & 1) != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(fullRounds), "The full rounds split evenly around the partial rounds; the count must be even.");
        }

        if(modulus.Length != ScalarSize)
        {
            throw new ArgumentException($"The modulus must be exactly {ScalarSize} canonical bytes; received {modulus.Length}.", nameof(modulus));
        }

        //The derived bit length keeps each raw n-bit draw below twice the modulus, so one Cauchy subtraction
        //suffices. A zero modulus leaves rejection sampling unable to accept any draw.
        int fieldSizeBits = BitLength(modulus);
        if(fieldSizeBits is 0)
        {
            throw new ArgumentException("The modulus must be nonzero.", nameof(modulus));
        }

        Span<byte> lfsr = stackalloc byte[LfsrStateBits];
        InitialiseLfsr(lfsr, fieldSizeBits, stateWidth, fullRounds, partialRounds);
        int warmup = DiscardedWarmupBits;
        for(int i = 0; i < warmup; i++)
        {
            _ = NextRawBit(lfsr);
        }

        //Draw (R_F + R_P) · t round constants sequentially from the Grain stream.
        int constantCount = checked((fullRounds + partialRounds) * stateWidth);
        int roundConstantsLength = checked(constantCount * ScalarSize);
        using IMemoryOwner<byte> roundConstantsOwner = pool.Rent(roundConstantsLength);
        Span<byte> roundConstants = roundConstantsOwner.Memory.Span[..roundConstantsLength];
        for(int i = 0; i < constantCount; i++)
        {
            SampleFieldElement(lfsr, fieldSizeBits, modulus, roundConstants.Slice(i * ScalarSize, ScalarSize));
        }

        //Continue the stream with 2t raw n-bit Cauchy points without rejection,
        //as the reference create_mds_p requires, then set M[i][j] = (x_i + y_j)^{−1}.
        int cauchyPointsLength = checked(2 * stateWidth * ScalarSize);
        using IMemoryOwner<byte> cauchyPointsOwner = pool.Rent(cauchyPointsLength);
        Span<byte> cauchyPoints = cauchyPointsOwner.Memory.Span[..cauchyPointsLength];
        for(int i = 0; i < 2 * stateWidth; i++)
        {
            SampleRawFieldElement(lfsr, fieldSizeBits, modulus, cauchyPoints.Slice(i * ScalarSize, ScalarSize));
        }

        int mdsLength = checked(stateWidth * stateWidth * ScalarSize);
        using IMemoryOwner<byte> mdsOwner = pool.Rent(mdsLength);
        Span<byte> mds = mdsOwner.Memory.Span[..mdsLength];
        Span<byte> sum = stackalloc byte[ScalarSize];
        for(int row = 0; row < stateWidth; row++)
        {
            ReadOnlySpan<byte> x = cauchyPoints.Slice(row * ScalarSize, ScalarSize);
            for(int column = 0; column < stateWidth; column++)
            {
                add(x, cauchyPoints.Slice((stateWidth + column) * ScalarSize, ScalarSize), sum, curve);
                invert(sum, mds.Slice(((row * stateWidth) + column) * ScalarSize, ScalarSize), curve);
            }
        }

        return new PoseidonParameters(stateWidth, fullRounds, partialRounds, roundConstants, mds, curve);
    }


    /// <summary>
    /// Seeds the 80-bit register with field type, S-box type, modulus bit length, state width, full-round count,
    /// partial-round count and thirty trailing one-bits, each descriptor slot most-significant-bit first.
    /// </summary>
    /// <param name="lfsr">The register storage, one byte per bit.</param>
    /// <param name="fieldSizeBits">The modulus bit length encoded in the descriptor.</param>
    /// <param name="stateWidth">The number of state lanes encoded in the descriptor.</param>
    /// <param name="fullRounds">The full-round count encoded in the descriptor.</param>
    /// <param name="partialRounds">The partial-round count encoded in the descriptor.</param>
    private static void InitialiseLfsr(Span<byte> lfsr, int fieldSizeBits, int stateWidth, int fullRounds, int partialRounds)
    {
        int position = 0;
        WriteBits(lfsr, ref position, PrimeFieldCode, FieldTypeBits);
        WriteBits(lfsr, ref position, PowerSboxCode, SboxTypeBits);
        WriteBits(lfsr, ref position, fieldSizeBits, FieldSizeBits);
        WriteBits(lfsr, ref position, stateWidth, StateWidthBits);
        WriteBits(lfsr, ref position, fullRounds, FullRoundsBits);
        WriteBits(lfsr, ref position, partialRounds, PartialRoundsBits);
        for(int i = 0; i < TrailingOneBits; i++)
        {
            lfsr[position++] = 1;
        }
    }


    /// <summary>Writes a descriptor value most-significant-bit first, using one register byte per bit.</summary>
    /// <param name="lfsr">The register storage receiving the descriptor bits.</param>
    /// <param name="position">The next register position, advanced by the slot width.</param>
    /// <param name="value">The descriptor value to encode.</param>
    /// <param name="width">The descriptor slot width in bits.</param>
    private static void WriteBits(Span<byte> lfsr, ref int position, int value, int width)
    {
        for(int bit = width - 1; bit >= 0; bit--)
        {
            lfsr[position++] = (byte)((value >> bit) & 1);
        }
    }


    /// <summary>
    /// Advances the register by the Grain recurrence
    /// <c>b_{i+80} = b_{i+62} ⊕ b_{i+51} ⊕ b_{i+38} ⊕ b_{i+23} ⊕ b_{i+13} ⊕ b_i</c>.
    /// </summary>
    /// <param name="lfsr">The register storage, shifted forward by one bit.</param>
    /// <returns>The feedback bit appended to the register.</returns>
    private static byte NextRawBit(Span<byte> lfsr)
    {
        byte produced = (byte)(lfsr[62] ^ lfsr[51] ^ lfsr[38] ^ lfsr[23] ^ lfsr[13] ^ lfsr[0]);
        for(int i = 0; i < LfsrStateBits - 1; i++)
        {
            lfsr[i] = lfsr[i + 1];
        }

        lfsr[LfsrStateBits - 1] = produced;

        return produced;
    }


    /// <summary>Filters raw bits pairwise, emitting the second bit only when the first bit is one.</summary>
    /// <param name="lfsr">The register storage advanced until one output bit is accepted.</param>
    /// <returns>The accepted second bit of a raw pair.</returns>
    /// <exception cref="InvalidOperationException">When no gate bit of one is drawn within <see cref="MaximumFilteredBitAttempts"/> attempts.</exception>
    private static byte NextFilteredBit(Span<byte> lfsr)
    {
        for(int attempt = 0; attempt < MaximumFilteredBitAttempts; attempt++)
        {
            byte gate = NextRawBit(lfsr);
            byte candidate = NextRawBit(lfsr);
            if(gate == 1)
            {
                return candidate;
            }
        }

        throw new InvalidOperationException(
            $"The filtered-bit gate draw failed to converge within {MaximumFilteredBitAttempts} attempts.");
    }


    /// <summary>
    /// Samples filtered bits most-significant-bit first into a canonical scalar, rejecting each draw at or above
    /// the modulus. The modulus has bit length <c>n</c>, so every <c>n</c>-bit draw with a clear leading bit is accepted.
    /// </summary>
    /// <param name="lfsr">The register storage advanced for each sampled bit.</param>
    /// <param name="fieldSizeBits">The number of filtered bits per draw, equal to the modulus bit length.</param>
    /// <param name="modulus">The exclusive upper bound, canonical big-endian and one scalar wide.</param>
    /// <param name="destination">The destination for the accepted canonical scalar.</param>
    /// <exception cref="InvalidOperationException">When no draw lands below the modulus within <see cref="MaximumFieldElementRejectionAttempts"/> attempts.</exception>
    private static void SampleFieldElement(Span<byte> lfsr, int fieldSizeBits, ReadOnlySpan<byte> modulus, Span<byte> destination)
    {
        for(int attempt = 0; attempt < MaximumFieldElementRejectionAttempts; attempt++)
        {
            destination.Clear();
            for(int k = 0; k < fieldSizeBits; k++)
            {
                if(NextFilteredBit(lfsr) == 1)
                {
                    //Value bit position counted from the least significant end.
                    int valueBit = fieldSizeBits - 1 - k;
                    destination[ScalarSize - 1 - (valueBit / 8)] |= (byte)(1 << (valueBit % 8));
                }
            }

            if(destination.SequenceCompareTo(modulus) < 0)
            {
                return;
            }
        }

        throw new InvalidOperationException(
            $"The field-element rejection draw failed to converge within {MaximumFieldElementRejectionAttempts} attempts.");
    }


    /// <summary>
    /// Samples filtered bits most-significant-bit first without rejection and reduces the draw once modulo the
    /// modulus. One subtraction suffices because a modulus of at least <c>2^(n-1)</c> keeps every raw
    /// <c>n</c>-bit draw below twice the modulus.
    /// </summary>
    /// <param name="lfsr">The register storage advanced for each sampled bit.</param>
    /// <param name="fieldSizeBits">The number of filtered bits in the draw, equal to the modulus bit length.</param>
    /// <param name="modulus">The reduction modulus, canonical big-endian and one scalar wide.</param>
    /// <param name="destination">The destination for the reduced canonical scalar.</param>
    private static void SampleRawFieldElement(Span<byte> lfsr, int fieldSizeBits, ReadOnlySpan<byte> modulus, Span<byte> destination)
    {
        destination.Clear();
        for(int k = 0; k < fieldSizeBits; k++)
        {
            if(NextFilteredBit(lfsr) == 1)
            {
                //Value bit position counted from the least significant end.
                int valueBit = fieldSizeBits - 1 - k;
                destination[ScalarSize - 1 - (valueBit / 8)] |= (byte)(1 << (valueBit % 8));
            }
        }

        CanonicalScalarReduction.ReduceOnceInPlace(destination, modulus);
    }


    /// <summary>
    /// Returns the bit length of a canonical big-endian value: one more than the position of its highest set bit, or
    /// zero when every byte is zero.
    /// </summary>
    /// <param name="value">The value, canonical big-endian.</param>
    /// <returns>The bit length of <paramref name="value"/>.</returns>
    private static int BitLength(ReadOnlySpan<byte> value)
    {
        int leadingIndex = value.IndexOfAnyExcept((byte)0);
        if(leadingIndex < 0)
        {
            return 0;
        }

        int bitsInLeadingByte = (sizeof(uint) * BitsPerByte) - BitOperations.LeadingZeroCount(value[leadingIndex]);

        return ((value.Length - 1 - leadingIndex) * BitsPerByte) + bitsInLeadingByte;
    }
}
