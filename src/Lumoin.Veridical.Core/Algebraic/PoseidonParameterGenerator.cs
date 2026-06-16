using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Deterministic Poseidon parameter generation per the reference Grain-LFSR
/// procedure (the <c>generate_parameters_grain</c> script of the Poseidon
/// authors — the same procedure circomlib's pinned constants were produced
/// with, so generating for BN254 at circomlib's round counts reproduces
/// circomlib's constants byte-for-byte; the known-answer tests gate this).
/// Derive-don't-embed: no constant tables ship, both wired curves are served
/// by the one generator, and any (width, rounds) shape is constructible.
/// </summary>
/// <remarks>
/// <para>
/// The Grain stream: an 80-bit LFSR seeded with the parameter descriptor —
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
/// same stream — drawn as raw <c>n</c>-bit values WITHOUT rejection
/// sampling, reduced once mod the modulus (the reference script's
/// <c>create_mds_p</c> takes them unrejected; circomlib's tables pin this
/// asymmetry, and the known-answer tests gate it).
/// </para>
/// </remarks>
public static class PoseidonParameterGenerator
{
    private const int ScalarSize = Scalar.SizeBytes;

    //The Grain LFSR's 80-bit state and the descriptor sub-field widths.
    private const int LfsrStateBits = 80;
    private const int DiscardedWarmupBits = 160;
    private const int FieldTypeBits = 2;
    private const int SboxTypeBits = 4;
    private const int FieldSizeBits = 12;
    private const int StateWidthBits = 12;
    private const int FullRoundsBits = 10;
    private const int PartialRoundsBits = 10;
    private const int TrailingOneBits = 30;

    //Descriptor codes: prime field, x^alpha S-box.
    private const int PrimeFieldCode = 1;
    private const int PowerSboxCode = 0;


    /// <summary>
    /// Generates the parameter set for a <paramref name="stateWidth"/>-wide
    /// Poseidon over the scalar field described by
    /// <paramref name="modulus"/> (canonical big-endian) of
    /// <paramref name="fieldSizeBits"/> bits.
    /// </summary>
    /// <param name="stateWidth">The state width <c>t</c>; at least 2.</param>
    /// <param name="fullRounds">The full round count <c>R_F</c>; positive and even.</param>
    /// <param name="partialRounds">The partial round count <c>R_P</c>; positive.</param>
    /// <param name="fieldSizeBits">The modulus bit length <c>n</c> (254 for BN254, 255 for BLS12-381).</param>
    /// <param name="modulus">The scalar-field modulus, canonical big-endian, one scalar wide.</param>
    /// <param name="curve">The curve the parameters are for.</param>
    /// <param name="add">Scalar-addition backend (sums the Cauchy points).</param>
    /// <param name="invert">Scalar-inversion backend (builds the Cauchy MDS entries).</param>
    /// <returns>The generated parameters.</returns>
    /// <exception cref="ArgumentNullException">When a delegate argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When a numeric argument is out of range.</exception>
    /// <exception cref="ArgumentException">When the modulus is not one scalar wide.</exception>
    public static PoseidonParameters Generate(
        int stateWidth,
        int fullRounds,
        int partialRounds,
        int fieldSizeBits,
        ReadOnlySpan<byte> modulus,
        CurveParameterSet curve,
        ScalarAddDelegate add,
        ScalarInvertDelegate invert)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentOutOfRangeException.ThrowIfLessThan(stateWidth, 2);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(fullRounds);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(partialRounds);
        if((fullRounds & 1) != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(fullRounds), "The full rounds split evenly around the partial rounds; the count must be even.");
        }

        if(fieldSizeBits <= 0 || fieldSizeBits > 8 * ScalarSize)
        {
            throw new ArgumentOutOfRangeException(nameof(fieldSizeBits));
        }

        if(modulus.Length != ScalarSize)
        {
            throw new ArgumentException($"The modulus must be exactly {ScalarSize} canonical bytes; received {modulus.Length}.", nameof(modulus));
        }

        Span<byte> lfsr = stackalloc byte[LfsrStateBits];
        InitialiseLfsr(lfsr, fieldSizeBits, stateWidth, fullRounds, partialRounds);
        int warmup = DiscardedWarmupBits;
        for(int i = 0; i < warmup; i++)
        {
            _ = NextRawBit(lfsr);
        }

        //Round constants: (R_F + R_P) · t field elements drawn sequentially.
        int constantCount = (fullRounds + partialRounds) * stateWidth;
        byte[] roundConstants = new byte[constantCount * ScalarSize];
        for(int i = 0; i < constantCount; i++)
        {
            SampleFieldElement(lfsr, fieldSizeBits, modulus, roundConstants.AsSpan(i * ScalarSize, ScalarSize));
        }

        //The Cauchy MDS: 2t points continue the stream as raw n-bit draws
        //(no rejection — the reference create_mds_p takes them unrejected,
        //which circomlib's tables pin), then M[i][j] = (x_i + y_j)^{−1}.
        byte[] cauchyPoints = new byte[2 * stateWidth * ScalarSize];
        for(int i = 0; i < 2 * stateWidth; i++)
        {
            SampleRawFieldElement(lfsr, fieldSizeBits, modulus, cauchyPoints.AsSpan(i * ScalarSize, ScalarSize));
        }

        byte[] mds = new byte[stateWidth * stateWidth * ScalarSize];
        Span<byte> sum = stackalloc byte[ScalarSize];
        for(int row = 0; row < stateWidth; row++)
        {
            ReadOnlySpan<byte> x = cauchyPoints.AsSpan(row * ScalarSize, ScalarSize);
            for(int column = 0; column < stateWidth; column++)
            {
                add(x, cauchyPoints.AsSpan((stateWidth + column) * ScalarSize, ScalarSize), sum, curve);
                invert(sum, mds.AsSpan(((row * stateWidth) + column) * ScalarSize, ScalarSize), curve);
            }
        }

        return new PoseidonParameters(stateWidth, fullRounds, partialRounds, roundConstants, mds, curve);
    }


    //The 80-bit descriptor: field type ‖ sbox type ‖ n ‖ t ‖ R_F ‖ R_P ‖ 1^30,
    //each sub-field MSB-first, stored one bit per byte slot.
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


    private static void WriteBits(Span<byte> lfsr, ref int position, int value, int width)
    {
        for(int bit = width - 1; bit >= 0; bit--)
        {
            lfsr[position++] = (byte)((value >> bit) & 1);
        }
    }


    //b_{i+80} = b_{i+62} ⊕ b_{i+51} ⊕ b_{i+38} ⊕ b_{i+23} ⊕ b_{i+13} ⊕ b_i;
    //shift the window forward and return the new bit.
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


    //The pairwise filter: emit the second bit of a pair when the first is 1.
    private static byte NextFilteredBit(Span<byte> lfsr)
    {
        while(true)
        {
            byte gate = NextRawBit(lfsr);
            byte candidate = NextRawBit(lfsr);
            if(gate == 1)
            {
                return candidate;
            }
        }
    }


    //n filtered bits MSB-first into a canonical scalar; rejection-sample below
    //the modulus (plain byte-lexicographic comparison — both are fixed-width
    //big-endian).
    private static void SampleFieldElement(Span<byte> lfsr, int fieldSizeBits, ReadOnlySpan<byte> modulus, Span<byte> destination)
    {
        while(true)
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
    }


    //n raw filtered bits MSB-first WITHOUT rejection, reduced once mod the
    //modulus. One conditional subtraction suffices: the modulus has bit
    //length n, so a raw n-bit value is below twice the modulus.
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

        if(destination.SequenceCompareTo(modulus) >= 0)
        {
            int borrow = 0;
            for(int i = ScalarSize - 1; i >= 0; i--)
            {
                int difference = destination[i] - modulus[i] - borrow;
                borrow = difference < 0 ? 1 : 0;
                destination[i] = (byte)difference;
            }
        }
    }
}
