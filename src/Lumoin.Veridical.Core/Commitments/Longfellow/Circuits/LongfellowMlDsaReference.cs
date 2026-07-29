using System;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;

/// <summary>
/// A decoded ML-DSA public key, the reference's <c>MLDsaTypes::PublicKey</c>: the expanded matrix
/// in the NTT domain, the unpacked rounded vector, and the public-key hash.
/// </summary>
internal sealed class LongfellowMlDsaPublicKey
{
    /// <summary>The expanded matrix in the NTT domain (the reference's <c>a_hat</c>), indexed row, column, coefficient.</summary>
    public uint[][][] MatrixA { get; }

    /// <summary>The unpacked rounded vector (the reference's <c>t1</c>), indexed row, coefficient.</summary>
    public uint[][] T1 { get; }

    /// <summary>The 64-byte public-key hash (the reference's <c>tr</c>).</summary>
    public byte[] Tr { get; }


    /// <summary>Constructs the decoded key.</summary>
    /// <param name="matrixA">The expanded matrix in the NTT domain.</param>
    /// <param name="t1">The unpacked rounded vector.</param>
    /// <param name="tr">The public-key hash.</param>
    public LongfellowMlDsaPublicKey(uint[][][] matrixA, uint[][] t1, byte[] tr)
    {
        MatrixA = matrixA;
        T1 = t1;
        Tr = tr;
    }
}


/// <summary>
/// A decoded ML-DSA signature, the reference's <c>MLDsaTypes::Signature</c>: the hash commitment,
/// the unpacked response vector, and the hint bits.
/// </summary>
internal sealed class LongfellowMlDsaSignature
{
    /// <summary>The hash commitment (the reference's <c>c_tilde</c>).</summary>
    public byte[] CommitmentHash { get; }

    /// <summary>The unpacked response vector (the reference's <c>z</c>), canonical coefficients indexed column, coefficient.</summary>
    public uint[][] Z { get; }

    /// <summary>The hint bits (the reference's <c>h</c>), indexed row, coefficient.</summary>
    public bool[][] Hints { get; }


    /// <summary>Constructs the decoded signature.</summary>
    /// <param name="commitmentHash">The hash commitment.</param>
    /// <param name="z">The unpacked response vector.</param>
    /// <param name="hints">The hint bits.</param>
    public LongfellowMlDsaSignature(byte[] commitmentHash, uint[][] z, bool[][] hints)
    {
        CommitmentHash = commitmentHash;
        Z = z;
        Hints = hints;
    }
}


/// <summary>
/// The host-side ML-DSA reference operations, a faithful port of the reference's
/// <c>ml_dsa_ref.cc</c> (FIPS 204 Algorithms 18, 19, 21, 23, 27, 28, 29, 30, 32, 36, 40, 41 and 42):
/// the decode, expansion, sampling and transform routines the witness generator drives. The
/// reference carries polynomials as base-field elements; this port carries them as canonical
/// <see cref="uint"/> values below <see cref="LongfellowMlDsaParameters.Modulus"/>, which is the
/// same representation because the reference base field's Montgomery conversions are the identity.
/// </summary>
/// <remarks>
/// The reference marks its ML-DSA implementation as experimental research code that is not vetted
/// for production; this port carries the same status.
/// </remarks>
internal static class LongfellowMlDsaReference
{
    /// <summary>The SHAKE128 block count <see cref="ExpandMatrix"/> extracts per polynomial (the reference's comment: overwhelmingly sufficient for 256 coefficients).</summary>
    private const int ExpandBlockCount = 5;

    /// <summary>The byte count one rejection-sampling candidate consumes.</summary>
    private const int RejectionCandidateBytes = 3;

    /// <summary>The rejection-sampling candidate's top-byte mask (23 candidate bits).</summary>
    private const byte RejectionTopByteMask = 0x7F;

    /// <summary>The SampleInBall hash's output length in bytes (the sign bits and the rejection stream).</summary>
    public const int SampleInBallHashBytes = 136;

    /// <summary>The byte offset where SampleInBall's rejection stream starts (the first eight bytes carry the sign bits).</summary>
    public const int SampleInBallStreamStart = 8;

    /// <summary>The packing width of one rounded public-key coefficient (FIPS 204's <c>bitlen(q−1) − d = 10</c>).</summary>
    private const int T1CoefficientBits = 10;

    /// <summary>The largest rounded public-key coefficient (<c>2^10 − 1</c>), the <c>SimpleBitUnpack</c> bound for <c>t1</c>.</summary>
    private const uint T1CoefficientBound = 1023;

    /// <summary>The seed length in bytes of the matrix-expansion seed <c>rho</c>.</summary>
    private const int SeedBytes = 32;

    /// <summary>The public-key hash length in bytes (the reference's <c>tr</c>).</summary>
    public const int PublicKeyHashBytes = 64;


    /// <summary>FIPS 204 Algorithm 41 <c>NTT</c>, in place (the reference's <c>Ntt</c>): Cooley-Tukey butterflies with ascending twiddle index.</summary>
    /// <param name="coefficients">The 256 canonical coefficients, transformed in place.</param>
    public static void NumberTheoreticTransform(uint[] coefficients)
    {
        int k = 1;
        for(int length = 128; length >= 1; length >>= 1)
        {
            for(int start = 0; start < LongfellowMlDsaParameters.CoefficientCount; start += 2 * length)
            {
                uint zeta = LongfellowMlDsaConstants.NttZetas[k++];
                for(int j = start; j < start + length; j++)
                {
                    uint t = MultiplyModQ(zeta, coefficients[j + length]);
                    coefficients[j + length] = SubtractModQ(coefficients[j], t);
                    coefficients[j] = AddModQ(coefficients[j], t);
                }
            }
        }
    }


    /// <summary>FIPS 204 Algorithm 42 <c>NTT⁻¹</c>, in place (the reference's <c>InvNtt</c>): Gentleman-Sande butterflies with descending twiddle index, then the <see cref="LongfellowMlDsaParameters.InverseTransformScale"/> normalization.</summary>
    /// <param name="coefficients">The 256 canonical coefficients, transformed in place.</param>
    public static void InverseNumberTheoreticTransform(uint[] coefficients)
    {
        int k = 255;
        for(int length = 1; length < LongfellowMlDsaParameters.CoefficientCount; length <<= 1)
        {
            for(int start = 0; start < LongfellowMlDsaParameters.CoefficientCount; start += 2 * length)
            {
                uint negatedZeta = NegateModQ(LongfellowMlDsaConstants.NttZetas[k--]);
                for(int j = start; j < start + length; j++)
                {
                    uint t = coefficients[j];
                    coefficients[j] = AddModQ(t, coefficients[j + length]);
                    coefficients[j + length] = MultiplyModQ(SubtractModQ(t, coefficients[j + length]), negatedZeta);
                }
            }
        }

        for(int i = 0; i < LongfellowMlDsaParameters.CoefficientCount; i++)
        {
            coefficients[i] = MultiplyModQ(coefficients[i], LongfellowMlDsaParameters.InverseTransformScale);
        }
    }


    /// <summary>
    /// FIPS 204 Algorithm 30 <c>RejNTTPoly</c> (the reference's <c>RejNTTPoly</c>): extracts
    /// SHAKE128 output and rejection-samples 256 coefficients from three-byte little-endian
    /// candidates with the top bit masked.
    /// </summary>
    /// <param name="seed">The sampling seed.</param>
    /// <param name="blockCount">The SHAKE128 block count to extract.</param>
    /// <returns>The sampled polynomial.</returns>
    /// <exception cref="InvalidOperationException">When the extracted stream cannot supply 256 coefficients (the reference's <c>check</c>).</exception>
    public static uint[] RejectionSampleNttPolynomial(ReadOnlySpan<byte> seed, int blockCount)
    {
        var stream = new byte[blockCount * LongfellowSha3Witness.Shake128Rate];
        LongfellowSha3Witness.Shake128Hash(seed, stream);

        var coefficients = new uint[LongfellowMlDsaParameters.CoefficientCount];
        int accepted = 0;
        for(int i = 0; i + 2 < stream.Length && accepted < LongfellowMlDsaParameters.CoefficientCount; i += RejectionCandidateBytes)
        {
            uint candidate = stream[i] | ((uint)stream[i + 1] << 8) | ((uint)(stream[i + 2] & RejectionTopByteMask) << 16);
            if(candidate < LongfellowMlDsaParameters.Modulus)
            {
                coefficients[accepted] = candidate;
                accepted++;
            }
        }

        if(accepted < LongfellowMlDsaParameters.CoefficientCount)
        {
            throw new InvalidOperationException("Failed to sample polynomial.");
        }

        return coefficients;
    }


    /// <summary>
    /// FIPS 204 Algorithm 32 <c>ExpandA</c> (the reference's <c>ExpandA</c>): samples the matrix in
    /// the NTT domain from the seed, one polynomial per position with the column and row bytes
    /// appended to the seed.
    /// </summary>
    /// <param name="parameters">The parameter set.</param>
    /// <param name="seed">The 32-byte expansion seed <c>rho</c>.</param>
    /// <returns>The matrix, indexed row, column, coefficient.</returns>
    public static uint[][][] ExpandMatrix(LongfellowMlDsaParameters parameters, ReadOnlySpan<byte> seed)
    {
        var matrix = new uint[parameters.RowCount][][];
        Span<byte> positionSeed = stackalloc byte[seed.Length + 2];
        seed.CopyTo(positionSeed);
        for(int row = 0; row < parameters.RowCount; row++)
        {
            matrix[row] = new uint[parameters.ColumnCount][];
            for(int column = 0; column < parameters.ColumnCount; column++)
            {
                positionSeed[seed.Length] = (byte)column;
                positionSeed[seed.Length + 1] = (byte)row;
                matrix[row][column] = RejectionSampleNttPolynomial(positionSeed, ExpandBlockCount);
            }
        }

        return matrix;
    }


    /// <summary>
    /// FIPS 204 Algorithm 29 <c>SampleInBall</c> (the reference's <c>SampleInBall</c>): samples the
    /// challenge polynomial with <see cref="LongfellowMlDsaParameters.ChallengeWeight"/> nonzero
    /// coefficients from the commitment hash via a rejection-sampled Fisher-Yates shuffle.
    /// </summary>
    /// <param name="parameters">The parameter set.</param>
    /// <param name="commitmentHash">The commitment hash <c>c_tilde</c>.</param>
    /// <returns>The canonical challenge coefficients (zero, one, or the modulus less one).</returns>
    /// <exception cref="InvalidOperationException">When the hash stream cannot supply the samples (the reference's <c>check</c>).</exception>
    public static uint[] SampleInBall(LongfellowMlDsaParameters parameters, ReadOnlySpan<byte> commitmentHash)
    {
        Span<byte> stream = stackalloc byte[SampleInBallHashBytes];
        LongfellowSha3Witness.Shake256Hash(commitmentHash, stream);

        var challenge = new uint[LongfellowMlDsaParameters.CoefficientCount];
        int streamIndex = SampleInBallStreamStart;
        for(int i = LongfellowMlDsaParameters.CoefficientCount - parameters.ChallengeWeight; i < LongfellowMlDsaParameters.CoefficientCount; i++)
        {
            byte j;
            do
            {
                if(streamIndex >= stream.Length)
                {
                    throw new InvalidOperationException("SampleInBall: Not enough pseudorandom bytes.");
                }

                j = stream[streamIndex++];
            }
            while(j > i);

            challenge[i] = challenge[j];

            int bitIndex = i + parameters.ChallengeWeight - LongfellowMlDsaParameters.CoefficientCount;
            int bit = (stream[bitIndex / 8] >> (bitIndex % 8)) & 1;
            challenge[j] = bit == 1 ? LongfellowMlDsaParameters.Modulus - 1 : 1;
        }

        return challenge;
    }


    /// <summary>
    /// FIPS 204 Algorithm 36 <c>Decompose</c> (the reference's <c>Decompose</c>): splits a
    /// coefficient into high and low parts such that <c>r = r1·(2·γ2) + r0 mod q</c> with the
    /// boundary case folded into <c>r1 = 0</c>.
    /// </summary>
    /// <param name="parameters">The parameter set.</param>
    /// <param name="value">The coefficient, any representative.</param>
    /// <returns>The high part and the signed low part.</returns>
    public static (int HighPart, int LowPart) Decompose(LongfellowMlDsaParameters parameters, int value)
    {
        int normalized = value % (int)LongfellowMlDsaParameters.Modulus;
        if(normalized < 0)
        {
            normalized += (int)LongfellowMlDsaParameters.Modulus;
        }

        int alpha = 2 * (int)parameters.RoundingRange;
        int halfAlpha = alpha / 2;
        int lowPart = normalized % alpha;
        if(lowPart > halfAlpha)
        {
            lowPart -= alpha;
        }

        int highPart;
        if(normalized - lowPart == (int)LongfellowMlDsaParameters.Modulus - 1)
        {
            highPart = 0;
            lowPart -= 1;
        }
        else
        {
            highPart = (normalized - lowPart) / alpha;
        }

        return (highPart, lowPart);
    }


    /// <summary>
    /// FIPS 204 Algorithm 40 <c>UseHint</c> (the reference's <c>UseHint</c>): returns the high bits
    /// of a coefficient adjusted by the hint.
    /// </summary>
    /// <param name="parameters">The parameter set.</param>
    /// <param name="hint">The hint bit.</param>
    /// <param name="value">The coefficient.</param>
    /// <returns>The hinted high bits in <c>[0, (q−1)/(2·γ2))</c>.</returns>
    public static uint UseHint(LongfellowMlDsaParameters parameters, bool hint, int value)
    {
        int hintModulus = (int)parameters.HintModulus;
        (int highPart, int lowPart) = Decompose(parameters, value);

        if(hint && lowPart > 0)
        {
            return (uint)((highPart + 1) % hintModulus);
        }

        if(hint && lowPart <= 0)
        {
            int result = (highPart - 1) % hintModulus;
            if(result < 0)
            {
                result += hintModulus;
            }

            return (uint)result;
        }

        return (uint)highPart;
    }


    /// <summary>
    /// FIPS 204 Algorithm 19 <c>BitUnpack</c> (the reference's <c>BitUnpack</c>): unpacks 256
    /// fixed-width values and maps each to the canonical coefficient <c>b − value</c>.
    /// </summary>
    /// <param name="packed">The packed bytes, exactly <c>32·bitsPerCoefficient</c> of them.</param>
    /// <param name="offset">The subtraction offset <c>b</c> (the algorithm's range top).</param>
    /// <param name="bitsPerCoefficient">The packing width of one value.</param>
    /// <returns>The canonical coefficients, or <see langword="null"/> when the input size does not match.</returns>
    public static uint[]? BitUnpack(ReadOnlySpan<byte> packed, uint offset, int bitsPerCoefficient)
    {
        if(packed.Length != 32 * bitsPerCoefficient)
        {
            return null;
        }

        var coefficients = new uint[LongfellowMlDsaParameters.CoefficientCount];
        for(int i = 0; i < LongfellowMlDsaParameters.CoefficientCount; i++)
        {
            int bitOffset = i * bitsPerCoefficient;
            int byteOffset = bitOffset / 8;
            int shift = bitOffset % 8;

            uint window = 0;
            for(int k = 0; k < 4 && byteOffset + k < packed.Length; k++)
            {
                window |= (uint)packed[byteOffset + k] << (8 * k);
            }

            window >>= shift;
            window &= (1u << bitsPerCoefficient) - 1;

            int coefficient = (int)offset - (int)window;
            if(coefficient < 0)
            {
                coefficient += (int)LongfellowMlDsaParameters.Modulus;
            }

            coefficients[i] = (uint)coefficient;
        }

        return coefficients;
    }


    /// <summary>
    /// FIPS 204 Algorithm 21 <c>HintBitUnpack</c> (the reference's <c>HintBitUnpack</c>): unpacks
    /// the hint bits, rejecting malformed encodings (descending indices, an overweight hint, or a
    /// nonzero pad).
    /// </summary>
    /// <param name="parameters">The parameter set.</param>
    /// <param name="packed">The <c>ω + K</c> packed hint bytes.</param>
    /// <returns>The hint bits indexed row, coefficient, or <see langword="null"/> when the encoding is malformed.</returns>
    public static bool[][]? HintBitUnpack(LongfellowMlDsaParameters parameters, ReadOnlySpan<byte> packed)
    {
        var hints = new bool[parameters.RowCount][];
        for(int i = 0; i < parameters.RowCount; i++)
        {
            hints[i] = new bool[LongfellowMlDsaParameters.CoefficientCount];
        }

        int index = 0;
        for(int i = 0; i < parameters.RowCount; i++)
        {
            int limit = packed[parameters.HintWeightBound + i];
            if(limit < index || limit > parameters.HintWeightBound)
            {
                return null;
            }

            int last = -1;
            while(index < limit)
            {
                int position = packed[index++];
                if(last >= 0 && position <= last)
                {
                    return null;
                }

                last = position;
                hints[i][position] = true;
            }
        }

        for(; index < parameters.HintWeightBound; index++)
        {
            if(packed[index] != 0)
            {
                return null;
            }
        }

        return hints;
    }


    /// <summary>
    /// FIPS 204 Algorithm 27 <c>sigDecode</c> (the reference's <c>sigDecode</c>): splits an encoded
    /// signature into the commitment hash, the unpacked response vector, and the hint bits.
    /// </summary>
    /// <param name="parameters">The parameter set.</param>
    /// <param name="signature">The encoded signature.</param>
    /// <returns>The decoded signature, or <see langword="null"/> when the encoding is malformed.</returns>
    public static LongfellowMlDsaSignature? SignatureDecode(LongfellowMlDsaParameters parameters, ReadOnlySpan<byte> signature)
    {
        int bitsPerCoefficient = parameters.ResponseCoefficientBits;
        int responseBytes = 32 * bitsPerCoefficient;
        int expectedSize = parameters.CommitmentBytes + (parameters.ColumnCount * responseBytes) + parameters.HintWeightBound + parameters.RowCount;
        if(signature.Length < expectedSize)
        {
            return null;
        }

        int offset = 0;
        byte[] commitmentHash = signature.Slice(offset, parameters.CommitmentBytes).ToArray();
        offset += parameters.CommitmentBytes;

        var z = new uint[parameters.ColumnCount][];
        for(int i = 0; i < parameters.ColumnCount; i++)
        {
            uint[]? unpacked = BitUnpack(signature.Slice(offset, responseBytes), parameters.MaskingBound, bitsPerCoefficient);
            if(unpacked is null)
            {
                return null;
            }

            z[i] = unpacked;
            offset += responseBytes;
        }

        bool[][]? hints = HintBitUnpack(parameters, signature.Slice(offset, parameters.HintWeightBound + parameters.RowCount));
        if(hints is null)
        {
            return null;
        }

        return new LongfellowMlDsaSignature(commitmentHash, z, hints);
    }


    /// <summary>
    /// FIPS 204 Algorithm 18 <c>SimpleBitUnpack</c> (the reference's <c>SimpleBitUnpack</c>):
    /// extracts 256 fixed-width coefficients from a byte array.
    /// </summary>
    /// <param name="packed">The packed bytes, exactly <c>32·bitlen(bound)</c> of them.</param>
    /// <param name="bound">The largest packed value, whose bit length is the packing width.</param>
    /// <returns>The coefficients.</returns>
    /// <exception cref="ArgumentException">When the input size does not match (the reference's <c>check</c>).</exception>
    public static uint[] SimpleBitUnpack(ReadOnlySpan<byte> packed, uint bound)
    {
        int bitsPerCoefficient = LongfellowMlDsaParameters.BitLength(bound);
        if(packed.Length != 32 * bitsPerCoefficient)
        {
            throw new ArgumentException("SimpleBitUnpack input size mismatch.", nameof(packed));
        }

        var coefficients = new uint[LongfellowMlDsaParameters.CoefficientCount];
        for(int i = 0; i < LongfellowMlDsaParameters.CoefficientCount; i++)
        {
            int bitOffset = i * bitsPerCoefficient;
            int byteOffset = bitOffset / 8;
            int shift = bitOffset % 8;

            uint window = 0;
            for(int k = 0; k < 2 && byteOffset + k < packed.Length; k++)
            {
                window |= (uint)packed[byteOffset + k] << (8 * k);
            }

            window >>= shift;
            window &= (1u << bitsPerCoefficient) - 1;
            coefficients[i] = window;
        }

        return coefficients;
    }


    /// <summary>
    /// FIPS 204 Algorithm 23 <c>pkDecode</c> (the reference's <c>pkDecode</c>): extracts the seed,
    /// expands the matrix, unpacks the rounded vector, and hashes the whole encoded key.
    /// </summary>
    /// <param name="parameters">The parameter set.</param>
    /// <param name="publicKey">The encoded public key.</param>
    /// <returns>The decoded key.</returns>
    /// <exception cref="ArgumentException">When the encoding is too short (the reference's <c>check</c>).</exception>
    public static LongfellowMlDsaPublicKey PublicKeyDecode(LongfellowMlDsaParameters parameters, ReadOnlySpan<byte> publicKey)
    {
        int t1Bytes = 32 * T1CoefficientBits;
        int expectedSize = SeedBytes + (parameters.RowCount * t1Bytes);
        if(publicKey.Length < expectedSize)
        {
            throw new ArgumentException("pkDecode public key too short.", nameof(publicKey));
        }

        int offset = 0;
        ReadOnlySpan<byte> seed = publicKey[..SeedBytes];
        offset += SeedBytes;

        uint[][][] matrixA = ExpandMatrix(parameters, seed);

        var t1 = new uint[parameters.RowCount][];
        for(int i = 0; i < parameters.RowCount; i++)
        {
            t1[i] = SimpleBitUnpack(publicKey.Slice(offset, t1Bytes), T1CoefficientBound);
            offset += t1Bytes;
        }

        var tr = new byte[PublicKeyHashBytes];
        LongfellowSha3Witness.Shake256Hash(publicKey, tr);

        return new LongfellowMlDsaPublicKey(matrixA, t1, tr);
    }


    /// <summary>
    /// FIPS 204 Algorithm 18 <c>SimpleBitPack</c> (the reference's <c>SimpleBitPack</c>): packs 256
    /// coefficients into a byte array at the bound's bit length, least significant bit first.
    /// </summary>
    /// <param name="coefficients">The canonical coefficients, each at most <paramref name="bound"/>.</param>
    /// <param name="bound">The largest packed value, whose bit length is the packing width.</param>
    /// <returns>The packed bytes.</returns>
    public static byte[] SimpleBitPack(uint[] coefficients, uint bound)
    {
        int bitsPerCoefficient = LongfellowMlDsaParameters.BitLength(bound);
        if(bound == 0)
        {
            bitsPerCoefficient = 1;
        }

        int totalBits = LongfellowMlDsaParameters.CoefficientCount * bitsPerCoefficient;
        var packed = new byte[(totalBits + 7) / 8];

        int currentBit = 0;
        for(int i = 0; i < LongfellowMlDsaParameters.CoefficientCount; i++)
        {
            uint value = coefficients[i];
            for(int k = 0; k < bitsPerCoefficient; k++)
            {
                if(((value >> k) & 1) != 0)
                {
                    packed[currentBit / 8] |= (byte)(1 << (currentBit % 8));
                }

                currentBit++;
            }
        }

        return packed;
    }


    /// <summary>
    /// FIPS 204 Algorithm 28 <c>w1Encode</c> (the reference's <c>w1Encode</c>): packs the high-bits
    /// vector row by row at the hint modulus's width.
    /// </summary>
    /// <param name="parameters">The parameter set.</param>
    /// <param name="highBits">The high-bits vector, indexed row, coefficient.</param>
    /// <returns>The packed byte string, <c>K·w1_bytes</c> long.</returns>
    public static byte[] W1Encode(LongfellowMlDsaParameters parameters, uint[][] highBits)
    {
        uint bound = parameters.HintModulus - 1;
        var encoded = new byte[parameters.RowCount * parameters.HighBitsBytes];

        int offset = 0;
        for(int i = 0; i < parameters.RowCount; i++)
        {
            byte[] packed = SimpleBitPack(highBits[i], bound);
            packed.CopyTo(encoded.AsSpan(offset));
            offset += packed.Length;
        }

        return encoded;
    }


    /// <summary>Adds two canonical values modulo <see cref="LongfellowMlDsaParameters.Modulus"/>.</summary>
    /// <param name="left">The first addend.</param>
    /// <param name="right">The second addend.</param>
    /// <returns>The canonical sum.</returns>
    public static uint AddModQ(uint left, uint right)
    {
        uint sum = left + right;
        if(sum >= LongfellowMlDsaParameters.Modulus)
        {
            sum -= LongfellowMlDsaParameters.Modulus;
        }

        return sum;
    }


    /// <summary>Subtracts two canonical values modulo <see cref="LongfellowMlDsaParameters.Modulus"/>.</summary>
    /// <param name="left">The minuend.</param>
    /// <param name="right">The subtrahend.</param>
    /// <returns>The canonical difference.</returns>
    public static uint SubtractModQ(uint left, uint right) => left >= right ? left - right : left + LongfellowMlDsaParameters.Modulus - right;


    /// <summary>Multiplies two canonical values modulo <see cref="LongfellowMlDsaParameters.Modulus"/>.</summary>
    /// <param name="left">The first factor.</param>
    /// <param name="right">The second factor.</param>
    /// <returns>The canonical product.</returns>
    public static uint MultiplyModQ(uint left, uint right) => (uint)(((ulong)left * right) % LongfellowMlDsaParameters.Modulus);


    /// <summary>Negates a canonical value modulo <see cref="LongfellowMlDsaParameters.Modulus"/>.</summary>
    /// <param name="value">The value to negate.</param>
    /// <returns>The canonical negation.</returns>
    public static uint NegateModQ(uint value) => value == 0 ? 0 : LongfellowMlDsaParameters.Modulus - value;
}
