using System;
using System.Numerics;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// The radix-2 number-theoretic transform over the wired scalar fields. Both
/// BLS12-381 and BN254 have highly 2-adic scalar fields (<c>r − 1 = 2^s · t</c>
/// with <c>s = 32</c> and <c>s = 28</c> respectively), so the transform runs
/// directly in the field over a multiplicative subgroup of power-of-two order —
/// no extension-field embedding is involved.
/// </summary>
/// <remarks>
/// <para>
/// The transform pair is decimation-in-frequency forward (natural input,
/// bit-reversed output) and decimation-in-time inverse (bit-reversed input,
/// natural output), so a convolution's transform–pointwise-product–inverse
/// round trip needs no bit-reversal pass. The inverse is unnormalized:
/// <c>Inverse(Forward(x))</c> is <c>length · x</c>, and a convolution caller
/// cancels the factor by folding <c>1/length</c> into its cached fixed-operand
/// spectrum.
/// </para>
/// <para>
/// The domain root of unity is derived at run time as
/// <c>ω = g^((r − 1) / 2^k)</c> from the field order <c>r</c> and the per-curve
/// domain generator <c>g</c>, a quadratic nonresidue, so <c>ω</c> has exact
/// order <c>2^k</c>; the derivation verifies <c>ω^(2^(k−1)) = −1</c> and
/// <c>ω^(2^k) = 1</c> and fails loudly on any mismatch. All arithmetic runs
/// through the injected span delegates over the canonical 32-byte big-endian
/// element layout.
/// </para>
/// </remarks>
internal static class ScalarNtt
{
    private const int ScalarSize = Scalar.SizeBytes;

    //The scalar-field 2-adicities: the largest s with 2^s dividing r − 1. The
    //per-curve values follow from the field orders in WellKnownCurves and are
    //re-derived from them by the conformance tests.
    private const int Bls12Curve381TwoAdicity = 32;
    private const int Bn254TwoAdicity = 28;

    //The domain generators: small prime quadratic nonresidues matching the
    //conventional multiplicative generator of published parameter tables for
    //each field — 7 for BLS12-381 (where 5 is a smaller nonresidue but not the
    //convention) and 5 for BN254 (the smallest). Nonresiduosity is the property
    //the derivation needs — it makes g^((r − 1) / 2^k) an element of exact
    //order 2^k — and the conformance tests re-verify it via the Euler
    //criterion; the derived roots are pinned by the anchor fixture.
    private const uint Bls12Curve381DomainGenerator = 7;
    private const uint Bn254DomainGenerator = 5;


    /// <summary>
    /// The 2-adicity <c>s</c> of the curve's scalar field: the largest domain
    /// this transform supports has length <c>2^s</c>.
    /// </summary>
    /// <param name="curve">A wired curve.</param>
    /// <returns>The 2-adicity of the scalar field order minus one.</returns>
    public static int TwoAdicity(CurveParameterSet curve)
    {
        WellKnownCurves.ThrowIfCurveNotWired(curve);

        return curve.Code == CurveParameterSet.Bls12Curve381.Code ? Bls12Curve381TwoAdicity : Bn254TwoAdicity;
    }


    /// <summary>
    /// The quadratic nonresidue the domain roots of unity derive from.
    /// </summary>
    /// <param name="curve">A wired curve.</param>
    /// <returns>The per-curve domain generator.</returns>
    public static uint DomainGenerator(CurveParameterSet curve)
    {
        WellKnownCurves.ThrowIfCurveNotWired(curve);

        return curve.Code == CurveParameterSet.Bls12Curve381.Code ? Bls12Curve381DomainGenerator : Bn254DomainGenerator;
    }


    /// <summary>
    /// Derives the primitive <c>2^lengthLog2</c>-th root of unity
    /// <c>ω = g^((r − 1) / 2^lengthLog2)</c> in the working domain and verifies
    /// its exact order before returning it.
    /// </summary>
    /// <param name="lengthLog2">The domain-length exponent; between 0 and <see cref="TwoAdicity"/>.</param>
    /// <param name="root">Receives the root, one element (32 bytes).</param>
    /// <param name="subtract">Scalar subtraction (forms <c>−1</c> for the order check).</param>
    /// <param name="multiply">Scalar multiplication.</param>
    /// <param name="ofScalar">Writes a small integer as a working-domain element.</param>
    /// <param name="curve">The wired curve the delegates route over.</param>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="lengthLog2"/> exceeds the field's 2-adicity.</exception>
    /// <exception cref="ArgumentException">When <paramref name="root"/> is not one element.</exception>
    /// <exception cref="InvalidOperationException">When the derived root fails its order check.</exception>
    public static void DeriveRootOfUnity(
        int lengthLog2,
        Span<byte> root,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        Action<uint, Span<byte>> ofScalar,
        CurveParameterSet curve)
    {
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(ofScalar);
        ArgumentOutOfRangeException.ThrowIfNegative(lengthLog2);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(lengthLog2, TwoAdicity(curve));
        if(root.Length != ScalarSize)
        {
            throw new ArgumentException($"The root must be {ScalarSize} bytes; received {root.Length}.", nameof(root));
        }

        if(lengthLog2 == 0)
        {
            //The order-one domain: ω = g^(r − 1) = 1 by Fermat.
            ofScalar(1, root);

            return;
        }

        //Square-and-multiply of g to the exponent (r − 1) / 2^lengthLog2, most
        //significant bit first, in the working domain.
        BigInteger exponent = (WellKnownCurves.GetScalarFieldOrder(curve) - BigInteger.One) >> lengthLog2;
        byte[] exponentBytes = exponent.ToByteArray(isUnsigned: true, isBigEndian: true);
        Span<byte> generatorValue = stackalloc byte[ScalarSize];
        ofScalar(DomainGenerator(curve), generatorValue);
        ofScalar(1, root);
        foreach(byte exponentByte in exponentBytes)
        {
            for(int bit = 7; bit >= 0; bit--)
            {
                multiply(root, root, root, curve);
                if(((exponentByte >> bit) & 1) == 1)
                {
                    multiply(root, generatorValue, root, curve);
                }
            }
        }

        //Exact-order check: ω^(2^(lengthLog2 − 1)) must be −1 and one further
        //squaring must give 1, so a wrong generator or 2-adicity fails loudly
        //instead of producing a consistent-but-wrong transform.
        Span<byte> power = stackalloc byte[ScalarSize];
        Span<byte> one = stackalloc byte[ScalarSize];
        Span<byte> minusOne = stackalloc byte[ScalarSize];
        Span<byte> zero = stackalloc byte[ScalarSize];
        root.CopyTo(power);
        for(int squaring = 1; squaring < lengthLog2; squaring++)
        {
            multiply(power, power, power, curve);
        }

        ofScalar(1, one);
        zero.Clear();
        subtract(zero, one, minusOne, curve);
        if(!power.SequenceEqual(minusOne))
        {
            throw new InvalidOperationException($"The derived 2^{lengthLog2}-th root of unity failed its half-order check for curve '{curve}'.");
        }

        multiply(power, power, power, curve);
        if(!power.SequenceEqual(one))
        {
            throw new InvalidOperationException($"The derived 2^{lengthLog2}-th root of unity failed its full-order check for curve '{curve}'.");
        }
    }


    /// <summary>
    /// Fills the twiddle table with the powers <c>root^j</c> for
    /// <c>j ∈ [0, length / 2)</c> — the one table every stage of
    /// <see cref="Forward"/> or <see cref="Inverse"/> indexes with a
    /// per-stage stride.
    /// </summary>
    /// <param name="root">The primitive <c>length</c>-th root of unity (forward) or its inverse (inverse transform).</param>
    /// <param name="length">The domain length; a power of two, at least 1.</param>
    /// <param name="twiddles">Receives <c>length / 2</c> elements.</param>
    /// <param name="multiply">Scalar multiplication.</param>
    /// <param name="ofScalar">Writes a small integer as a working-domain element.</param>
    /// <param name="curve">The curve the delegates route over.</param>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span length does not match.</exception>
    public static void BuildTwiddles(
        ReadOnlySpan<byte> root,
        int length,
        Span<byte> twiddles,
        ScalarMultiplyDelegate multiply,
        Action<uint, Span<byte>> ofScalar,
        CurveParameterSet curve)
    {
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(ofScalar);
        ThrowIfNotPowerOfTwo(length);
        if(root.Length != ScalarSize)
        {
            throw new ArgumentException($"The root must be {ScalarSize} bytes; received {root.Length}.", nameof(root));
        }

        int count = length / 2;
        if(twiddles.Length != count * ScalarSize)
        {
            throw new ArgumentException($"The twiddle table must be {count * ScalarSize} bytes; received {twiddles.Length}.", nameof(twiddles));
        }

        if(count == 0)
        {
            return;
        }

        ofScalar(1, twiddles[..ScalarSize]);
        for(int j = 1; j < count; j++)
        {
            multiply(At(twiddles, j - 1), root, At(twiddles, j), curve);
        }
    }


    /// <summary>
    /// The in-place decimation-in-frequency forward transform: natural-order
    /// input to bit-reversed-order output.
    /// </summary>
    /// <param name="data">The domain, <c>length</c> elements (<c>length · 32</c> bytes), transformed in place.</param>
    /// <param name="length">The domain length; a power of two, at least 1.</param>
    /// <param name="twiddles">The <c>length / 2</c> powers of the primitive <c>length</c>-th root, from <see cref="BuildTwiddles"/>.</param>
    /// <param name="add">Scalar addition.</param>
    /// <param name="subtract">Scalar subtraction.</param>
    /// <param name="multiply">Scalar multiplication.</param>
    /// <param name="curve">The curve the delegates route over.</param>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span length does not match.</exception>
    public static void Forward(
        Span<byte> data,
        int length,
        ReadOnlySpan<byte> twiddles,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        ValidateTransformArguments(data, length, twiddles, add, subtract, multiply);
        if(length == 1)
        {
            return;
        }

        //Gentleman–Sande butterflies: low = u + v, high = (u − v) · ω^(j·stride).
        //The twiddle multiplications inside a stage share one contiguous table
        //stretch, a batching seam left to a later performance pass.
        Span<byte> u = stackalloc byte[ScalarSize];
        Span<byte> difference = stackalloc byte[ScalarSize];
        for(int half = length >> 1; half >= 1; half >>= 1)
        {
            int stride = (length >> 1) / half;
            for(int block = 0; block < length; block += 2 * half)
            {
                for(int j = 0; j < half; j++)
                {
                    Span<byte> low = At(data, block + j);
                    Span<byte> high = At(data, block + j + half);
                    low.CopyTo(u);
                    add(u, high, low, curve);
                    subtract(u, high, difference, curve);
                    multiply(difference, At(twiddles, j * stride), high, curve);
                }
            }
        }
    }


    /// <summary>
    /// The in-place decimation-in-time inverse transform: bit-reversed-order
    /// input (as <see cref="Forward"/> leaves it) to natural-order output,
    /// unnormalized — the result carries a factor of <c>length</c>.
    /// </summary>
    /// <param name="data">The domain, <c>length</c> elements (<c>length · 32</c> bytes), transformed in place.</param>
    /// <param name="length">The domain length; a power of two, at least 1.</param>
    /// <param name="inverseTwiddles">The <c>length / 2</c> powers of the inverse primitive root, from <see cref="BuildTwiddles"/>.</param>
    /// <param name="add">Scalar addition.</param>
    /// <param name="subtract">Scalar subtraction.</param>
    /// <param name="multiply">Scalar multiplication.</param>
    /// <param name="curve">The curve the delegates route over.</param>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span length does not match.</exception>
    public static void Inverse(
        Span<byte> data,
        int length,
        ReadOnlySpan<byte> inverseTwiddles,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        ValidateTransformArguments(data, length, inverseTwiddles, add, subtract, multiply);
        if(length == 1)
        {
            return;
        }

        //Cooley–Tukey butterflies: low = u + v · ω^(−j·stride), high = u − v · ω^(−j·stride).
        Span<byte> u = stackalloc byte[ScalarSize];
        Span<byte> product = stackalloc byte[ScalarSize];
        for(int half = 1; half <= length >> 1; half <<= 1)
        {
            int stride = (length >> 1) / half;
            for(int block = 0; block < length; block += 2 * half)
            {
                for(int j = 0; j < half; j++)
                {
                    Span<byte> low = At(data, block + j);
                    Span<byte> high = At(data, block + j + half);
                    multiply(high, At(inverseTwiddles, j * stride), product, curve);
                    low.CopyTo(u);
                    add(u, product, low, curve);
                    subtract(u, product, high, curve);
                }
            }
        }
    }


    private static void ValidateTransformArguments(
        Span<byte> data,
        int length,
        ReadOnlySpan<byte> twiddles,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ThrowIfNotPowerOfTwo(length);
        if(data.Length != length * ScalarSize)
        {
            throw new ArgumentException($"The data must be {length * ScalarSize} bytes; received {data.Length}.", nameof(data));
        }

        if(twiddles.Length != (length / 2) * ScalarSize)
        {
            throw new ArgumentException($"The twiddle table must be {(length / 2) * ScalarSize} bytes; received {twiddles.Length}.", nameof(twiddles));
        }
    }


    private static void ThrowIfNotPowerOfTwo(int length)
    {
        if(length < 1 || !BitOperations.IsPow2(length))
        {
            throw new ArgumentException($"The transform length must be a power of two of at least 1; received {length}.", nameof(length));
        }
    }


    private static Span<byte> At(Span<byte> data, int index) => data.Slice(index * ScalarSize, ScalarSize);

    private static ReadOnlySpan<byte> At(ReadOnlySpan<byte> data, int index) => data.Slice(index * ScalarSize, ScalarSize);
}
