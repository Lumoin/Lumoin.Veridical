using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Numerics;

namespace Lumoin.Veridical.Core.Commitments.Whir;

/// <summary>
/// The smooth-coset Reed-Solomon encoder for the WHIR oracles: evaluates a
/// multilinear coefficient vector over the multiplicative subgroup of
/// power-of-two order the round's code lives on (WHIR Definition 4.2, with the
/// trivial coset shift), by zero-padding to the domain length and running the
/// raw <see cref="ScalarNtt"/> transform. Composed directly on the transform
/// primitives; the integer-domain <see cref="ScalarNttReedSolomon"/>
/// interpolator serves the Ligero convention and shares nothing with this
/// smooth-domain evaluation map.
/// </summary>
/// <remarks>
/// <para>
/// Under Definition 4.2's identification <c>pow(x, m) = (x^(2^0), ..., x^(2^(m-1)))</c>
/// the multilinear coefficient vector is the univariate coefficient vector
/// verbatim: the coefficient of the monomial with variable set <c>S</c> is the
/// coefficient of <c>x^(Σ_{l∈S} 2^(l-1))</c>, so index <c>t</c> of the input
/// carries the monomial whose variable <c>X_(l+1)</c> appears exactly when bit
/// <c>l</c> of <c>t</c> is set. Encoding is therefore plain polynomial
/// evaluation of that univariate on the domain.
/// </para>
/// <para>
/// The forward transform is decimation-in-frequency (natural input,
/// bit-reversed output); <see cref="Encode"/> permutes the output back so
/// position <c>t</c> of the result is the evaluation at <c>ω^t</c> for the
/// domain's derived root <c>ω</c>. <see cref="EncodeToCosetLeaves"/> instead
/// groups the evaluations by the <c>2^k</c>-cosets the WHIR verifier queries
/// as one symbol: leaf <c>s</c> carries the evaluations at
/// <c>{ω^(s + j·2^(n-k)) : j ∈ [0, 2^k)}</c> — exactly the block
/// <c>{y : y^(2^k) = z_s}</c> over the query point <c>z_s = (ω^(2^k))^s</c> —
/// in ascending <c>j</c>.
/// </para>
/// </remarks>
public sealed class WhirCosetEncoder
{
    /// <summary>The byte size of one field element.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>
    /// The largest domain whose scalar byte span stays int-addressable: 2^26
    /// elements of 32 bytes exceed <see cref="int.MaxValue"/>. The cap runs
    /// before any <c>1 &lt;&lt; domainSizeLog2</c>, which would otherwise
    /// silently wrap at the field's full two-adicity because C# masks an int
    /// shift count to its low five bits — <c>1 &lt;&lt; 32</c> evaluates to
    /// 1, not 2^32.
    /// </summary>
    private const int MaximumDomainSizeLog2 = 25;

    private readonly ScalarAddDelegate add;
    private readonly ScalarSubtractDelegate subtract;
    private readonly ScalarMultiplyDelegate multiply;
    private readonly CurveParameterSet curve;
    private readonly BaseMemoryPool pool;


    private WhirCosetEncoder(
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        this.add = add;
        this.subtract = subtract;
        this.multiply = multiply;
        this.curve = curve;
        this.pool = pool;
    }


    /// <summary>
    /// Creates an encoder routing over the given scalar backends. The encoder
    /// holds no per-shape state: every call derives and order-checks its
    /// domain root and builds its twiddle table from the pool.
    /// </summary>
    /// <param name="add">Scalar addition.</param>
    /// <param name="subtract">Scalar subtraction.</param>
    /// <param name="multiply">Scalar multiplication.</param>
    /// <param name="curve">The wired curve the delegates route over.</param>
    /// <param name="pool">The pool per-call scratch rents from.</param>
    /// <returns>The encoder.</returns>
    /// <exception cref="ArgumentNullException">When a delegate or the pool is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the curve is not wired.</exception>
    public static WhirCosetEncoder Create(
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(pool);
        WellKnownCurves.ThrowIfCurveNotWired(curve);

        return new WhirCosetEncoder(add, subtract, multiply, curve, pool);
    }


    /// <summary>
    /// Evaluates the polynomial with the given coefficient vector over the
    /// order-<c>2^domainSizeLog2</c> subgroup, in natural order: position
    /// <c>t</c> of <paramref name="evaluations"/> receives the value at
    /// <c>ω^t</c>.
    /// </summary>
    /// <param name="coefficients">The coefficient vector; a power-of-two count of elements, at most the domain size.</param>
    /// <param name="domainSizeLog2">The domain-length exponent; between 1 and the smaller of the field's 2-adicity and the byte-addressability cap of 25.</param>
    /// <param name="evaluations">Receives the <c>2^domainSizeLog2</c> evaluations.</param>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="domainSizeLog2"/> is out of range.</exception>
    /// <exception cref="ArgumentException">When a span length does not match the shape.</exception>
    public void Encode(ReadOnlySpan<byte> coefficients, int domainSizeLog2, Span<byte> evaluations)
    {
        int domainLength = ValidateEncodeShape(coefficients, domainSizeLog2, evaluations.Length);

        TransformPaddedCoefficients(coefficients, randomness: default, domainSizeLog2, domainLength, evaluations);
    }


    /// <summary>
    /// Evaluates the zero-knowledge extension of the polynomial over the
    /// order-<c>2^domainSizeLog2</c> subgroup, in natural order: the encoded
    /// coefficient vector is <c>(coefficients ‖ randomness ‖ zeros)</c>, so
    /// the codeword is <c>Enc(f, r)(x) = Σ_j f_j·x^j + Σ_s r_s·x^(len(f)+s)</c>
    /// (eprint 2026/391 Definition 3.22 on a Reed-Solomon code). With
    /// <paramref name="randomness"/> uniform, any <c>t</c> codeword positions
    /// with <c>t</c> at most the randomness element count are simulatable —
    /// the hiding lives in the codeword itself, not in leaf salting. An empty
    /// <paramref name="randomness"/> degenerates to <see cref="Encode"/>.
    /// </summary>
    /// <param name="coefficients">The message coefficient vector; at least one element. Unlike <see cref="Encode"/> the element count need not be a power of two — the mask codes of the hiding path carry arbitrary message lengths.</param>
    /// <param name="randomness">The fresh randomness coefficients appended after the message; may be empty.</param>
    /// <param name="domainSizeLog2">The domain-length exponent; between 1 and the smaller of the field's 2-adicity and the byte-addressability cap of 25.</param>
    /// <param name="evaluations">Receives the <c>2^domainSizeLog2</c> evaluations.</param>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="domainSizeLog2"/> is out of range.</exception>
    /// <exception cref="ArgumentException">When a span length does not match the shape or the message and randomness together exceed the domain.</exception>
    public void EncodeWithRandomness(
        ReadOnlySpan<byte> coefficients,
        ReadOnlySpan<byte> randomness,
        int domainSizeLog2,
        Span<byte> evaluations)
    {
        int domainLength = ValidateZeroKnowledgeEncodeShape(coefficients, randomness, domainSizeLog2, evaluations.Length);

        TransformPaddedCoefficients(coefficients, randomness, domainSizeLog2, domainLength, evaluations);
    }


    /// <summary>
    /// Evaluates the polynomial over the order-<c>2^domainSizeLog2</c>
    /// subgroup and lays the evaluations out coset-contiguously for
    /// Merkle-leaf grouping: position <c>s·2^k + j</c> of
    /// <paramref name="leaves"/> receives the value at
    /// <c>ω^(s + j·2^(n-k))</c>, so leaf <c>s</c> is the full query block over
    /// <c>z_s = (ω^(2^k))^s</c>.
    /// </summary>
    /// <param name="coefficients">The coefficient vector; a power-of-two count of elements, at most the domain size.</param>
    /// <param name="domainSizeLog2">The domain-length exponent <c>n</c>; between 1 and the smaller of the field's 2-adicity and the byte-addressability cap of 25.</param>
    /// <param name="foldingParameter">The coset exponent <c>k</c>; between 1 and <paramref name="domainSizeLog2"/>.</param>
    /// <param name="leaves">Receives the <c>2^n</c> evaluations in coset-contiguous order.</param>
    /// <exception cref="ArgumentOutOfRangeException">When an exponent is out of range.</exception>
    /// <exception cref="ArgumentException">When a span length does not match the shape.</exception>
    public void EncodeToCosetLeaves(
        ReadOnlySpan<byte> coefficients,
        int domainSizeLog2,
        int foldingParameter,
        Span<byte> leaves)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(foldingParameter, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(foldingParameter, domainSizeLog2);
        int domainLength = ValidateEncodeShape(coefficients, domainSizeLog2, leaves.Length);

        using IMemoryOwner<byte> naturalOwner = pool.Rent(domainLength * ScalarSize);
        Span<byte> natural = naturalOwner.Memory.Span[..(domainLength * ScalarSize)];
        Encode(coefficients, domainSizeLog2, natural);
        RegroupToCosetLeaves(natural, domainLength, foldingParameter, leaves);
    }


    /// <summary>
    /// Evaluates the zero-knowledge extension of the polynomial —
    /// <c>(coefficients ‖ randomness ‖ zeros)</c> as one coefficient vector,
    /// see <see cref="EncodeWithRandomness"/> — over the
    /// order-<c>2^domainSizeLog2</c> subgroup and lays the evaluations out
    /// coset-contiguously exactly as <see cref="EncodeToCosetLeaves"/> does:
    /// the leaf shape, the Merkle machinery and the fold butterfly are all
    /// unchanged by hiding. Under the limb decomposition
    /// <c>f(X) = Σ_b X^b·f_b(X^(2^k))</c> a randomness vector of <c>t·2^k</c>
    /// elements gives every limb polynomial <c>t</c> fresh high coefficients,
    /// so any <c>t</c> opened leaves are simulatable. An empty
    /// <paramref name="randomness"/> produces bytes identical to
    /// <see cref="EncodeToCosetLeaves"/>.
    /// </summary>
    /// <param name="coefficients">The message coefficient vector; a power-of-two count of elements.</param>
    /// <param name="randomness">The fresh randomness coefficients; a multiple of <c>2^foldingParameter</c> elements — <c>t</c> per limb — and may be empty.</param>
    /// <param name="domainSizeLog2">The domain-length exponent <c>n</c>; between 1 and the smaller of the field's 2-adicity and the byte-addressability cap of 25.</param>
    /// <param name="foldingParameter">The coset exponent <c>k</c>; between 1 and <paramref name="domainSizeLog2"/>.</param>
    /// <param name="leaves">Receives the <c>2^n</c> evaluations in coset-contiguous order.</param>
    /// <exception cref="ArgumentOutOfRangeException">When an exponent is out of range.</exception>
    /// <exception cref="ArgumentException">When a span length does not match the shape, the message count is not a power of two, the randomness count is not a multiple of <c>2^foldingParameter</c>, or message and randomness together exceed the domain.</exception>
    public void EncodeToCosetLeavesWithRandomness(
        ReadOnlySpan<byte> coefficients,
        ReadOnlySpan<byte> randomness,
        int domainSizeLog2,
        int foldingParameter,
        Span<byte> leaves)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(foldingParameter, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(foldingParameter, domainSizeLog2);
        int domainLength = ValidateZeroKnowledgeEncodeShape(coefficients, randomness, domainSizeLog2, leaves.Length);

        int messageCount = coefficients.Length / ScalarSize;
        if(!BitOperations.IsPow2(messageCount))
        {
            throw new ArgumentException(
                $"The message coefficient count must be a power of two for the coset-leaf layout; received {messageCount}.",
                nameof(coefficients));
        }

        int limbCount = 1 << foldingParameter;
        if(randomness.Length % (limbCount * ScalarSize) != 0)
        {
            throw new ArgumentException(
                $"The randomness must carry a multiple of 2^{foldingParameter} elements — the per-limb budget times the limb count; received {randomness.Length / ScalarSize} elements.",
                nameof(randomness));
        }

        using IMemoryOwner<byte> naturalOwner = pool.Rent(domainLength * ScalarSize);
        Span<byte> natural = naturalOwner.Memory.Span[..(domainLength * ScalarSize)];
        TransformPaddedCoefficients(coefficients, randomness, domainSizeLog2, domainLength, natural);
        RegroupToCosetLeaves(natural, domainLength, foldingParameter, leaves);
    }


    /// <summary>
    /// Derives the natural-order domain root <c>ω</c> of the
    /// order-<c>2^domainSizeLog2</c> subgroup — the point mapping the WHIR
    /// verifier shares with this encoder, so queried block indices resolve to
    /// the same field elements on both ends.
    /// </summary>
    /// <param name="domainSizeLog2">The domain-length exponent; between 0 and the field's 2-adicity.</param>
    /// <param name="root">Receives the root, one element.</param>
    /// <exception cref="ArgumentOutOfRangeException">When the exponent exceeds the field's 2-adicity.</exception>
    /// <exception cref="ArgumentException">When <paramref name="root"/> is not one element.</exception>
    public void DeriveDomainRoot(int domainSizeLog2, Span<byte> root)
    {
        ScalarNtt.DeriveRootOfUnity(domainSizeLog2, root, subtract, multiply, WriteCanonicalUInt, curve);
    }


    /// <summary>
    /// Copies the message and randomness into a padded working buffer, runs
    /// the forward transform and writes the evaluations in natural exponent
    /// order — the shared trunk of the plain and zero-knowledge encodes.
    /// </summary>
    private void TransformPaddedCoefficients(
        ReadOnlySpan<byte> coefficients,
        ReadOnlySpan<byte> randomness,
        int domainSizeLog2,
        int domainLength,
        Span<byte> evaluations)
    {
        //The pool zeroes rented buffers on return, so the witness-material
        //working copy needs no explicit scrub.
        using IMemoryOwner<byte> scratchOwner = pool.Rent(domainLength * ScalarSize);
        Span<byte> scratch = scratchOwner.Memory.Span[..(domainLength * ScalarSize)];
        coefficients.CopyTo(scratch);
        randomness.CopyTo(scratch[coefficients.Length..]);
        scratch[(coefficients.Length + randomness.Length)..].Clear();
        TransformInPlace(scratch, domainSizeLog2);

        //The forward transform leaves position p holding the evaluation at
        //ω^bitreverse(p); the permutation restores exponent order.
        for(int position = 0; position < domainLength; position++)
        {
            int exponent = ReverseBits(position, domainSizeLog2);
            scratch.Slice(position * ScalarSize, ScalarSize).CopyTo(evaluations.Slice(exponent * ScalarSize, ScalarSize));
        }
    }


    /// <summary>
    /// Regroups natural-order evaluations into the coset-contiguous leaf
    /// layout: position <c>s·2^k + j</c> receives the evaluation at
    /// <c>ω^(s + j·2^(n-k))</c>.
    /// </summary>
    private static void RegroupToCosetLeaves(ReadOnlySpan<byte> natural, int domainLength, int foldingParameter, Span<byte> leaves)
    {
        int blockCount = domainLength >> foldingParameter;
        int blockSize = 1 << foldingParameter;
        for(int block = 0; block < blockCount; block++)
        {
            for(int j = 0; j < blockSize; j++)
            {
                int exponent = block + (j * blockCount);
                natural.Slice(exponent * ScalarSize, ScalarSize)
                    .CopyTo(leaves.Slice(((block * blockSize) + j) * ScalarSize, ScalarSize));
            }
        }
    }


    /// <summary>
    /// Validates the coefficient and destination spans against the domain
    /// shape and returns the domain length.
    /// </summary>
    private int ValidateEncodeShape(ReadOnlySpan<byte> coefficients, int domainSizeLog2, int destinationLength)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(domainSizeLog2, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(domainSizeLog2, MaximumDomainSizeLog2);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(domainSizeLog2, ScalarNtt.TwoAdicity(curve));

        int domainLength = 1 << domainSizeLog2;
        if(destinationLength != domainLength * ScalarSize)
        {
            throw new ArgumentException(
                $"The destination must carry {domainLength} elements ({domainLength * ScalarSize} bytes); received {destinationLength}.");
        }

        if(coefficients.Length == 0
            || coefficients.Length % ScalarSize != 0
            || !BitOperations.IsPow2(coefficients.Length / ScalarSize)
            || coefficients.Length > domainLength * ScalarSize)
        {
            throw new ArgumentException(
                $"The coefficient vector must be a power-of-two count of {ScalarSize}-byte elements of at most the domain length {domainLength}; received {coefficients.Length} bytes.",
                nameof(coefficients));
        }

        return domainLength;
    }


    /// <summary>
    /// Validates the message, randomness and destination spans of a
    /// zero-knowledge encode against the domain shape and returns the domain
    /// length. The message need not have a power-of-two element count — the
    /// mask codes carry arbitrary lengths — but message and randomness
    /// together must fit the domain: the fit is load-bearing for hiding, a
    /// vector that saturates the domain would pin the codeword.
    /// </summary>
    private int ValidateZeroKnowledgeEncodeShape(
        ReadOnlySpan<byte> coefficients,
        ReadOnlySpan<byte> randomness,
        int domainSizeLog2,
        int destinationLength)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(domainSizeLog2, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(domainSizeLog2, MaximumDomainSizeLog2);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(domainSizeLog2, ScalarNtt.TwoAdicity(curve));

        int domainLength = 1 << domainSizeLog2;
        if(destinationLength != domainLength * ScalarSize)
        {
            throw new ArgumentException(
                $"The destination must carry {domainLength} elements ({domainLength * ScalarSize} bytes); received {destinationLength}.");
        }

        if(coefficients.Length == 0 || coefficients.Length % ScalarSize != 0)
        {
            throw new ArgumentException(
                $"The message must be a positive count of {ScalarSize}-byte elements; received {coefficients.Length} bytes.",
                nameof(coefficients));
        }

        if(randomness.Length % ScalarSize != 0)
        {
            throw new ArgumentException(
                $"The randomness must be a count of {ScalarSize}-byte elements; received {randomness.Length} bytes.",
                nameof(randomness));
        }

        if(coefficients.Length + randomness.Length > domainLength * ScalarSize)
        {
            throw new ArgumentException(
                $"The message and randomness together must fit the domain of {domainLength} elements; received {(coefficients.Length + randomness.Length) / ScalarSize}.",
                nameof(randomness));
        }

        return domainLength;
    }


    /// <summary>
    /// Derives the domain root, builds its twiddle table and runs the forward
    /// transform in place, leaving bit-reversed order.
    /// </summary>
    private void TransformInPlace(Span<byte> data, int domainSizeLog2)
    {
        int domainLength = 1 << domainSizeLog2;
        int twiddleCount = domainLength / 2;

        Span<byte> root = stackalloc byte[ScalarSize];
        ScalarNtt.DeriveRootOfUnity(domainSizeLog2, root, subtract, multiply, WriteCanonicalUInt, curve);

        using IMemoryOwner<byte> twiddleOwner = pool.Rent(twiddleCount * ScalarSize);
        Span<byte> twiddles = twiddleOwner.Memory.Span[..(twiddleCount * ScalarSize)];
        ScalarNtt.BuildTwiddles(root, domainLength, twiddles, multiply, WriteCanonicalUInt, curve);
        ScalarNtt.Forward(data, domainLength, twiddles, add, subtract, multiply, curve);
    }


    /// <summary>
    /// Reverses the low <paramref name="bitCount"/> bits of a value.
    /// </summary>
    private static int ReverseBits(int value, int bitCount)
    {
        int reversed = 0;
        for(int bit = 0; bit < bitCount; bit++)
        {
            reversed = (reversed << 1) | ((value >> bit) & 1);
        }

        return reversed;
    }


    /// <summary>
    /// Writes a small integer as a canonical big-endian field element — the
    /// working-domain injection the raw transform surfaces take.
    /// </summary>
    private static void WriteCanonicalUInt(uint value, Span<byte> destination)
    {
        destination.Clear();
        BinaryPrimitives.WriteUInt32BigEndian(destination[(ScalarSize - sizeof(uint))..], value);
    }
}
