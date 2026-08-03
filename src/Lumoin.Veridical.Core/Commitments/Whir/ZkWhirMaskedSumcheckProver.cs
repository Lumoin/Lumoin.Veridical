using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Sumcheck;
using System;
using System.Buffers;
using System.Buffers.Binary;

namespace Lumoin.Veridical.Core.Commitments.Whir;

/// <summary>
/// The prover side of one masked-sumcheck fold batch of the hiding WHIR path
/// (eprint 2026/391 Construction 6.3): commits the batch's mask oracle, sends
/// the mask total <c>μ̃</c> before any challenge, receives the combining
/// challenge <c>ε</c> and runs <c>k</c> masked rounds whose wire polynomial
/// blends the live mask, the past mask evaluations, the future mask endpoints
/// and the plain sumcheck contribution scaled by <c>ε</c>:
/// </summary>
/// <remarks>
/// <para>
/// <code>
/// h_j(X) = 2^(k-j)   · s_j(X)
///        + 2^(k-j)   · Σ_(l&lt;j) s_l(γ_l)
///        + 2^(k-j-1) · Σ_(l&gt;j) (s_l(0) + s_l(1))
///        + ε         · plain_j(X)
/// </code>
/// </para>
/// <para>
/// The wire stays in the compressed <c>c_1</c>-elided convention: the masked
/// polynomial's linear coefficient is dropped and the verifier reconstructs
/// it from the running chain <c>h_j(0) + h_j(1) = h_(j-1)(γ_(j-1))</c>
/// (round 1: <c>ε·μ + μ̃</c>, with <c>μ</c> the joint claim). The prover
/// therefore never materialises a linear coefficient — the plain rounds'
/// pair-fold yields exactly the constant and quadratic terms, matching the
/// non-hiding prover.
/// </para>
/// <para>
/// The committed-sumcheck composition (eprint 2026/391 Definition 5.8) pairs
/// the source claim <c>⟨f, w⟩</c> with the carried mask-oracle claims
/// <c>⟨ξ_i, u_i⟩</c>: their total is the batch's auxiliary constant, the
/// bound scalar is the joint claim (source plus auxiliary), and the constant
/// rides the affine chain as <c>ε·aux·2^(-j)</c> on each wire's constant
/// slot, so the final residual gains <c>ε·aux·2^(-k)</c> and downstream
/// reductions rescale the carried mask covectors by exactly
/// <c>ε·2^(-k)</c>.
/// </para>
/// <para>
/// The masking layer leaves the fold structure untouched: the caller binds
/// the same tables with the same challenges as the plain protocol, and this
/// driver mutates them in step so a following batch resumes exactly where the
/// plain prover would.
/// </para>
/// </remarks>
public static class ZkWhirMaskedSumcheckProver
{
    /// <summary>The byte size of one field element.</summary>
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Runs one full masked fold batch: binds the joint claim, absorbs the
    /// mask oracle root and the mask total, squeezes <c>ε</c>, then per round
    /// emits the masked wire polynomial, squeezes the fold challenge and
    /// binds the tables.
    /// </summary>
    /// <param name="functionTable">The f-table over the current cube, <c>size</c> elements; bound in place round by round.</param>
    /// <param name="weightTable">The weight table over the current cube, <c>size</c> elements; bound in place round by round.</param>
    /// <param name="size">The table element count at batch start, at least <c>2^k</c> and a power of two.</param>
    /// <param name="masks">The batch's committed masks, <c>k</c> of them.</param>
    /// <param name="sourceClaim">The batch's incoming source claim <c>⟨f, w⟩</c>, one element.</param>
    /// <param name="auxClaim">The carried mask-claim total entering the batch as its auxiliary constant, one element; zero for the initial batch.</param>
    /// <param name="transcript">The Fiat-Shamir transcript.</param>
    /// <param name="hash">The transcript's fixed-output hash backend.</param>
    /// <param name="squeeze">The transcript's XOF backend.</param>
    /// <param name="reduce">The scalar-reduce backend for deriving challenges.</param>
    /// <param name="add">Scalar-add backend.</param>
    /// <param name="subtract">Scalar-subtract backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="invert">Scalar-invert backend, for the auxiliary carry's <c>2^(-j)</c> factors.</param>
    /// <param name="pool">The pool the wire buffers rent from.</param>
    /// <param name="epsilon">Receives the combining challenge <c>ε</c>, one element.</param>
    /// <param name="challenges">Receives the fold challenges <c>γ_1..γ_k</c>, <c>k</c> elements.</param>
    /// <returns>The <c>k</c> compressed wire polynomials in round order; the caller owns their disposal.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span length does not match the shape.</exception>
    public static CompressedRoundPolynomial[] RunBatch(
        Span<byte> functionTable,
        Span<byte> weightTable,
        int size,
        ZkWhirMaskGroup masks,
        ReadOnlySpan<byte> sourceClaim,
        ReadOnlySpan<byte> auxClaim,
        FiatShamirTranscript transcript,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate reduce,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        BaseMemoryPool pool,
        Span<byte> epsilon,
        Span<byte> challenges)
    {
        ArgumentNullException.ThrowIfNull(masks);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(squeeze);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(pool);

        int roundCount = masks.MaskCount;
        CurveParameterSet curve = masks.Curve;
        ValidateBatchShape(functionTable.Length, weightTable.Length, size, roundCount, epsilon.Length, challenges.Length);
        ThrowIfNotOneElement(sourceClaim, nameof(sourceClaim));
        ThrowIfNotOneElement(auxClaim, nameof(auxClaim));

        //The joint claim binds first so every batch transcript is
        //self-contained, mirroring the reference domain-separator order.
        Span<byte> jointClaim = stackalloc byte[ScalarSize];
        add(sourceClaim, auxClaim, jointClaim, curve);
        transcript.AbsorbWhirMaskBatchClaim(jointClaim, hash);

        transcript.AbsorbWhirMaskOracleRoot(masks.Tree.Root, hash);

        Span<byte> maskTotal = stackalloc byte[ScalarSize];
        masks.WriteMaskTotal(maskTotal, add, multiply);
        transcript.AbsorbWhirMaskTotal(maskTotal, hash);

        using(Scalar epsilonScalar = transcript.SqueezeWhirMaskCombinationChallenge(squeeze, hash, reduce, curve, pool))
        {
            epsilonScalar.AsReadOnlySpan().CopyTo(epsilon);
        }

        //Running mask state: the past evaluations Σ_(l<j) s_l(γ_l) and the
        //future endpoints Σ_(l>j) (s_l(0) + s_l(1)); the live round moves its
        //endpoint out of the future sum before assembly.
        Span<byte> pastEvaluationSum = stackalloc byte[ScalarSize];
        pastEvaluationSum.Clear();
        Span<byte> futureEndpointSum = stackalloc byte[ScalarSize];
        futureEndpointSum.Clear();
        Span<byte> endpointSum = stackalloc byte[ScalarSize];
        Span<byte> term = stackalloc byte[ScalarSize];
        Span<byte> scale = stackalloc byte[ScalarSize];

        //The auxiliary constant's carry aux·2^(-j), halved once per round so
        //the chain telescopes to ε·aux·2^(-k) on the residual.
        Span<byte> half = stackalloc byte[ScalarSize];
        WriteCanonicalUInt(2, half);
        invert(half, half, curve);
        Span<byte> auxCarry = stackalloc byte[ScalarSize];
        auxClaim.CopyTo(auxCarry);
        for(int mask = 0; mask < roundCount; mask++)
        {
            masks.WriteEndpointSum(mask, endpointSum, add);
            add(futureEndpointSum, endpointSum, futureEndpointSum, curve);
        }

        int wireDegree = Math.Max(masks.Shape.MessageLength - 1, 2);
        int wireLength = wireDegree * ScalarSize;
        var wires = new CompressedRoundPolynomial[roundCount];
        int built = 0;
        try
        {
            using IMemoryOwner<byte> wireOwner = pool.Rent(wireLength);
            Span<byte> wire = wireOwner.Memory.Span[..wireLength];
            int currentSize = size;
            for(int round = 0; round < roundCount; round++)
            {
                //One-based round index j of the construction's formulas.
                int j = round + 1;

                masks.WriteEndpointSum(round, endpointSum, add);
                subtract(futureEndpointSum, endpointSum, futureEndpointSum, curve);

                //The wire in compressed storage order (c_0, c_2, ..., c_d):
                //slot 0 is the constant term, slot i-1 the degree-i term for
                //i ≥ 2. The linear term is never assembled — it is elided on
                //the wire and reconstructed by the verifier from the chain.
                wire.Clear();
                Span<byte> constantSlot = wire[..ScalarSize];

                //Live mask, scaled 2^(k-j).
                WriteCanonicalUInt(1u << (roundCount - j), scale);
                ReadOnlySpan<byte> maskCoefficients = masks.MaskCoefficients(round);
                for(int degree = 0; degree < masks.Shape.MessageLength; degree++)
                {
                    if(degree == 1)
                    {
                        continue;
                    }

                    int slot = degree == 0 ? 0 : degree - 1;
                    multiply(maskCoefficients.Slice(degree * ScalarSize, ScalarSize), scale, term, curve);
                    add(wire.Slice(slot * ScalarSize, ScalarSize), term, wire.Slice(slot * ScalarSize, ScalarSize), curve);
                }

                //Past mask evaluations, scaled 2^(k-j).
                multiply(pastEvaluationSum, scale, term, curve);
                add(constantSlot, term, constantSlot, curve);

                //Future mask endpoints, scaled 2^(k-j-1); absent in the last round.
                if(j < roundCount)
                {
                    WriteCanonicalUInt(1u << (roundCount - j - 1), scale);
                    multiply(futureEndpointSum, scale, term, curve);
                    add(constantSlot, term, constantSlot, curve);
                }

                //Auxiliary constant carry: the wire's constant slot gains
                //ε·aux·2^(-j), entering the affine chain like a plain
                //constant term.
                multiply(auxCarry, half, auxCarry, curve);
                multiply(auxCarry, epsilon, term, curve);
                add(constantSlot, term, constantSlot, curve);

                //Plain contribution ε·plain_j: the pair-fold constant and
                //quadratic terms of the f-table and weight-table product,
                //identical to the non-hiding prover's round computation.
                ComputePlainRoundTerms(
                    functionTable[..(currentSize * ScalarSize)],
                    weightTable[..(currentSize * ScalarSize)],
                    currentSize,
                    epsilon,
                    wire,
                    add,
                    subtract,
                    multiply,
                    curve);

                CompressedRoundPolynomial wirePolynomial = CompressedRoundPolynomial.FromCompressedBytes(wire, wireDegree, curve, pool);
                wires[round] = wirePolynomial;
                built++;
                transcript.AbsorbWhirSumcheckPolynomial(wirePolynomial, hash);

                using Scalar challenge = transcript.SqueezeWhirFoldChallenge(squeeze, hash, reduce, curve, pool);
                ReadOnlySpan<byte> challengeBytes = challenge.AsReadOnlySpan();
                challengeBytes.CopyTo(challenges.Slice(round * ScalarSize, ScalarSize));

                masks.EvaluateMask(round, challengeBytes, term, add, multiply);
                add(pastEvaluationSum, term, pastEvaluationSum, curve);

                WhirMultilinear.BindFirstVariable(functionTable, currentSize, challengeBytes, add, subtract, multiply, curve);
                WhirMultilinear.BindFirstVariable(weightTable, currentSize, challengeBytes, add, subtract, multiply, curve);
                currentSize /= 2;
            }

            return wires;
        }
        catch
        {
            for(int wireIndex = 0; wireIndex < built; wireIndex++)
            {
                wires[wireIndex].Dispose();
            }

            throw;
        }
    }


    /// <summary>
    /// Accumulates <c>ε·plain_j</c> into the wire's constant and quadratic
    /// slots: over even/odd pairs, <c>c_0 = Σ f_even·w_even</c> and
    /// <c>c_2 = Σ (f_odd − f_even)·(w_odd − w_even)</c> — the same pair-fold
    /// as the non-hiding round computation, scaled by the combining
    /// challenge.
    /// </summary>
    private static void ComputePlainRoundTerms(
        ReadOnlySpan<byte> functionTable,
        ReadOnlySpan<byte> weightTable,
        int size,
        ReadOnlySpan<byte> epsilon,
        Span<byte> wire,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        Span<byte> constantTerm = stackalloc byte[ScalarSize];
        constantTerm.Clear();
        Span<byte> quadraticTerm = stackalloc byte[ScalarSize];
        quadraticTerm.Clear();
        Span<byte> functionSlope = stackalloc byte[ScalarSize];
        Span<byte> weightSlope = stackalloc byte[ScalarSize];
        Span<byte> product = stackalloc byte[ScalarSize];
        int half = size / 2;
        for(int pair = 0; pair < half; pair++)
        {
            ReadOnlySpan<byte> functionEven = functionTable.Slice(2 * pair * ScalarSize, ScalarSize);
            ReadOnlySpan<byte> functionOdd = functionTable.Slice(((2 * pair) + 1) * ScalarSize, ScalarSize);
            ReadOnlySpan<byte> weightEven = weightTable.Slice(2 * pair * ScalarSize, ScalarSize);
            ReadOnlySpan<byte> weightOdd = weightTable.Slice(((2 * pair) + 1) * ScalarSize, ScalarSize);

            multiply(functionEven, weightEven, product, curve);
            add(constantTerm, product, constantTerm, curve);

            subtract(functionOdd, functionEven, functionSlope, curve);
            subtract(weightOdd, weightEven, weightSlope, curve);
            multiply(functionSlope, weightSlope, product, curve);
            add(quadraticTerm, product, quadraticTerm, curve);
        }

        multiply(constantTerm, epsilon, constantTerm, curve);
        add(wire[..ScalarSize], constantTerm, wire[..ScalarSize], curve);

        multiply(quadraticTerm, epsilon, quadraticTerm, curve);
        add(wire.Slice(ScalarSize, ScalarSize), quadraticTerm, wire.Slice(ScalarSize, ScalarSize), curve);
    }


    /// <summary>
    /// Validates the batch's span shapes against the mask count and table
    /// size.
    /// </summary>
    private static void ValidateBatchShape(
        int functionTableLength,
        int weightTableLength,
        int size,
        int roundCount,
        int epsilonLength,
        int challengesLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(size);
        if(size < 1 << roundCount)
        {
            throw new ArgumentException(
                $"The table must carry at least 2^{roundCount} elements to fold {roundCount} rounds; received {size}.",
                nameof(size));
        }

        if(functionTableLength < size * ScalarSize || weightTableLength < size * ScalarSize)
        {
            throw new ArgumentException(
                $"The tables must carry at least {size} elements ({size * ScalarSize} bytes); received {functionTableLength} and {weightTableLength}.");
        }

        if(epsilonLength != ScalarSize)
        {
            throw new ArgumentException(
                $"The epsilon destination must carry one element ({ScalarSize} bytes); received {epsilonLength}.");
        }

        if(challengesLength != roundCount * ScalarSize)
        {
            throw new ArgumentException(
                $"The challenges destination must carry {roundCount} elements ({roundCount * ScalarSize} bytes); received {challengesLength}.");
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


    /// <summary>
    /// Rejects a span that is not exactly one field element wide.
    /// </summary>
    private static void ThrowIfNotOneElement(ReadOnlySpan<byte> span, string parameterName)
    {
        if(span.Length != ScalarSize)
        {
            throw new ArgumentException($"The value must be one {ScalarSize}-byte element; received {span.Length} bytes.", parameterName);
        }
    }
}
