using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Whir;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;

namespace Lumoin.Veridical.Tests.Commitments.Whir;

/// <summary>
/// Tests for the code-switch batching algebra of the hiding WHIR path
/// (4.2 phase C2, eprint 2026/391 Construction 9.7): the zero-evader padded
/// evaluation must equal plain Horner over the concatenated coefficient
/// vector, the switch-mask covector must reproduce the mask side of the
/// batched claim as a dot product — with the query layers stopping at the
/// randomness boundary because the fresh pad never appears in openings — and
/// the loud out-of-domain gate must reject a zero point, coinciding points
/// and an underfilled pad exactly as ruled, instead of leaking silently.
/// </summary>
[TestClass]
internal sealed class ZkWhirCodeSwitchTests
{
    /// <summary>The byte size of one field element.</summary>
    private const int ScalarSize = 32;

    /// <summary>
    /// The test message element count; deliberately not a power of two, since
    /// the zero-evader form must serve the mask codes' arbitrary lengths.
    /// </summary>
    private const int MessageLength = 5;

    /// <summary>The test folded-randomness element count of the mask message.</summary>
    private const int RandomnessLength = 3;

    /// <summary>The test pad element count of the mask message.</summary>
    private const int PadLength = 2;

    /// <summary>A fill salt for the message stream, distinct from the mask stream.</summary>
    private const int MessageSalt = 51;

    /// <summary>A fill salt for the mask-message stream, distinct from the message stream.</summary>
    private const int MaskSalt = 52;

    /// <summary>A fill salt for the evaluation points, distinct from both coefficient streams.</summary>
    private const int PointSalt = 53;

    /// <summary>The BLS12-381 scalar backend bundle.</summary>
    private static ScalarArithmeticBackend Bls { get; } = TestScalarBackends.Bls12Curve381;


    [TestMethod]
    public void PaddedEvaluationMatchesConcatenatedHorner()
    {
        Span<byte> message = stackalloc byte[MessageLength * ScalarSize];
        Span<byte> maskMessage = stackalloc byte[(RandomnessLength + PadLength) * ScalarSize];
        Span<byte> point = stackalloc byte[ScalarSize];
        DeterministicScalarFill.FillCanonical(message, MessageSalt, Bls.Reduce, Bls.Curve);
        DeterministicScalarFill.FillCanonical(maskMessage, MaskSalt, Bls.Reduce, Bls.Curve);
        DeterministicScalarFill.FillCanonical(point, PointSalt, Bls.Reduce, Bls.Curve);

        Span<byte> viaSplitForm = stackalloc byte[ScalarSize];
        ZkWhirCodeSwitch.EvaluatePaddedOutOfDomain(point, message, maskMessage, viaSplitForm, Bls.Add, Bls.Multiply, Bls.Curve);

        //Reference: the concatenated vector evaluated as one polynomial.
        Span<byte> concatenated = stackalloc byte[(MessageLength + RandomnessLength + PadLength) * ScalarSize];
        message.CopyTo(concatenated);
        maskMessage.CopyTo(concatenated[(MessageLength * ScalarSize)..]);
        Span<byte> viaConcatenation = stackalloc byte[ScalarSize];
        ZkWhirCodeSwitch.EvaluateCoefficients(point, concatenated, viaConcatenation, Bls.Add, Bls.Multiply, Bls.Curve);

        Assert.IsTrue(viaConcatenation.SequenceEqual(viaSplitForm), "The split zero-evader form must equal Horner over the concatenation.");
    }


    [TestMethod]
    public void EmptyCoefficientVectorEvaluatesToZero()
    {
        Span<byte> point = stackalloc byte[ScalarSize];
        DeterministicScalarFill.FillCanonical(point, PointSalt, Bls.Reduce, Bls.Curve);

        Span<byte> value = stackalloc byte[ScalarSize];
        value[0] = 0xFF;
        ZkWhirCodeSwitch.EvaluateCoefficients(point, [], value, Bls.Add, Bls.Multiply, Bls.Curve);

        Span<byte> zero = stackalloc byte[ScalarSize];
        Assert.IsTrue(zero.SequenceEqual(value), "An empty coefficient vector must evaluate to the empty sum.");
    }


    [TestMethod]
    public void SwitchMaskCovectorReproducesTheMaskSideOfTheBatchedClaim()
    {
        //Two out-of-domain layers and two query layers with distinct
        //coefficients: enough to catch a wrong power shift, a swapped layer
        //or a pad slot reached by a query layer.
        const int OutOfDomainCount = 2;
        const int QueryCount = 2;
        Span<byte> maskMessage = stackalloc byte[(RandomnessLength + PadLength) * ScalarSize];
        Span<byte> outOfDomainPoints = stackalloc byte[OutOfDomainCount * ScalarSize];
        Span<byte> outOfDomainCoefficients = stackalloc byte[OutOfDomainCount * ScalarSize];
        Span<byte> queryPoints = stackalloc byte[QueryCount * ScalarSize];
        Span<byte> queryCoefficients = stackalloc byte[QueryCount * ScalarSize];
        DeterministicScalarFill.FillCanonical(maskMessage, MaskSalt, Bls.Reduce, Bls.Curve);
        DeterministicScalarFill.FillCanonical(outOfDomainPoints, PointSalt, Bls.Reduce, Bls.Curve);
        DeterministicScalarFill.FillCanonical(outOfDomainCoefficients, MessageSalt, Bls.Reduce, Bls.Curve);
        DeterministicScalarFill.FillCanonical(queryPoints, PointSalt + 1, Bls.Reduce, Bls.Curve);
        DeterministicScalarFill.FillCanonical(queryCoefficients, MessageSalt + 1, Bls.Reduce, Bls.Curve);

        Span<byte> covector = stackalloc byte[(RandomnessLength + PadLength) * ScalarSize];
        ZkWhirCodeSwitch.WriteSwitchMaskCovector(
            MessageLength,
            RandomnessLength,
            PadLength,
            outOfDomainPoints,
            outOfDomainCoefficients,
            queryPoints,
            queryCoefficients,
            covector,
            Bls.Add,
            Bls.Multiply,
            Bls.Curve);

        Span<byte> viaCovector = stackalloc byte[ScalarSize];
        WriteDotProduct(covector, maskMessage, RandomnessLength + PadLength, viaCovector);

        //Reference: every layer as a scaled shifted evaluation — the
        //out-of-domain layers over the whole mask message, the query layers
        //over the randomness prefix only.
        Span<byte> expected = stackalloc byte[ScalarSize];
        expected.Clear();
        Span<byte> shift = stackalloc byte[ScalarSize];
        Span<byte> value = stackalloc byte[ScalarSize];
        for(int layer = 0; layer < OutOfDomainCount; layer++)
        {
            ReadOnlySpan<byte> point = outOfDomainPoints.Slice(layer * ScalarSize, ScalarSize);
            ZkWhirCodeSwitch.EvaluateCoefficients(point, maskMessage, value, Bls.Add, Bls.Multiply, Bls.Curve);
            WhirFold.ComputeDomainPoint(point, MessageLength, shift, Bls.Multiply, Bls.Curve);
            Bls.Multiply(value, shift, value, Bls.Curve);
            Bls.Multiply(value, outOfDomainCoefficients.Slice(layer * ScalarSize, ScalarSize), value, Bls.Curve);
            Bls.Add(expected, value, expected, Bls.Curve);
        }

        for(int layer = 0; layer < QueryCount; layer++)
        {
            ReadOnlySpan<byte> point = queryPoints.Slice(layer * ScalarSize, ScalarSize);
            ZkWhirCodeSwitch.EvaluateCoefficients(point, maskMessage[..(RandomnessLength * ScalarSize)], value, Bls.Add, Bls.Multiply, Bls.Curve);
            WhirFold.ComputeDomainPoint(point, MessageLength, shift, Bls.Multiply, Bls.Curve);
            Bls.Multiply(value, shift, value, Bls.Curve);
            Bls.Multiply(value, queryCoefficients.Slice(layer * ScalarSize, ScalarSize), value, Bls.Curve);
            Bls.Add(expected, value, expected, Bls.Curve);
        }

        Assert.IsTrue(expected.SequenceEqual(viaCovector), "The covector dot product must reproduce the layered mask contributions.");
    }


    [TestMethod]
    public void ZeroOutOfDomainPointIsRejected()
    {
        Assert.Throws<InvalidOperationException>(static () => GateZeroPoint());
    }


    [TestMethod]
    public void CoincidingOutOfDomainPointsAreRejected()
    {
        Assert.Throws<InvalidOperationException>(static () => GateCoincidingPoints());
    }


    [TestMethod]
    public void UnderfilledPadIsRejected()
    {
        Assert.Throws<InvalidOperationException>(static () => GateDistinctPoints(padLength: 1));
    }


    [TestMethod]
    public void AdmissiblePointsPassTheGate()
    {
        GateDistinctPoints(padLength: 2);
    }


    /// <summary>
    /// Runs the gate against one zero point; the zero-point rejection test
    /// asserts on the exception this raises.
    /// </summary>
    private static void GateZeroPoint()
    {
        Span<byte> points = stackalloc byte[ScalarSize];
        points.Clear();
        ZkWhirCodeSwitch.ThrowIfOutOfDomainPointsInadmissible(points, PadLength);
    }


    /// <summary>
    /// Runs the gate against two identical nonzero points; the coincidence
    /// rejection test asserts on the exception this raises.
    /// </summary>
    private static void GateCoincidingPoints()
    {
        Span<byte> points = stackalloc byte[2 * ScalarSize];
        DeterministicScalarFill.FillCanonical(points[..ScalarSize], PointSalt, Bls.Reduce, Bls.Curve);
        points[..ScalarSize].CopyTo(points[ScalarSize..]);
        ZkWhirCodeSwitch.ThrowIfOutOfDomainPointsInadmissible(points, padLength: 2);
    }


    /// <summary>
    /// Runs the gate against two distinct nonzero points with the given pad
    /// length — the admissible case at a full pad, the underfilled-pad
    /// rejection at a short one.
    /// </summary>
    private static void GateDistinctPoints(int padLength)
    {
        Span<byte> points = stackalloc byte[2 * ScalarSize];
        DeterministicScalarFill.FillCanonical(points[..ScalarSize], PointSalt, Bls.Reduce, Bls.Curve);
        DeterministicScalarFill.FillCanonical(points[ScalarSize..], PointSalt + 1, Bls.Reduce, Bls.Curve);
        ZkWhirCodeSwitch.ThrowIfOutOfDomainPointsInadmissible(points, padLength);
    }


    /// <summary>
    /// Writes <c>destination = Σ a_i·b_i</c> over <paramref name="count"/>
    /// elements.
    /// </summary>
    private static void WriteDotProduct(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, int count, Span<byte> destination)
    {
        Span<byte> product = stackalloc byte[ScalarSize];
        destination.Clear();
        for(int index = 0; index < count; index++)
        {
            Bls.Multiply(a.Slice(index * ScalarSize, ScalarSize), b.Slice(index * ScalarSize, ScalarSize), product, Bls.Curve);
            Bls.Add(destination, product, destination, Bls.Curve);
        }
    }
}
