using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The LCH14 additive-FFT Reed–Solomon port, gated as a faithful translation of
/// google/longfellow-zk's <c>lib/gf2k/lch14.h</c> and <c>lib/gf2k/lch14_reed_solomon.h</c> over the
/// <c>GF(2^128)</c> field and both GF(2)-subfields the port supports: the production
/// <c>GF(2^16)</c> subfield (<see cref="Lch14Subfield.Production16"/>, the reference's
/// <c>GF2_128&lt;&gt;</c> default and the mdoc wire format) and the test-parity <c>GF(2^32)</c>
/// subfield (<see cref="Lch14Subfield.TestParity32"/>, <c>GF2_128&lt;5&gt;</c>). The
/// instantiation-generic gates run over both subfields; every reference test case is ported: the
/// normalized basis-vanishing table against its slow direct definition (their <c>WHat</c>), the
/// linear-time twiddles against the per-index form (their <c>Twiddle</c>), the cross-coset
/// interpolation against a Newton oracle (their <c>Interpolation</c>), the truncated-Fourier
/// round-trip against the forward transform (their <c>BidirectionalFFT</c>), and the systematic
/// Reed–Solomon interpolate over their exact <c>test_m</c> set against monomial evaluation (their
/// <c>ReedSolomon</c>). An independent naive-basis evaluation oracle catches a self-consistent but
/// wrong port; the two managed backends (the fast <see cref="Gf2k128Backend"/> and the
/// <see cref="Gf2k128Reference"/> oracle) must agree byte for byte; the basis, nodes and codewords
/// are pinned to the C++ reference for both subfields; and the adversarial duals show a corrupted
/// evaluation breaks the round-trip and a malformed <c>(n, m)</c> is rejected.
/// </summary>
[TestClass]
internal sealed class Lch14ReedSolomonTests
{
    /// <summary>
    /// The canonical scalar size in bytes, shared by every element buffer these gates allocate.
    /// </summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>
    /// The <see cref="Lch14Subfield.Production16"/> subfield, exposed as an MSTest data-row value so
    /// the instantiation-generic gates run over it.
    /// </summary>
    private const Lch14Subfield Production16 = Lch14Subfield.Production16;

    /// <summary>
    /// The <see cref="Lch14Subfield.TestParity32"/> subfield, exposed as an MSTest data-row value so
    /// the instantiation-generic gates run over it.
    /// </summary>
    private const Lch14Subfield TestParity32 = Lch14Subfield.TestParity32;

    /// <summary>
    /// The row cap for the Ŵ conformance gate. <see cref="WHatRef"/> is exponential in <c>i</c> (2^i
    /// products); google/longfellow-zk's own gate limits <c>i</c> to 16, and 12 keeps this gate fast
    /// while still exercising several recursion levels.
    /// </summary>
    private const int WHatGateRows = 12;

    /// <summary>
    /// The number of trailing big-endian bytes that hold the <c>GF(2^128)</c> element in a canonical
    /// scalar: the 128-bit element lives in bytes 16..31, and bytes 0..15 are zero.
    /// </summary>
    private const int ElementBytes = 16;

    /// <summary>
    /// The dimension <c>n</c> of the first anchored codeword. Paired with
    /// <see cref="AnchorStraddleBlockLength"/>, it covers the bidirectional pass and the
    /// straddling-coset branch.
    /// </summary>
    private const int AnchorStraddleDimension = 9;

    /// <summary>
    /// The block length <c>m</c> of the first anchored codeword. With <c>fftn = 16</c> and
    /// <see cref="AnchorStraddleDimension"/>, <c>m = 23</c> straddles a coset (the partial-copy
    /// path).
    /// </summary>
    private const int AnchorStraddleBlockLength = 23;

    /// <summary>
    /// The dimension <c>n</c> of the second anchored codeword, paired with
    /// <see cref="AnchorFullCosetBlockLength"/>.
    /// </summary>
    private const int AnchorFullCosetDimension = 9;

    /// <summary>
    /// The block length <c>m</c> of the second anchored codeword. With <c>fftn = 16</c>, <c>m =
    /// 64</c> fills whole cosets and never straddles, so its spot anchors sit at coset boundaries.
    /// </summary>
    private const int AnchorFullCosetBlockLength = 64;

    /// <summary>
    /// The FFT dimension <c>l</c> for the cross-coset interpolation gate, matching
    /// google/longfellow-zk's own <c>Interpolation</c> test (<c>l = 5</c>, <c>n = 32</c>).
    /// </summary>
    private const int InterpolationDimension = 5;

    /// <summary>
    /// The number of cosets the cross-coset interpolation gate checks against each other, matching
    /// google/longfellow-zk's own <c>Interpolation</c> test.
    /// </summary>
    private const int InterpolationCosets = 7;

    /// <summary>
    /// The FFT dimension <c>l</c> for the truncated-Fourier round-trip gate. google/longfellow-zk's
    /// own <c>BidirectionalFFT</c> test uses <c>l = 10</c>; this smaller <c>l</c> exercises the
    /// identical kernel (every <c>k</c> from 0 to 2^l) far faster over the slow reference field.
    /// </summary>
    private const int BidirectionalDimension = 7;

    /// <summary>
    /// The exact block-length set google/longfellow-zk's own <c>ReedSolomon</c> test iterates over.
    /// </summary>
    private static int[] ReedSolomonBlockLengths { get; } = [1, 7, 8, 9, 63, 64, 65, 99, 128];

    /// <summary>
    /// The fast production backend's scalar addition delegate.
    /// </summary>
    private static ScalarAddDelegate FastAdd { get; } = Gf2k128Backend.GetAdd();

    /// <summary>
    /// The fast production backend's scalar subtraction delegate.
    /// </summary>
    private static ScalarSubtractDelegate FastSubtract { get; } = Gf2k128Backend.GetSubtract();

    /// <summary>
    /// The fast production backend's scalar multiplication delegate.
    /// </summary>
    private static ScalarMultiplyDelegate FastMultiply { get; } = Gf2k128Backend.GetMultiply();

    /// <summary>
    /// The fast production backend's scalar inversion delegate.
    /// </summary>
    private static ScalarInvertDelegate FastInvert { get; } = Gf2k128Backend.GetInvert();

    /// <summary>
    /// The slow, independently defined reference backend's scalar addition delegate, used to
    /// cross-check <see cref="FastAdd"/>.
    /// </summary>
    private static ScalarAddDelegate ReferenceAdd { get; } = Gf2k128Reference.GetAdd();

    /// <summary>
    /// The slow, independently defined reference backend's scalar subtraction delegate, used to
    /// cross-check <see cref="FastSubtract"/>.
    /// </summary>
    private static ScalarSubtractDelegate ReferenceSubtract { get; } = Gf2k128Reference.GetSubtract();

    /// <summary>
    /// The slow, independently defined reference backend's scalar multiplication delegate, used to
    /// cross-check <see cref="FastMultiply"/>.
    /// </summary>
    private static ScalarMultiplyDelegate ReferenceMultiply { get; } = Gf2k128Reference.GetMultiply();

    /// <summary>
    /// The slow, independently defined reference backend's scalar inversion delegate, used to
    /// cross-check <see cref="FastInvert"/>.
    /// </summary>
    private static ScalarInvertDelegate ReferenceInvert { get; } = Gf2k128Reference.GetInvert();


    /// <summary>
    /// Asserts that <see cref="Lch14AdditiveFft.NormalizedWHat"/> matches the slow, direct
    /// definition <see cref="WHatRef"/> computes, for every row up to <see cref="WHatGateRows"/> and
    /// every basis column, over both subfields.
    /// </summary>
    /// <param name="subfield">The GF(2)-subfield instantiation this gate runs over.</param>
    [TestMethod]
    [DataRow(Production16)]
    [DataRow(TestParity32)]
    public void NormalizedTableMatchesTheSlowBasisVanishingDefinition(Lch14Subfield subfield)
    {
        using Lch14AdditiveFft fft = NewFastFft(subfield);
        int subFieldBits = fft.SubFieldBits;
        int rows = Math.Min(WHatGateRows, subFieldBits);
        Span<byte> expected = stackalloc byte[ScalarSize];
        for(int i = 0; i < rows; i++)
        {
            for(int j = 0; j < subFieldBits; j++)
            {
                WHatRef(fft, i, fft.BasisElement(j), expected, FastMultiply, FastInvert);
                Assert.IsTrue(
                    fft.NormalizedWHat(i, j).SequenceEqual(expected),
                    $"Ŵ_{i}(β_{j}) must match the slow direct definition.");
            }
        }
    }


    /// <summary>
    /// Asserts that <see cref="Lch14AdditiveFft.ComputeTwiddleTable"/>'s linear-time table matches
    /// <see cref="Lch14AdditiveFft.Twiddle"/> computed per index, for every stage of a dimension
    /// within both subfields' transform bound.
    /// </summary>
    /// <param name="subfield">The GF(2)-subfield instantiation this gate runs over.</param>
    [TestMethod]
    [DataRow(Production16)]
    [DataRow(TestParity32)]
    public void LinearTimeTwiddlesMatchThePerIndexForm(Lch14Subfield subfield)
    {
        using Lch14AdditiveFft fft = NewFastFft(subfield);

        //A dimension at or below the smaller subfield's basis width, so the gate runs identically
        //over both subfields and stays within each instance's transform bound.
        const int dimension = 12;
        using IMemoryOwner<byte> tableOwner = BaseMemoryPool.Shared.Rent(Lch14AdditiveFft.TwiddleCount(dimension) * ScalarSize);
        Span<byte> table = tableOwner.Memory.Span[..(Lch14AdditiveFft.TwiddleCount(dimension) * ScalarSize)];
        Span<byte> single = stackalloc byte[ScalarSize];

        for(int i = 0; i < dimension; i++)
        {
            fft.ComputeTwiddleTable(i, dimension, coset: 0, table);
            for(int u = 0; (u << (i + 1)) < (1 << dimension); u++)
            {
                fft.Twiddle(i, u << (i + 1), single);
                Assert.IsTrue(
                    table.Slice(u * ScalarSize, ScalarSize).SequenceEqual(single),
                    $"Linear-time twiddle [{u}] of stage {i} must match the per-index form.");
            }
        }
    }


    /// <summary>
    /// Asserts that inverse-transforming one coset's evaluations to novel-basis coefficients and then
    /// forward-transforming to every other coset matches an independent Newton-interpolant evaluation
    /// at each target coset's nodes, for both subfields.
    /// </summary>
    /// <param name="subfield">The GF(2)-subfield instantiation this gate runs over.</param>
    [TestMethod]
    [DataRow(Production16)]
    [DataRow(TestParity32)]
    public void CrossCosetInterpolationMatchesTheNewtonOracle(Lch14Subfield subfield)
    {
        using Lch14AdditiveFft fft = NewFastFft(subfield);
        const int l = InterpolationDimension;
        int n = 1 << l;

        using IMemoryOwner<byte> nodeOwner = BaseMemoryPool.Shared.Rent(n * ScalarSize);
        using IMemoryOwner<byte> valueOwner = BaseMemoryPool.Shared.Rent(n * ScalarSize);
        using IMemoryOwner<byte> coefficientOwner = BaseMemoryPool.Shared.Rent(n * ScalarSize);
        using IMemoryOwner<byte> transformedOwner = BaseMemoryPool.Shared.Rent(n * ScalarSize);
        using IMemoryOwner<byte> dividedOwner = BaseMemoryPool.Shared.Rent(n * ScalarSize);
        Span<byte> nodes = nodeOwner.Memory.Span[..(n * ScalarSize)];
        Span<byte> values = valueOwner.Memory.Span[..(n * ScalarSize)];
        Span<byte> coefficients = coefficientOwner.Memory.Span[..(n * ScalarSize)];
        Span<byte> transformed = transformedOwner.Memory.Span[..(n * ScalarSize)];
        Span<byte> dividedDifferences = dividedOwner.Memory.Span[..(n * ScalarSize)];

        Span<byte> point = stackalloc byte[ScalarSize];
        Span<byte> oracle = stackalloc byte[ScalarSize];
        for(int ca = 0; ca < InterpolationCosets; ca++)
        {
            for(int i = 0; i < n; i++)
            {
                fft.NodeElement((uint)(i + (ca << l)), nodes.Slice(i * ScalarSize, ScalarSize));
                fft.NodeElement((uint)(((i * (i + ca)) ^ 42)), values.Slice(i * ScalarSize, ScalarSize));
            }

            //The Newton divided differences over coset A's nodes and values depend on neither the
            //target coset nor the evaluation point, so build them once and Horner-evaluate cheaply.
            BuildDividedDifferences(values, nodes, n, dividedDifferences, FastSubtract, FastMultiply, FastInvert);

            //IFFT the coset-A evaluations to novel-basis coefficients, then forward-transform to
            //every coset B and check against the Newton interpolant at coset B's nodes.
            values.CopyTo(coefficients);
            fft.InverseTransform(l, ca << l, coefficients);

            for(int cb = 0; cb < InterpolationCosets; cb++)
            {
                coefficients.CopyTo(transformed);
                fft.ForwardTransform(l, cb << l, transformed);
                for(int i = 0; i < n; i++)
                {
                    fft.NodeElement((uint)(i + (cb << l)), point);
                    NewtonHorner(dividedDifferences, nodes, n, point, oracle, FastAdd, FastSubtract, FastMultiply);
                    Assert.IsTrue(
                        transformed.Slice(i * ScalarSize, ScalarSize).SequenceEqual(oracle),
                        $"Coset {ca}→{cb} evaluation [{i}] must match the Newton oracle.");
                }
            }

            nodes.Clear();
            values.Clear();
            coefficients.Clear();
            transformed.Clear();
            dividedDifferences.Clear();
        }
    }


    /// <summary>
    /// Asserts that <see cref="Lch14AdditiveFft.BidirectionalTransform"/> round-trips against
    /// <see cref="Lch14AdditiveFft.ForwardTransform"/>: for every split point <c>k</c>, it recovers
    /// the missing coefficients or evaluations from the ones supplied, over both subfields.
    /// </summary>
    /// <param name="subfield">The GF(2)-subfield instantiation this gate runs over.</param>
    [TestMethod]
    [DataRow(Production16)]
    [DataRow(TestParity32)]
    public void TruncatedFourierRoundTripsAgainstTheForwardTransform(Lch14Subfield subfield)
    {
        using Lch14AdditiveFft fft = NewFastFft(subfield);
        const int l = BidirectionalDimension;
        int n = 1 << l;

        using IMemoryOwner<byte> coefficientOwner = BaseMemoryPool.Shared.Rent(n * ScalarSize);
        using IMemoryOwner<byte> evaluationOwner = BaseMemoryPool.Shared.Rent(n * ScalarSize);
        using IMemoryOwner<byte> blockOwner = BaseMemoryPool.Shared.Rent(n * ScalarSize);
        Span<byte> coefficients = coefficientOwner.Memory.Span[..(n * ScalarSize)];
        Span<byte> evaluations = evaluationOwner.Memory.Span[..(n * ScalarSize)];
        Span<byte> block = blockOwner.Memory.Span[..(n * ScalarSize)];

        for(int k = 0; k <= n; k++)
        {
            for(int i = 0; i < n; i++)
            {
                fft.NodeElement((uint)((((i * i) + 42) & 0xFFFF)), coefficients.Slice(i * ScalarSize, ScalarSize));
            }

            coefficients.CopyTo(evaluations);
            fft.ForwardTransform(l, coset: 0, evaluations);

            //Evaluations in the first k slots, coefficients in the rest.
            for(int i = 0; i < n; i++)
            {
                ReadOnlySpan<byte> source = i < k ? evaluations.Slice(i * ScalarSize, ScalarSize) : coefficients.Slice(i * ScalarSize, ScalarSize);
                source.CopyTo(block.Slice(i * ScalarSize, ScalarSize));
            }

            fft.BidirectionalTransform(l, k, block);

            //Now: coefficients in the first k slots, evaluations in the rest.
            for(int i = 0; i < n; i++)
            {
                ReadOnlySpan<byte> expected = i < k ? coefficients.Slice(i * ScalarSize, ScalarSize) : evaluations.Slice(i * ScalarSize, ScalarSize);
                Assert.IsTrue(
                    block.Slice(i * ScalarSize, ScalarSize).SequenceEqual(expected),
                    $"Bidirectional transform (k = {k}) slot [{i}] must flip the known/unknown halves.");
            }
        }

        coefficients.Clear();
        evaluations.Clear();
        block.Clear();
    }


    /// <summary>
    /// Asserts that <see cref="Lch14ReedSolomon.Interpolate"/> matches monomial evaluation for every
    /// <c>(n, m)</c> pair drawn from <see cref="ReedSolomonBlockLengths"/>, over both subfields.
    /// </summary>
    /// <param name="subfield">The GF(2)-subfield instantiation this gate runs over.</param>
    [TestMethod]
    [DataRow(Production16)]
    [DataRow(TestParity32)]
    public void SystematicInterpolateMatchesMonomialEvaluationOverTheReferenceSet(Lch14Subfield subfield)
    {
        using Lch14AdditiveFft fft = NewFastFft(subfield);
        foreach(int m in ReedSolomonBlockLengths)
        {
            for(int n = 1; n < m; n++)
            {
                RunReedSolomonCase(fft, n, m, FastAdd, FastMultiply);
            }
        }
    }


    /// <summary>
    /// Asserts that interpolating with <c>n == m</c> — including the degenerate <c>n == m == 1</c>
    /// singleton — leaves the codeword prefix unchanged, since there is nothing to extend.
    /// </summary>
    /// <param name="subfield">The GF(2)-subfield instantiation this gate runs over.</param>
    [TestMethod]
    [DataRow(Production16)]
    [DataRow(TestParity32)]
    public void InterpolateAtTheDegenerateSingletonReturnsTheLoneEvaluation(Lch14Subfield subfield)
    {
        using Lch14AdditiveFft fft = NewFastFft(subfield);

        //n == m == 1: a degree-0 polynomial; the single evaluation is the codeword.
        RunReedSolomonCase(fft, n: 1, m: 1, FastAdd, FastMultiply);

        //n == m for several lengths: nothing to extend, the prefix is the whole codeword.
        RunReedSolomonCase(fft, n: 8, m: 8, FastAdd, FastMultiply);
        RunReedSolomonCase(fft, n: 13, m: 13, FastAdd, FastMultiply);
    }


    /// <summary>
    /// Asserts that the fast backend and the slow reference backend produce byte-identical
    /// interpolated codewords for the same inputs, over both subfields.
    /// </summary>
    /// <param name="subfield">The GF(2)-subfield instantiation this gate runs over.</param>
    [TestMethod]
    [DataRow(Production16)]
    [DataRow(TestParity32)]
    public void TheTwoBackendsProduceByteIdenticalInterpolations(Lch14Subfield subfield)
    {
        using Lch14AdditiveFft fastFft = NewFastFft(subfield);
        using Lch14AdditiveFft referenceFft = NewReferenceFft(subfield);

        const int m = 99;
        const int n = 50;
        using IMemoryOwner<byte> fastOwner = BaseMemoryPool.Shared.Rent(m * ScalarSize);
        using IMemoryOwner<byte> referenceOwner = BaseMemoryPool.Shared.Rent(m * ScalarSize);
        Span<byte> fast = fastOwner.Memory.Span[..(m * ScalarSize)];
        Span<byte> reference = referenceOwner.Memory.Span[..(m * ScalarSize)];

        SeedInputs(fastFft, n, m, fast);
        fast[..(n * ScalarSize)].CopyTo(reference[..(n * ScalarSize)]);
        reference[(n * ScalarSize)..].Clear();

        InterpolateOnce(n, m, fastFft, fast);
        InterpolateOnce(n, m, referenceFft, reference);

        Assert.IsTrue(fast.SequenceEqual(reference), "The fast backend and the reference backend must produce byte-identical codewords.");

        fast.Clear();
        reference.Clear();
    }


    /// <summary>
    /// Asserts that <see cref="Lch14AdditiveFft.NormalizedWHat"/> agrees between the fast backend and
    /// the slow reference backend for every row and column, over both subfields.
    /// </summary>
    /// <param name="subfield">The GF(2)-subfield instantiation this gate runs over.</param>
    [TestMethod]
    [DataRow(Production16)]
    [DataRow(TestParity32)]
    public void NormalizedTableMatchesAcrossTheTwoBackends(Lch14Subfield subfield)
    {
        using Lch14AdditiveFft fastFft = NewFastFft(subfield);
        using Lch14AdditiveFft referenceFft = NewReferenceFft(subfield);
        int subFieldBits = fastFft.SubFieldBits;
        for(int i = 0; i < subFieldBits; i++)
        {
            for(int j = 0; j < subFieldBits; j++)
            {
                Assert.IsTrue(
                    fastFft.NormalizedWHat(i, j).SequenceEqual(referenceFft.NormalizedWHat(i, j)),
                    $"Ŵ_{i}(β_{j}) must agree across the two backends.");
            }
        }
    }


    /// <summary>
    /// Asserts that the test-parity subfield's generator, basis vectors, nodes and interpolated
    /// codewords all match the pinned anchor values.
    /// </summary>
    [TestMethod]
    public void TheBasisNodesAndCodewordsMatchTheReferenceImplementationForTheTestParitySubfield()
    {
        using Lch14AdditiveFft fft = NewFastFft(TestParity32);

        //The subfield generator g and the basis vectors β_j against BasisElement(j). β_1 == g.
        AssertReferenceElement(AnchorGenerator, fft.BasisElement(1), "g must equal the reference subfield generator.");
        AssertReferenceElement(AnchorBeta1, fft.BasisElement(1), "β_1 must equal the reference g.");
        AssertReferenceElement(AnchorBeta5, fft.BasisElement(5), "β_5 must match the reference.");
        AssertReferenceElement(AnchorBeta31, fft.BasisElement(31), "β_31 must match the reference.");

        //The of_scalar nodes against NodeElement(index).
        Span<byte> node = stackalloc byte[ScalarSize];
        fft.NodeElement(11, node);
        AssertReferenceElement(AnchorNode11, node, "of_scalar(11) must match the reference.");
        fft.NodeElement(200, node);
        AssertReferenceElement(AnchorNode200, node, "of_scalar(200) must match the reference.");

        //The full straddling-coset codeword (n = 9, m = 23): every element pinned.
        AssertReferenceCodeword(fft, AnchorStraddleDimension, AnchorStraddleBlockLength, AnchorStraddleCodeword);

        //The full-coset codeword (n = 9, m = 64): spot anchors at coset boundaries.
        AssertReferenceCodeword(fft, AnchorFullCosetDimension, AnchorFullCosetBlockLength, AnchorFullCosetSpotChecks);
    }


    /// <summary>
    /// Asserts that the production subfield's generator, basis vectors, nodes and interpolated
    /// codewords all match the pinned anchor values.
    /// </summary>
    [TestMethod]
    public void TheBasisNodesAndCodewordsMatchTheReferenceImplementationForTheProductionSubfield()
    {
        using Lch14AdditiveFft fft = NewFastFft(Production16);

        //The subfield generator g and the basis vectors β_j against BasisElement(j). β_1 == g. The
        //GF(2^16) subfield has 16 basis vectors, so the top index pinned is β_15.
        AssertReferenceElement(ProductionAnchorGenerator, fft.BasisElement(1), "g must equal the reference subfield generator.");
        AssertReferenceElement(ProductionAnchorBeta1, fft.BasisElement(1), "β_1 must equal the reference g.");
        AssertReferenceElement(ProductionAnchorBeta5, fft.BasisElement(5), "β_5 must match the reference.");
        AssertReferenceElement(ProductionAnchorBeta15, fft.BasisElement(15), "β_15 must match the reference.");

        //The of_scalar nodes against NodeElement(index).
        Span<byte> node = stackalloc byte[ScalarSize];
        fft.NodeElement(11, node);
        AssertReferenceElement(ProductionAnchorNode11, node, "of_scalar(11) must match the reference.");
        fft.NodeElement(200, node);
        AssertReferenceElement(ProductionAnchorNode200, node, "of_scalar(200) must match the reference.");

        //The full straddling-coset codeword (n = 9, m = 23): every element pinned.
        AssertReferenceCodeword(fft, AnchorStraddleDimension, AnchorStraddleBlockLength, ProductionAnchorStraddleCodeword);

        //The full-coset codeword (n = 9, m = 64): spot anchors at coset boundaries.
        AssertReferenceCodeword(fft, AnchorFullCosetDimension, AnchorFullCosetBlockLength, ProductionAnchorFullCosetSpotChecks);
    }


    /// <summary>
    /// Asserts that flipping one bit of an extended evaluation makes the systematic codeword no
    /// longer match the monomial polynomial at that node, over both subfields.
    /// </summary>
    /// <param name="subfield">The GF(2)-subfield instantiation this gate runs over.</param>
    [TestMethod]
    [DataRow(Production16)]
    [DataRow(TestParity32)]
    public void ACorruptedEvaluationBreaksTheRoundTrip(Lch14Subfield subfield)
    {
        using Lch14AdditiveFft fft = NewFastFft(subfield);
        const int m = 64;
        const int n = 33;

        using IMemoryOwner<byte> codewordOwner = BaseMemoryPool.Shared.Rent(m * ScalarSize);
        using IMemoryOwner<byte> monomialOwner = BaseMemoryPool.Shared.Rent(n * ScalarSize);
        Span<byte> codeword = codewordOwner.Memory.Span[..(m * ScalarSize)];
        Span<byte> monomial = monomialOwner.Memory.Span[..(n * ScalarSize)];

        SeedMonomial(fft, n, m, monomial);
        for(int i = 0; i < n; i++)
        {
            EvaluateMonomial(fft, monomial, n, (uint)i, codeword.Slice(i * ScalarSize, ScalarSize), FastAdd, FastMultiply);
        }

        InterpolateOnce(n, m, fft, codeword);

        //Flip one bit of one extended evaluation; it can no longer match the monomial evaluation
        //at that node — the systematic codeword no longer lies on the degree-<n polynomial.
        codeword[(m * ScalarSize) - 1] ^= 0x01;
        Span<byte> expected = stackalloc byte[ScalarSize];
        EvaluateMonomial(fft, monomial, n, (uint)(m - 1), expected, FastAdd, FastMultiply);
        Assert.IsFalse(
            codeword.Slice((m - 1) * ScalarSize, ScalarSize).SequenceEqual(expected),
            "A corrupted extended evaluation must no longer match the monomial polynomial.");

        codeword.Clear();
        monomial.Clear();
    }


    /// <summary>
    /// Asserts that constructing an <see cref="Lch14ReedSolomon"/> with a block length below its
    /// dimension throws <see cref="ArgumentOutOfRangeException"/>, over both subfields.
    /// </summary>
    /// <param name="subfield">The GF(2)-subfield instantiation this gate runs over.</param>
    [TestMethod]
    [DataRow(Production16)]
    [DataRow(TestParity32)]
    public void ConstructingWithBlockLengthBelowDimensionIsRejected(Lch14Subfield subfield)
    {
        using Lch14AdditiveFft fft = NewFastFft(subfield);
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => _ = new Lch14ReedSolomon(dimension: 8, blockLength: 4, fft, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// Asserts that <see cref="Lch14AdditiveFft.ForwardTransform"/> rejects a dimension one past the
    /// subfield's basis width, over both subfields.
    /// </summary>
    /// <param name="subfield">The GF(2)-subfield instantiation this gate runs over.</param>
    [TestMethod]
    [DataRow(Production16)]
    [DataRow(TestParity32)]
    public void TransformRejectsADimensionPastTheSubfield(Lch14Subfield subfield)
    {
        using Lch14AdditiveFft fft = NewFastFft(subfield);

        //The covering FFT dimension must stay within the subfield basis (l ≤ SubFieldBits): a
        //GF(2^16) transform caps at l ≤ 16, a GF(2^32) one at l ≤ 32. The transform guards it
        //directly; a dimension of SubFieldBits + 1 is rejected.
        byte[] oversized = new byte[ScalarSize];
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => fft.ForwardTransform(fft.SubFieldBits + 1, coset: 0, oversized));
    }


    /// <summary>
    /// Asserts that <see cref="Lch14ReedSolomon.Interpolate"/> rejects a buffer sized for fewer
    /// elements than the block length, over both subfields.
    /// </summary>
    /// <param name="subfield">The GF(2)-subfield instantiation this gate runs over.</param>
    [TestMethod]
    [DataRow(Production16)]
    [DataRow(TestParity32)]
    public void InterpolateRejectsAMisSizedBuffer(Lch14Subfield subfield)
    {
        using Lch14AdditiveFft fft = NewFastFft(subfield);
        var rs = new Lch14ReedSolomon(dimension: 4, blockLength: 16, fft, BaseMemoryPool.Shared);

        //A buffer sized for 8 elements when the block length is 16: Interpolate takes a Span, so
        //the wrong-length argument is a plain array that converts to the span at the call.
        byte[] wrongLength = new byte[8 * ScalarSize];
        Assert.ThrowsExactly<ArgumentException>(() => rs.Interpolate(wrongLength));
    }


    /// <summary>
    /// Runs one Reed–Solomon case: builds a monomial polynomial of degree less than
    /// <paramref name="n"/>, evaluates it at the first <paramref name="n"/> nodes, interpolates to
    /// <paramref name="m"/> outputs, and asserts every output equals the monomial evaluation at that
    /// node.
    /// </summary>
    /// <param name="fft">The additive FFT to transform and interpolate under.</param>
    /// <param name="n">The number of known input evaluations.</param>
    /// <param name="m">The block length to interpolate to.</param>
    /// <param name="add">The scalar addition delegate the monomial evaluation uses.</param>
    /// <param name="multiply">The scalar multiplication delegate the monomial evaluation uses.</param>
    private static void RunReedSolomonCase(Lch14AdditiveFft fft, int n, int m, ScalarAddDelegate add, ScalarMultiplyDelegate multiply)
    {
        using IMemoryOwner<byte> monomialOwner = BaseMemoryPool.Shared.Rent(n * ScalarSize);
        using IMemoryOwner<byte> codewordOwner = BaseMemoryPool.Shared.Rent(m * ScalarSize);
        Span<byte> monomial = monomialOwner.Memory.Span[..(n * ScalarSize)];
        Span<byte> codeword = codewordOwner.Memory.Span[..(m * ScalarSize)];

        SeedMonomial(fft, n, m, monomial);
        for(int i = 0; i < n; i++)
        {
            EvaluateMonomial(fft, monomial, n, (uint)i, codeword.Slice(i * ScalarSize, ScalarSize), add, multiply);
        }

        InterpolateOnce(n, m, fft, codeword);

        Span<byte> expected = stackalloc byte[ScalarSize];
        for(int i = 0; i < m; i++)
        {
            EvaluateMonomial(fft, monomial, n, (uint)i, expected, add, multiply);
            Assert.IsTrue(
                codeword.Slice(i * ScalarSize, ScalarSize).SequenceEqual(expected),
                $"ReedSolomon (n = {n}, m = {m}) output [{i}] must equal the monomial evaluation.");
        }

        monomial.Clear();
        codeword.Clear();
    }


    /// <summary>
    /// Extends one codeword in place. <see cref="Lch14ReedSolomon"/> holds no state of its own — its
    /// precompute lives in the shared additive-FFT engine — so a one-shot construct-and-interpolate is
    /// the natural shape for these byte-comparison gates, unlike a commitment scheme, which reuses one
    /// encoder across every tableau row.
    /// </summary>
    /// <param name="dimension">The number of known input evaluations.</param>
    /// <param name="blockLength">The block length to interpolate to.</param>
    /// <param name="fft">The additive FFT to interpolate under.</param>
    /// <param name="codeword">The buffer holding the known evaluations, extended in place.</param>
    private static void InterpolateOnce(int dimension, int blockLength, Lch14AdditiveFft fft, Span<byte> codeword) =>
        new Lch14ReedSolomon(dimension, blockLength, fft, BaseMemoryPool.Shared).Interpolate(codeword);


    /// <summary>
    /// Seeds the <paramref name="n"/> known input evaluations as a monomial polynomial's values at
    /// the first <paramref name="n"/> nodes, following google/longfellow-zk's own seeding convention:
    /// writes those inputs directly into <paramref name="y"/>'s prefix and zeroes the rest.
    /// </summary>
    /// <param name="fft">The additive FFT whose nodes the monomial is evaluated at.</param>
    /// <param name="n">The number of known input evaluations.</param>
    /// <param name="m">The block length <paramref name="y"/> is sized for.</param>
    /// <param name="y">The buffer to seed: filled with the first <paramref name="n"/> evaluations,
    /// then zeroed for the rest.</param>
    private static void SeedInputs(Lch14AdditiveFft fft, int n, int m, Span<byte> y)
    {
        using IMemoryOwner<byte> monomialOwner = BaseMemoryPool.Shared.Rent(n * ScalarSize);
        Span<byte> monomial = monomialOwner.Memory.Span[..(n * ScalarSize)];
        SeedMonomial(fft, n, m, monomial);
        for(int i = 0; i < n; i++)
        {
            EvaluateMonomial(fft, monomial, n, (uint)i, y.Slice(i * ScalarSize, ScalarSize), FastAdd, FastMultiply);
        }

        y[(n * ScalarSize)..].Clear();
        monomial.Clear();
    }


    /// <summary>
    /// Writes google/longfellow-zk's deterministic monomial coefficients
    /// <c>M[i] = of_scalar(i² + 42 + (m+11)(n+22))</c>. The coordinate value stays well below 2^32 for
    /// every <paramref name="n"/>/<paramref name="m"/> pair this file uses, so it maps directly
    /// through <c>of_scalar</c> with no masking, matching the upstream formula.
    /// </summary>
    /// <param name="fft">The additive FFT supplying <c>of_scalar</c> node evaluation.</param>
    /// <param name="n">The number of monomial coefficients to write.</param>
    /// <param name="m">The block length the coefficients are parameterized by.</param>
    /// <param name="monomial">The buffer to receive the <paramref name="n"/> coefficients.</param>
    private static void SeedMonomial(Lch14AdditiveFft fft, int n, int m, Span<byte> monomial)
    {
        for(int i = 0; i < n; i++)
        {
            long index = ((long)i * i) + 42 + ((long)(m + 11) * (n + 22));
            fft.NodeElement((uint)index, monomial.Slice(i * ScalarSize, ScalarSize));
        }
    }


    /// <summary>
    /// Evaluates the monomial polynomial <c>M</c> at node <c>of_scalar(nodeIndex)</c> by Horner's
    /// method.
    /// </summary>
    /// <param name="fft">The additive FFT supplying <c>of_scalar</c> node evaluation.</param>
    /// <param name="monomial">The polynomial's coefficients, indexed so that <c>monomial[i]</c> is
    /// the coefficient of <c>x^i</c>.</param>
    /// <param name="degreeCount">The number of coefficients in <paramref name="monomial"/>.</param>
    /// <param name="nodeIndex">The node index to evaluate at.</param>
    /// <param name="result">Receives the evaluation.</param>
    /// <param name="add">The scalar addition delegate.</param>
    /// <param name="multiply">The scalar multiplication delegate.</param>
    private static void EvaluateMonomial(Lch14AdditiveFft fft, ReadOnlySpan<byte> monomial, int degreeCount, uint nodeIndex, Span<byte> result, ScalarAddDelegate add, ScalarMultiplyDelegate multiply)
    {
        Span<byte> x = stackalloc byte[ScalarSize];
        fft.NodeElement(nodeIndex, x);

        Span<byte> accumulator = stackalloc byte[ScalarSize];
        Span<byte> scratch = stackalloc byte[ScalarSize];
        accumulator.Clear();
        for(int i = degreeCount - 1; i >= 0; i--)
        {
            multiply(accumulator, x, scratch, CurveParameterSet.None);
            add(monomial.Slice(i * ScalarSize, ScalarSize), scratch, accumulator, CurveParameterSet.None);
        }

        accumulator.CopyTo(result);
    }


    /// <summary>
    /// The slow, direct definition of <c>Ŵ_i</c>: <c>W_i(x) = Π_{j&lt;2^i} (x − of_scalar(j))</c>,
    /// divided by <c>W_i(β_i)</c>. The independent oracle the normalized, precomputed <c>Ŵ</c> table
    /// is checked against.
    /// </summary>
    /// <param name="fft">The additive FFT supplying nodes and basis elements.</param>
    /// <param name="i">The row index.</param>
    /// <param name="x">The point to evaluate <c>Ŵ_i</c> at.</param>
    /// <param name="result">Receives the evaluation.</param>
    /// <param name="multiply">The scalar multiplication delegate.</param>
    /// <param name="invert">The scalar inversion delegate.</param>
    private static void WHatRef(Lch14AdditiveFft fft, int i, ReadOnlySpan<byte> x, Span<byte> result, ScalarMultiplyDelegate multiply, ScalarInvertDelegate invert)
    {
        Span<byte> wAtX = stackalloc byte[ScalarSize];
        WRef(fft, i, x, wAtX, multiply);

        Span<byte> wAtBeta = stackalloc byte[ScalarSize];
        WRef(fft, i, fft.BasisElement(i), wAtBeta, multiply);

        Span<byte> inverse = stackalloc byte[ScalarSize];
        invert(wAtBeta, inverse, CurveParameterSet.None);
        multiply(wAtX, inverse, result, CurveParameterSet.None);
    }


    /// <summary>
    /// <c>W_i(x) = Π_{j &lt; 2^i} (x − of_scalar(j))</c>. Subtraction is XOR in characteristic two.
    /// </summary>
    /// <param name="fft">The additive FFT supplying nodes.</param>
    /// <param name="i">The row index.</param>
    /// <param name="x">The point to evaluate <c>W_i</c> at.</param>
    /// <param name="result">Receives the evaluation.</param>
    /// <param name="multiply">The scalar multiplication delegate.</param>
    private static void WRef(Lch14AdditiveFft fft, int i, ReadOnlySpan<byte> x, Span<byte> result, ScalarMultiplyDelegate multiply)
    {
        Span<byte> product = stackalloc byte[ScalarSize];
        product.Clear();
        product[ScalarSize - 1] = 1;

        Span<byte> node = stackalloc byte[ScalarSize];
        Span<byte> factor = stackalloc byte[ScalarSize];
        Span<byte> scratch = stackalloc byte[ScalarSize];
        int count = 1 << i;
        for(int j = 0; j < count; j++)
        {
            fft.NodeElement((uint)j, node);
            for(int b = 0; b < ScalarSize; b++)
            {
                factor[b] = (byte)(x[b] ^ node[b]);
            }

            multiply(product, factor, scratch, CurveParameterSet.None);
            scratch.CopyTo(product);
        }

        product.CopyTo(result);
    }


    /// <summary>
    /// Builds the Newton divided-difference table over <paramref name="nodes"/> and
    /// <paramref name="values"/>, in place into <paramref name="dividedDifferences"/>. The table
    /// depends only on <paramref name="values"/> and <paramref name="nodes"/>, so
    /// <see cref="CrossCosetInterpolationMatchesTheNewtonOracle"/> builds it once per coset and
    /// Horner-evaluates many points against it, keeping the O(n²) Fermat inversions out of the
    /// per-point loop.
    /// </summary>
    /// <param name="values">The known evaluations at <paramref name="nodes"/>.</param>
    /// <param name="nodes">The nodes the evaluations were taken at.</param>
    /// <param name="count">The number of nodes and values.</param>
    /// <param name="dividedDifferences">Receives the divided-difference table.</param>
    /// <param name="subtract">The scalar subtraction delegate.</param>
    /// <param name="multiply">The scalar multiplication delegate.</param>
    /// <param name="invert">The scalar inversion delegate.</param>
    private static void BuildDividedDifferences(
        ReadOnlySpan<byte> values,
        ReadOnlySpan<byte> nodes,
        int count,
        Span<byte> dividedDifferences,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert)
    {
        values.CopyTo(dividedDifferences);

        Span<byte> difference = stackalloc byte[ScalarSize];
        Span<byte> denominator = stackalloc byte[ScalarSize];
        Span<byte> inverse = stackalloc byte[ScalarSize];
        Span<byte> scratch = stackalloc byte[ScalarSize];
        for(int level = 1; level < count; level++)
        {
            for(int idx = count - 1; idx >= level; idx--)
            {
                subtract(dividedDifferences.Slice(idx * ScalarSize, ScalarSize), dividedDifferences.Slice((idx - 1) * ScalarSize, ScalarSize), difference, CurveParameterSet.None);
                subtract(nodes.Slice(idx * ScalarSize, ScalarSize), nodes.Slice((idx - level) * ScalarSize, ScalarSize), denominator, CurveParameterSet.None);
                invert(denominator, inverse, CurveParameterSet.None);
                multiply(difference, inverse, scratch, CurveParameterSet.None);
                scratch.CopyTo(dividedDifferences.Slice(idx * ScalarSize, ScalarSize));
            }
        }
    }


    /// <summary>
    /// Evaluates the Newton interpolant at <paramref name="x"/> from a precomputed
    /// divided-difference table: <c>acc = acc·(x − node[idx]) + divided[idx]</c>, descending from the
    /// last index. An independent route from the FFT to the same polynomial value, so a
    /// self-consistent but wrong transform is caught.
    /// </summary>
    /// <param name="dividedDifferences">The precomputed divided-difference table.</param>
    /// <param name="nodes">The nodes the table was built over.</param>
    /// <param name="count">The number of nodes and table entries.</param>
    /// <param name="x">The point to evaluate the interpolant at.</param>
    /// <param name="result">Receives the evaluation.</param>
    /// <param name="add">The scalar addition delegate.</param>
    /// <param name="subtract">The scalar subtraction delegate.</param>
    /// <param name="multiply">The scalar multiplication delegate.</param>
    private static void NewtonHorner(
        ReadOnlySpan<byte> dividedDifferences,
        ReadOnlySpan<byte> nodes,
        int count,
        ReadOnlySpan<byte> x,
        Span<byte> result,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply)
    {
        Span<byte> difference = stackalloc byte[ScalarSize];
        Span<byte> scratch = stackalloc byte[ScalarSize];
        Span<byte> accumulator = stackalloc byte[ScalarSize];
        accumulator.Clear();
        for(int idx = count - 1; idx >= 0; idx--)
        {
            subtract(x, nodes.Slice(idx * ScalarSize, ScalarSize), difference, CurveParameterSet.None);
            multiply(accumulator, difference, scratch, CurveParameterSet.None);
            add(scratch, dividedDifferences.Slice(idx * ScalarSize, ScalarSize), accumulator, CurveParameterSet.None);
        }

        accumulator.CopyTo(result);
    }


    /// <summary>
    /// Interpolates a Reed–Solomon codeword for <paramref name="n"/>/<paramref name="m"/> under the
    /// deterministic seeding <see cref="SeedMonomial"/> and <see cref="EvaluateMonomial"/> define,
    /// and asserts the requested elements equal <paramref name="anchors"/>.
    /// </summary>
    /// <param name="fft">The additive FFT to interpolate under.</param>
    /// <param name="n">The number of known input evaluations.</param>
    /// <param name="m">The block length to interpolate to.</param>
    /// <param name="anchors">The pinned elements to check the interpolated codeword against.</param>
    private static void AssertReferenceCodeword(Lch14AdditiveFft fft, int n, int m, ReferenceCodewordElement[] anchors)
    {
        using IMemoryOwner<byte> monomialOwner = BaseMemoryPool.Shared.Rent(n * ScalarSize);
        using IMemoryOwner<byte> codewordOwner = BaseMemoryPool.Shared.Rent(m * ScalarSize);
        Span<byte> monomial = monomialOwner.Memory.Span[..(n * ScalarSize)];
        Span<byte> codeword = codewordOwner.Memory.Span[..(m * ScalarSize)];

        SeedMonomial(fft, n, m, monomial);
        for(int i = 0; i < n; i++)
        {
            EvaluateMonomial(fft, monomial, n, (uint)i, codeword.Slice(i * ScalarSize, ScalarSize), FastAdd, FastMultiply);
        }

        InterpolateOnce(n, m, fft, codeword);

        foreach(ReferenceCodewordElement anchor in anchors)
        {
            AssertReferenceElement(
                anchor.ReferenceHex,
                codeword.Slice(anchor.Index * ScalarSize, ScalarSize),
                $"Codeword (n = {n}, m = {m}) element [{anchor.Index}] must match the reference.");
        }

        monomial.Clear();
        codeword.Clear();
    }


    /// <summary>
    /// Asserts that a canonical 32-byte element equals the expected value encoded as 32 hex
    /// characters.
    /// </summary>
    /// <param name="referenceHex">The expected value, as 32 hex characters (16 little-endian
    /// bytes).</param>
    /// <param name="actual">The canonical 32-byte element to check.</param>
    /// <param name="message">The assertion failure message.</param>
    private static void AssertReferenceElement(string referenceHex, ReadOnlySpan<byte> actual, string message)
    {
        Span<byte> expected = stackalloc byte[ScalarSize];
        ReferenceElementToCanonical(referenceHex, expected);
        Assert.IsTrue(actual.SequenceEqual(expected), message);
    }


    /// <summary>
    /// Converts a hex-encoded field element in google/longfellow-zk's <c>to_bytes_field</c> format —
    /// the 128-bit element as 16 little-endian bytes, printed as 32 hex characters — into this
    /// project's canonical 32-byte big-endian scalar: the 16 bytes reversed into positions 16..31,
    /// with the leading 16 bytes left zero.
    /// </summary>
    /// <param name="referenceHex">The hex-encoded field element to convert.</param>
    /// <param name="destination">Receives the canonical 32-byte scalar.</param>
    private static void ReferenceElementToCanonical(string referenceHex, Span<byte> destination)
    {
        destination.Clear();
        ReadOnlySpan<byte> littleEndian = Convert.FromHexString(referenceHex);
        for(int i = 0; i < ElementBytes; i++)
        {
            destination[ScalarSize - 1 - i] = littleEndian[i];
        }
    }


    /// <summary>
    /// Constructs an <see cref="Lch14AdditiveFft"/> over <paramref name="subfield"/> using the fast
    /// production backend's scalar delegates.
    /// </summary>
    /// <param name="subfield">The subfield to construct the transform over.</param>
    /// <returns>The constructed transform.</returns>
    private static Lch14AdditiveFft NewFastFft(Lch14Subfield subfield) =>
        new(subfield, FastAdd, FastSubtract, FastMultiply, FastInvert, CurveParameterSet.None, BaseMemoryPool.Shared);


    /// <summary>
    /// Constructs an <see cref="Lch14AdditiveFft"/> over <paramref name="subfield"/> using the slow,
    /// independently defined reference backend's scalar delegates.
    /// </summary>
    /// <param name="subfield">The subfield to construct the transform over.</param>
    /// <returns>The constructed transform.</returns>
    private static Lch14AdditiveFft NewReferenceFft(Lch14Subfield subfield) =>
        new(subfield, ReferenceAdd, ReferenceSubtract, ReferenceMultiply, ReferenceInvert, CurveParameterSet.None, BaseMemoryPool.Shared);


    /// <summary>
    /// One pinned codeword element.
    /// </summary>
    /// <param name="Index">The element's index within the codeword.</param>
    /// <param name="ReferenceHex">The element's expected value, as 32 hex characters.</param>
    private readonly record struct ReferenceCodewordElement(int Index, string ReferenceHex);


    /// <summary>
    /// The test-parity subfield's generator <c>g</c>, from google/longfellow-zk's
    /// <c>GF2_128&lt;5&gt;</c> instantiation, as 16 little-endian bytes in hex. Equal to
    /// <see cref="AnchorBeta1"/>, since the generator is basis vector <c>β_1</c>.
    /// </summary>
    private const string AnchorGenerator = "5ed02f3c88a430056b1f25adfc41e392";

    /// <summary>
    /// The test-parity subfield's basis vector <c>β_1</c>, from google/longfellow-zk's
    /// <c>GF2_128&lt;5&gt;</c> instantiation, as 16 little-endian bytes in hex.
    /// </summary>
    private const string AnchorBeta1 = "5ed02f3c88a430056b1f25adfc41e392";

    /// <summary>
    /// The test-parity subfield's basis vector <c>β_5</c>, from google/longfellow-zk's
    /// <c>GF2_128&lt;5&gt;</c> instantiation, as 16 little-endian bytes in hex.
    /// </summary>
    private const string AnchorBeta5 = "8b7d79d022e97273fbbf761f1911818f";

    /// <summary>
    /// The test-parity subfield's basis vector <c>β_31</c>, from google/longfellow-zk's
    /// <c>GF2_128&lt;5&gt;</c> instantiation, as 16 little-endian bytes in hex.
    /// </summary>
    private const string AnchorBeta31 = "72008237d5c1ec925810af7d64d216de";

    /// <summary>
    /// <c>of_scalar(11)</c> in the test-parity subfield, from google/longfellow-zk's
    /// <c>GF2_128&lt;5&gt;</c> instantiation, as 16 little-endian bytes in hex.
    /// </summary>
    private const string AnchorNode11 = "2b24fbf40390c1d95ef29104e2905d69";

    /// <summary>
    /// <c>of_scalar(200)</c> in the test-parity subfield, from google/longfellow-zk's
    /// <c>GF2_128&lt;5&gt;</c> instantiation, as 16 little-endian bytes in hex.
    /// </summary>
    private const string AnchorNode200 = "8ed6ffe88eca96b953b9ac3dd493272c";


    /// <summary>
    /// The production subfield's generator <c>g</c>, from google/longfellow-zk's default
    /// <c>GF2_128&lt;&gt;</c> instantiation (the wire-format-conformant one), as 16 little-endian
    /// bytes in hex. Equal to <see cref="ProductionAnchorBeta1"/>, since the generator is basis
    /// vector <c>β_1</c>.
    /// </summary>
    private const string ProductionAnchorGenerator = "4cda4fb6011e87f1b8d401758771595c";

    /// <summary>
    /// The production subfield's basis vector <c>β_1</c>, from google/longfellow-zk's default
    /// <c>GF2_128&lt;&gt;</c> instantiation, as 16 little-endian bytes in hex.
    /// </summary>
    private const string ProductionAnchorBeta1 = "4cda4fb6011e87f1b8d401758771595c";

    /// <summary>
    /// The production subfield's basis vector <c>β_5</c>, from google/longfellow-zk's default
    /// <c>GF2_128&lt;&gt;</c> instantiation, as 16 little-endian bytes in hex.
    /// </summary>
    private const string ProductionAnchorBeta5 = "9e689f62934eaff7ed9c26a5f44f9454";

    /// <summary>
    /// The production subfield's top basis vector <c>β_15</c> (the field has 16 basis vectors), from
    /// google/longfellow-zk's default <c>GF2_128&lt;&gt;</c> instantiation, as 16 little-endian bytes
    /// in hex.
    /// </summary>
    private const string ProductionAnchorBeta15 = "5357e550230183b6e85a3c83b6bbd418";

    /// <summary>
    /// <c>of_scalar(11)</c> in the production subfield, from google/longfellow-zk's default
    /// <c>GF2_128&lt;&gt;</c> instantiation, as 16 little-endian bytes in hex.
    /// </summary>
    private const string ProductionAnchorNode11 = "a0a4b04fa3f60acee4b2f8675d7947ea";

    /// <summary>
    /// <c>of_scalar(200)</c> in the production subfield, from google/longfellow-zk's default
    /// <c>GF2_128&lt;&gt;</c> instantiation, as 16 little-endian bytes in hex.
    /// </summary>
    private const string ProductionAnchorNode200 = "c7bd54b7464e9d0a864d2761993bcbab";


    /// <summary>
    /// The full interpolated codeword for <c>(n = 9, m = 23)</c> over the test-parity subfield: every
    /// element pinned. With <c>fftn = 16</c>, <c>m = 23</c> exercises the straddling-coset partial
    /// copy.
    /// </summary>
    private static ReferenceCodewordElement[] AnchorStraddleCodeword { get; } =
    [
        new(0, "bb3fa07dcec2f48cbca3e5481921995c"),
        new(1, "294593ef50a3e35cbc49f13d94707429"),
        new(2, "2648489a47a67f0043ad370153cf8f7c"),
        new(3, "d3af114fed238aba03feb95af68cb68f"),
        new(4, "95bd98178bb726c0bd58bc87887d3f9e"),
        new(5, "932aa90b0a1176ec89d11478105ca345"),
        new(6, "5d74362022af7512383cec9b2a493a3c"),
        new(7, "fc94f6b29b8434f999516470962184c2"),
        new(8, "47ef323da690baa1091e6e1f5e9c9268"),
        new(9, "e90870ba4adaab27f11c523368d68d4c"),
        new(10, "583ca9a810fbbedc411b15c88b1b14ea"),
        new(11, "46c62b78d71587618b04c9ffaf038400"),
        new(12, "9b43a0f8c36360fc0d8eea1db7989eb6"),
        new(13, "0ad1c7b7e721e55f99a6c07559fed8aa"),
        new(14, "0019e587cad7e437e9c2066d432d482d"),
        new(15, "e17cd956c958ba029aaa7624b342775c"),
        new(16, "f283d071ebaedc232813a29ec83d6c97"),
        new(17, "826fbce4d1e6c4579bedd922b92cd2ca"),
        new(18, "736e3e0578408eae2e9e71ccdcb5fb1d"),
        new(19, "2a1beec31b6b032cfa3234798b608183"),
        new(20, "19302bf9ca48580f4e632ffcae6fbc5c"),
        new(21, "6cb457cd1b3048d28ec600a596f04a39"),
        new(22, "1842297fcd53dea13b7a5f63286b6b64"),
    ];


    /// <summary>
    /// Spot anchors of the <c>(n = 9, m = 64)</c> test-parity codeword at coset boundaries
    /// (<c>fftn = 16</c>, no straddle): the first element, the last element of the first coset and
    /// the first of the second (15, 16), the second/third coset boundary (31, 32), and the final
    /// element (63).
    /// </summary>
    private static ReferenceCodewordElement[] AnchorFullCosetSpotChecks { get; } =
    [
        new(0, "aa8b3ab4602065abc82565d742b47abe"),
        new(9, "819e0b7703a5b64fdd72699a9340ed87"),
        new(15, "32fc73899b408870188f7845277e529f"),
        new(16, "9d332535cb88107b49677e1fe3cd4440"),
        new(31, "8c859fe1cac48d4a624808f6ce498764"),
        new(32, "aec6303401e224cb0deff4682bf54829"),
        new(63, "7b9a02d9782989b36bedd24c73aa2593"),
    ];


    /// <summary>
    /// The full interpolated codeword for <c>(n = 9, m = 23)</c> over the <c>GF(2^16)</c> production
    /// subfield: every element pinned. With <c>fftn = 16</c>, <c>m = 23</c> straddles a coset.
    /// </summary>
    private static ReferenceCodewordElement[] ProductionAnchorStraddleCodeword { get; } =
    [
        new(0, "3e2514f0a2e00a2fd254042c0aef6348"),
        new(1, "ad76835bf52016764b6098b6debd4ea6"),
        new(2, "fe3d354a2c1fb6d91072534dbe47aef7"),
        new(3, "c7bb390c67534fa065205f1601920da7"),
        new(4, "ba5edcf1ef8b7509b510be696355b841"),
        new(5, "6f90168e9764e8247e7b3990dd44c6e6"),
        new(6, "dfe750bbbeec65e259ec0069d5f83139"),
        new(7, "8b780d9686ba67774eaf246893ea88ab"),
        new(8, "caf6c340aeab159c4eaed1fff3c7e065"),
        new(9, "3051f929ec278bf6761322f52de1a4db"),
        new(10, "8ee2d97165fa8720009bdb56bd076f08"),
        new(11, "0502710b58c0cc879d74ba2a864f0882"),
        new(12, "4b3ff1fe5592a6f441c63713a366c871"),
        new(13, "7a1920993ca3b48aba79ad1253d9f89b"),
        new(14, "a54ffa99696e695fa2bc98a378efff9e"),
        new(15, "ceaab55223dcd474cc1fa3edfebaa5cb"),
        new(16, "54c181f06032c71e6e7db34083acf954"),
        new(17, "add8c4b352381b291c84f06be35f6f2c"),
        new(18, "636ff86b03ba9c5eb15928dcc4b23ee7"),
        new(19, "b7bc605a84d89a947d0b8b06ed78b9aa"),
        new(20, "4377160de0045a1ba020a8fc0e4f269e"),
        new(21, "bf7483a2e25995970e7ca7d4f2eca47d"),
        new(22, "73a219894d9dde24b63b38655d4d592d"),
    ];


    /// <summary>
    /// Spot anchors of the <c>(n = 9, m = 64)</c> production codeword at coset boundaries
    /// (<c>fftn = 16</c>, no straddle): the same indices as the test-parity spot checks.
    /// </summary>
    private static ReferenceCodewordElement[] ProductionAnchorFullCosetSpotChecks { get; } =
    [
        new(0, "9861e95ec280653f891c1827fe45507c"),
        new(9, "5926cef29c7b6c58e08e542580451d4c"),
        new(15, "343e45526701e7ae5015f05d7694c7c7"),
        new(16, "0baa00dda3139d52a5939ed0cc399f59"),
        new(31, "8271202faaa2239fa6412eba76dd3cde"),
        new(32, "0045e32886f48cc69d6acb15cacc7f20"),
        new(63, "5860680c215bbe0bbe9a6a3411684c79"),
    ];
}
