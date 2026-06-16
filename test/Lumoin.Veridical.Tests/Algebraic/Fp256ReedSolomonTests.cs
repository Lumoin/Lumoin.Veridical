using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Numerics;
using System.Threading.Tasks;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The Fp256 Reed–Solomon engine (conformance step C.12, the foundational P-256 primitive), gated as a
/// faithful port of google/longfellow-zk's <c>ReedSolomon&lt;Fp256Base, FFTExtConvolutionFactory&gt;</c>
/// (<c>lib/algebra/reed_solomon.h</c> over <c>lib/algebra/convolution.h</c> and <c>lib/algebra/rfft.h</c>) —
/// the point-evaluation interpolator the reference instantiates for the P-256 signature circuit's Ligero
/// (the <c>RSFactory_b</c> in <c>lib/circuits/mdoc/mdoc_zk.cc</c>). It extends the values of a degree-(&lt;n)
/// polynomial at points <c>0, …, n−1</c> to the values at <c>n, …, m−1</c> in place, via the real-FFT
/// convolution over the Fp2 extension with the reference's Fp2 root of unity.
/// </summary>
/// <remarks>
/// <para>
/// The anchor (fp256-rs-anchor-output.txt in TestMaterial/Longfellow) is computed by the reference
/// implementation in its own Docker build environment via development tooling outside this repository. It
/// dumps the root of unity, a few field anchors, and several full interpolated codewords: for each
/// <c>cwNxM</c> a degree-(&lt;N) polynomial with the coefficients <c>of_scalar(i·i + 42 + (M+11)·(N+22))</c>
/// is evaluated at <c>0, …, N−1</c> and extended in place to all <c>M</c> points, each printed as 32
/// little-endian to_bytes_field bytes.
/// </para>
/// <para>
/// The gates:
/// </para>
/// <list type="bullet">
///   <item><description><b>Byte identity</b>: our interpolator's full codeword equals the reference's, element for element, for each <c>cwNxM</c> — over the small dimensions, the 9×23 / 9×64 shapes (matching the binary C.1 anchor shapes), and a larger 17×68.</description></item>
///   <item><description><b>Systematic</b>: the first <c>N</c> outputs are the unchanged inputs (the encoder is systematic).</description></item>
///   <item><description><b>Field anchors</b>: the parsed root of unity and of_scalar samples match.</description></item>
/// </list>
/// </remarks>
[TestClass]
internal sealed class Fp256ReedSolomonTests
{
    private const string AnchorRelativePath = "TestMaterial/Longfellow/fp256-rs-anchor-output.txt";
    private const int ScalarSize = Scalar.SizeBytes;

    //mdoc_zk.cc's omega_order for the Fp256 RS convolution: 2^31.
    private const ulong OmegaOrder = 1UL << 31;

    private static readonly BigInteger FieldOrder = P256BaseFieldReference.FieldOrder;

    private static ScalarAddDelegate Add { get; } = P256BaseFieldMontgomeryBackend.GetAdd();

    private static ScalarSubtractDelegate Subtract { get; } = P256BaseFieldMontgomeryBackend.GetSubtract();

    private static ScalarMultiplyDelegate Multiply { get; } = P256BaseFieldMontgomeryBackend.GetMultiply();

    private static ScalarInvertDelegate Invert { get; } = P256BaseFieldMontgomeryBackend.GetInvert();

    private static Dictionary<string, string> Anchors { get; } = LoadAnchors();

    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public void TheParsedRootOfUnityMatchesTheReference()
    {
        //The root of unity is parsed by the reference from kRootX/kRootY; the dump prints its two
        //coordinates in to_bytes_field order. We only confirm the anchor carries them (the engine
        //consumes them as opaque field bytes); the codeword gates exercise the value end to end.
        Assert.IsTrue(Anchors.ContainsKey("rootx"), "The anchor must carry the root-of-unity real part.");
        Assert.IsTrue(Anchors.ContainsKey("rooty"), "The anchor must carry the root-of-unity imaginary part.");

        byte[] one = ParseElement(Anchors["one"]);
        byte[] expectedOne = OfScalar(1);
        Assert.IsTrue(one.AsSpan().SequenceEqual(expectedOne), "of one must be the field one.");

        Assert.IsTrue(ParseElement(Anchors["of_scalar_7"]).AsSpan().SequenceEqual(OfScalar(7)), "of_scalar(7) must match.");
        Assert.IsTrue(ParseElement(Anchors["of_scalar_300"]).AsSpan().SequenceEqual(OfScalar(300)), "of_scalar(300) must match.");
    }


    [TestMethod]
    public void TheSmallCodewordMatchesTheReferenceByteForByte() => AssertCodeword("cw5x16", 5, 16);


    [TestMethod]
    public void TheNineByTwentyThreeCodewordMatchesTheReferenceByteForByte() => AssertCodeword("cw9x23", 9, 23);


    [TestMethod]
    public void TheNineBySixtyFourCodewordMatchesTheReferenceByteForByte() => AssertCodeword("cw9x64", 9, 64);


    [TestMethod]
    public void TheSeventeenBySixtyEightCodewordMatchesTheReferenceByteForByte() => AssertCodeword("cw17x68", 17, 68);


    [TestMethod]
    public void ForwardThenBackwardAtLengthTwoScalesByTwo()
    {
        //The R2HcI2/Hc2RI2 shortcut paths (length == 2) are not reached by any codeword shape; this
        //test exercises them directly. The transform is unnormalized: HC2R(R2HC(x)) == length * x
        //elementwise (the convolution pre-scales by 1/padding to cancel this). At length 2 the factor
        //is 2. The length-1 branch (length < 4, length != 2) is a no-op.
        const int Length2 = 2;
        const int Length1 = 1;
        byte[] two = OfScalar(2);

        byte[] rootOfUnity = new byte[Fp256QuadraticExtension.ElementSize];
        ParseElement(Anchors["rootx"]).CopyTo(rootOfUnity.AsSpan(0, ScalarSize));
        ParseElement(Anchors["rooty"]).CopyTo(rootOfUnity.AsSpan(ScalarSize, ScalarSize));

        //Length-1 no-op: input must be unchanged after forward and after backward.
        byte[] noopInput = OfScalar(137);
        byte[] noopData1 = new byte[Length1 * ScalarSize];
        noopInput.CopyTo(noopData1.AsSpan(0, ScalarSize));
        var fft1 = new Fp256RealFft(rootOfUnity, OmegaOrder, Add, Subtract, Multiply, Invert, OfScalarInto, CurveParameterSet.None, BaseMemoryPool.Shared);
        fft1.ForwardRealToHalfComplex(noopData1, Length1);
        Assert.IsTrue(noopData1.AsSpan(0, ScalarSize).SequenceEqual(noopInput), "Length-1 forward must leave input unchanged.");
        fft1.BackwardHalfComplexToReal(noopData1, Length1);
        Assert.IsTrue(noopData1.AsSpan(0, ScalarSize).SequenceEqual(noopInput), "Length-1 backward must leave input unchanged.");

        //Length-2 round-trip: backward(forward(x)) == 2 * x elementwise.
        byte[] x0 = OfScalar(17);
        byte[] x1 = OfScalar(99);
        byte[] data2 = new byte[Length2 * ScalarSize];
        x0.CopyTo(data2.AsSpan(0, ScalarSize));
        x1.CopyTo(data2.AsSpan(ScalarSize, ScalarSize));
        var fft2 = new Fp256RealFft(rootOfUnity, OmegaOrder, Add, Subtract, Multiply, Invert, OfScalarInto, CurveParameterSet.None, BaseMemoryPool.Shared);
        fft2.ForwardRealToHalfComplex(data2, Length2);
        fft2.BackwardHalfComplexToReal(data2, Length2);
        byte[] expected0 = FieldMultiply(x0, two);
        byte[] expected1 = FieldMultiply(x1, two);
        Assert.IsTrue(data2.AsSpan(0, ScalarSize).SequenceEqual(expected0), $"Length-2 round-trip: data[0] must equal 2*x0 (expected {Convert.ToHexString(expected0)}, got {Convert.ToHexString(data2[..ScalarSize])}).");
        Assert.IsTrue(data2.AsSpan(ScalarSize, ScalarSize).SequenceEqual(expected1), $"Length-2 round-trip: data[1] must equal 2*x1 (expected {Convert.ToHexString(expected1)}, got {Convert.ToHexString(data2.AsSpan(ScalarSize, ScalarSize).ToArray())}).");
    }


    [TestMethod]
    public void TheEncoderIsSystematic()
    {
        //The first n outputs are the unchanged inputs: our interpolate leaves y[0..n) alone.
        (byte[] evaluations, int n, int m) = BuildAndInterpolate(9, 23);

        for(int i = 0; i < n; i++)
        {
            byte[] expected = EvaluatePolynomial(BuildCoefficients(n, m), OfScalar((ulong)i));
            Assert.IsTrue(evaluations.AsSpan(i * ScalarSize, ScalarSize).SequenceEqual(expected), $"Systematic input {i} must be unchanged.");
        }
    }


    [TestMethod]
    public void TheMontgomeryDomainInterpolationDropsToTheCanonicalCodeword()
    {
        //Perf Increment 1: the RS engine + real-FFT + convolution run domain-agnostically over the injected
        //delegates, so interpolating in the Montgomery working domain (the witness lifted, the FFT root lifted
        //per coordinate, the of_scalar constants lifted) and dropping each output back must equal the canonical
        //interpolation element for element. This is the fast pre-check for the 1-CIOS RS path the sig prove uses.
        const int N = 9;
        const int M = 23;
        byte[][] coefficients = BuildCoefficients(N, M);

        byte[] canonicalEval = new byte[M * ScalarSize];
        byte[] montEval = new byte[M * ScalarSize];
        for(int i = 0; i < N; i++)
        {
            byte[] value = EvaluatePolynomial(coefficients, OfScalar((ulong)i));
            value.CopyTo(canonicalEval.AsSpan(i * ScalarSize, ScalarSize));
            P256BaseFieldMontgomeryBackend.ToMontgomery(value, montEval.AsSpan(i * ScalarSize, ScalarSize));
        }

        byte[] canonicalRoot = new byte[Fp256QuadraticExtension.ElementSize];
        ParseElement(Anchors["rootx"]).CopyTo(canonicalRoot.AsSpan(0, ScalarSize));
        ParseElement(Anchors["rooty"]).CopyTo(canonicalRoot.AsSpan(ScalarSize, ScalarSize));

        byte[] montRoot = new byte[Fp256QuadraticExtension.ElementSize];
        P256BaseFieldMontgomeryBackend.ToMontgomery(canonicalRoot.AsSpan(0, ScalarSize), montRoot.AsSpan(0, ScalarSize));
        P256BaseFieldMontgomeryBackend.ToMontgomery(canonicalRoot.AsSpan(ScalarSize, ScalarSize), montRoot.AsSpan(ScalarSize, ScalarSize));

        var cfft = new Fp256RealFft(canonicalRoot, OmegaOrder, Add, Subtract, Multiply, Invert, OfScalarInto, CurveParameterSet.None, BaseMemoryPool.Shared);
        using var crs = new Fp256ReedSolomon(N, M, cfft, Add, Subtract, Multiply, Invert, OfScalarInto, CurveParameterSet.None, BaseMemoryPool.Shared);
        crs.Interpolate(canonicalEval);

        ScalarMultiplyDelegate mMul = P256BaseFieldMontgomeryBackend.GetMultiplyMontgomery();
        ScalarInvertDelegate mInv = P256BaseFieldMontgomeryBackend.GetInvertMontgomery();
        var mfft = new Fp256RealFft(montRoot, OmegaOrder, Add, Subtract, mMul, mInv, MontOfScalarInto, CurveParameterSet.None, BaseMemoryPool.Shared);
        using var mrs = new Fp256ReedSolomon(N, M, mfft, Add, Subtract, mMul, mInv, MontOfScalarInto, CurveParameterSet.None, BaseMemoryPool.Shared);
        mrs.Interpolate(montEval);

        for(int i = 0; i < M; i++)
        {
            byte[] dropped = new byte[ScalarSize];
            P256BaseFieldMontgomeryBackend.FromMontgomery(montEval.AsSpan(i * ScalarSize, ScalarSize), dropped);
            Assert.IsTrue(canonicalEval.AsSpan(i * ScalarSize, ScalarSize).SequenceEqual(dropped), $"Montgomery interpolation element {i} must drop to the canonical value (canonical {Convert.ToHexString(canonicalEval.AsSpan(i * ScalarSize, ScalarSize).ToArray())}, dropped {Convert.ToHexString(dropped)}).");
        }
    }


    private static void MontOfScalarInto(uint value, Span<byte> destination)
    {
        OfScalar(value).CopyTo(destination);
        P256BaseFieldMontgomeryBackend.ToMontgomery(destination, destination);
    }


    private static void AssertCodeword(string label, int n, int m)
    {
        (byte[] evaluations, _, _) = BuildAndInterpolate(n, m);

        for(int i = 0; i < m; i++)
        {
            byte[] expected = ParseElement(Anchors[$"{label}[{i}]"]);
            Assert.IsTrue(
                evaluations.AsSpan(i * ScalarSize, ScalarSize).SequenceEqual(expected),
                $"{label}[{i}] must match the reference (expected {Convert.ToHexString(expected)}, got {Convert.ToHexString(evaluations.AsSpan(i * ScalarSize, ScalarSize).ToArray())}).");
        }
    }


    //Builds the anchor's polynomial, evaluates it at 0..n-1, and runs our interpolator over the m-length
    //buffer. Returns the full m-element codeword.
    private static (byte[] Evaluations, int N, int M) BuildAndInterpolate(int n, int m)
    {
        byte[][] coefficients = BuildCoefficients(n, m);

        byte[] evaluations = new byte[m * ScalarSize];
        for(int i = 0; i < n; i++)
        {
            byte[] value = EvaluatePolynomial(coefficients, OfScalar((ulong)i));
            value.CopyTo(evaluations.AsSpan(i * ScalarSize, ScalarSize));
        }

        byte[] rootOfUnity = new byte[Fp256QuadraticExtension.ElementSize];
        ParseElement(Anchors["rootx"]).CopyTo(rootOfUnity.AsSpan(0, ScalarSize));
        ParseElement(Anchors["rooty"]).CopyTo(rootOfUnity.AsSpan(ScalarSize, ScalarSize));

        var fft = new Fp256RealFft(rootOfUnity, OmegaOrder, Add, Subtract, Multiply, Invert, OfScalarInto, CurveParameterSet.None, BaseMemoryPool.Shared);
        using var rs = new Fp256ReedSolomon(n, m, fft, Add, Subtract, Multiply, Invert, OfScalarInto, CurveParameterSet.None, BaseMemoryPool.Shared);
        rs.Interpolate(evaluations);

        return (evaluations, n, m);
    }


    //The anchor's coefficient construction: M[i] = of_scalar(i*i + 42 + (m+11)*(n+22)).
    private static byte[][] BuildCoefficients(int n, int m)
    {
        byte[][] coefficients = new byte[n][];
        for(int i = 0; i < n; i++)
        {
            ulong value = ((ulong)i * (ulong)i) + 42UL + (((ulong)m + 11UL) * ((ulong)n + 22UL));
            coefficients[i] = OfScalar(value);
        }

        return coefficients;
    }


    //Horner evaluation of the monomial-basis polynomial at x (the anchor's eval_poly).
    private static byte[] EvaluatePolynomial(byte[][] coefficients, ReadOnlySpan<byte> x)
    {
        byte[] result = new byte[ScalarSize];
        Span<byte> accumulator = stackalloc byte[ScalarSize];
        accumulator.Clear();
        for(int i = coefficients.Length; i-- > 0;)
        {
            Multiply(accumulator, x, accumulator, CurveParameterSet.None);
            Add(accumulator, coefficients[i], accumulator, CurveParameterSet.None);
        }

        accumulator.CopyTo(result);

        return result;
    }


    //of_scalar(u) in the canonical working domain, in the engines' Action<uint, Span<byte>> shape: the
    //integer reduced mod p as a canonical 32-byte big-endian scalar. The RS/FFT engines source their field
    //constants through this so they stay domain-agnostic; for the canonical domain the bytes are identical
    //to the engines' former baked OfOne/OfScalar.
    private static void OfScalarInto(uint value, Span<byte> destination) => OfScalar(value).CopyTo(destination);


    //of_scalar(value): value reduced mod p as a canonical 32-byte big-endian scalar.
    private static byte[] OfScalar(ulong value)
    {
        byte[] canonical = new byte[ScalarSize];
        BigInteger reduced = new BigInteger(value) % FieldOrder;
        reduced.TryWriteBytes(canonical.AsSpan(), out int written, isUnsigned: true, isBigEndian: true);
        if(written < ScalarSize)
        {
            int shift = ScalarSize - written;
            canonical.AsSpan(0, written).CopyTo(canonical.AsSpan(shift));
            canonical.AsSpan(0, shift).Clear();
        }

        return canonical;
    }


    //Multiplies two base-field elements and returns the product as a new 32-byte canonical scalar.
    private static byte[] FieldMultiply(byte[] a, byte[] b)
    {
        byte[] result = new byte[ScalarSize];
        Multiply(a, b, result, CurveParameterSet.None);

        return result;
    }


    //Parses a 32-byte little-endian to_bytes_field element into a 32-byte big-endian canonical scalar.
    private static byte[] ParseElement(string hex)
    {
        byte[] littleEndian = Convert.FromHexString(hex);
        byte[] canonical = new byte[ScalarSize];
        for(int i = 0; i < ScalarSize; i++)
        {
            canonical[ScalarSize - 1 - i] = littleEndian[i];
        }

        return canonical;
    }


    private static Dictionary<string, string> LoadAnchors()
    {
        string path = $"../../../{AnchorRelativePath}";
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach(string line in File.ReadAllLines(path))
        {
            int separator = line.IndexOf('=', StringComparison.Ordinal);
            if(separator < 0)
            {
                continue;
            }

            string key = line[..separator];
            string value = line[(separator + 1)..];

            //Anchor data lines are key=hex with no spaces; the provenance header lines are skipped here.
            if(value.Length > 0 && IsHex(value))
            {
                map[key] = value;
            }
        }

        return map;
    }


    private static bool IsHex(string value)
    {
        foreach(char c in value)
        {
            bool isHexDigit = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if(!isHexDigit)
            {
                return false;
            }
        }

        return true;
    }
}
