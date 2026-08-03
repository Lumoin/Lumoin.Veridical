using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The gates for the sextic-extension field backend <c>F_q[x]/(x^6 − 7)</c> over the FIPS 204
/// prime: the defining relation, agreement with an independent <see cref="BigInteger"/>
/// polynomial model, inversion round-trips with the zero-maps-to-zero convention, the canonical
/// container layout the compiler kernel's little-endian serialization depends on, and the Logic
/// bundle's bounded <c>of_scalar</c> mirroring the reference's panic.
/// </summary>
[TestClass]
internal sealed class Fp24SexticBackendTests
{
    /// <summary>The field element width in bytes used for every canonical container.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The extension degree.</summary>
    private const int LimbCount = Fp24SexticBackend.LimbCount;

    /// <summary>The FIPS 204 prime modulus.</summary>
    private const uint Modulus = Fp24SexticBackend.Modulus;

    /// <summary>The extension residue of <c>x^6</c>.</summary>
    private const uint ExtensionResidue = Fp24SexticBackend.ExtensionResidue;

    /// <summary>The agreement sweep's pair count: enough to exercise every convolution diagonal with full-width coefficients.</summary>
    private const int AgreementPairCount = 24;

    /// <summary>The deterministic coefficient generator's multiplier (a fixed odd constant; the values only need to be spread and reproducible).</summary>
    private const ulong FillMultiplier = 6364136223846793005;

    /// <summary>The deterministic coefficient generator's increment.</summary>
    private const ulong FillIncrement = 1442695040888963407;

    /// <summary>The last representable basis index: 2^22 is the largest power of two below the modulus, which sits between 2^22 and 2^23.</summary>
    private const int LastRepresentableBasisIndex = 22;

    /// <summary>The first unrepresentable basis index: 2^23 exceeds the modulus, so the reference's <c>of_scalar</c> check fires.</summary>
    private const int FirstUnrepresentableBasisIndex = 23;

    /// <summary>The add delegate under test.</summary>
    private static ScalarAddDelegate Add { get; } = Fp24SexticBackend.GetAdd();

    /// <summary>The subtract delegate under test.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = Fp24SexticBackend.GetSubtract();

    /// <summary>The multiply delegate under test.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = Fp24SexticBackend.GetMultiply();

    /// <summary>The invert delegate under test.</summary>
    private static ScalarInvertDelegate Invert { get; } = Fp24SexticBackend.GetInvert();


    /// <summary>Pins the defining relation: the sixth power of the degree-one monomial is the extension residue.</summary>
    [TestMethod]
    public void TheSixthPowerOfXIsTheExtensionResidue()
    {
        byte[] x = FromLimbs(0, 1, 0, 0, 0, 0);
        byte[] power = FromLimbs(1, 0, 0, 0, 0, 0);
        var next = new byte[ScalarSize];
        for(int i = 0; i < LimbCount; i++)
        {
            Multiply(power, x, next, CurveParameterSet.None);
            next.CopyTo(power.AsSpan());
        }

        Assert.AreSequenceEqual(FromLimbs(ExtensionResidue, 0, 0, 0, 0, 0), power, "x^6 must equal the extension residue.");
    }


    /// <summary>Pins agreement of add, subtract and multiply with an independent polynomial model over a deterministic coefficient sweep.</summary>
    [TestMethod]
    public void TheDelegatesAgreeWithThePolynomialModel()
    {
        ulong state = 1;
        var result = new byte[ScalarSize];
        for(int pair = 0; pair < AgreementPairCount; pair++)
        {
            uint[] left = NextCoefficients(ref state);
            uint[] right = NextCoefficients(ref state);
            byte[] leftBytes = FromLimbs(left);
            byte[] rightBytes = FromLimbs(right);

            Add(leftBytes, rightBytes, result, CurveParameterSet.None);
            Assert.AreSequenceEqual(FromLimbs(ModelAdd(left, right)), result, $"Addition must match the model at pair {pair}.");

            Subtract(leftBytes, rightBytes, result, CurveParameterSet.None);
            Assert.AreSequenceEqual(FromLimbs(ModelSubtract(left, right)), result, $"Subtraction must match the model at pair {pair}.");

            Multiply(leftBytes, rightBytes, result, CurveParameterSet.None);
            Assert.AreSequenceEqual(FromLimbs(ModelMultiply(left, right)), result, $"Multiplication must match the model at pair {pair}.");
        }
    }


    /// <summary>Pins inversion: a nonzero element times its inverse is one — for a subfield element, the degree-one monomial, and a full-width element — and zero inverts to zero.</summary>
    [TestMethod]
    public void InversionRoundTripsAndZeroMapsToZero()
    {
        uint[][] elements =
        [
            [12345, 0, 0, 0, 0, 0],
            [0, 1, 0, 0, 0, 0],
            [1, 2, 3, 4, 5, 6],
        ];

        var inverse = new byte[ScalarSize];
        var product = new byte[ScalarSize];
        foreach(uint[] limbs in elements)
        {
            byte[] element = FromLimbs(limbs);
            Invert(element, inverse, CurveParameterSet.None);
            Multiply(element, inverse, product, CurveParameterSet.None);
            Assert.AreSequenceEqual(FromLimbs(1, 0, 0, 0, 0, 0), product, "An element times its inverse must be one.");
        }

        Invert(new byte[ScalarSize], inverse, CurveParameterSet.None);
        Assert.AreSequenceEqual(new byte[ScalarSize], inverse, "Zero must invert to zero under the Fermat convention.");
    }


    /// <summary>Pins the canonical layout: the compiler bundle's little-endian serialization of a known element reproduces the reference's <c>to_bytes_field</c> coefficient order.</summary>
    [TestMethod]
    public void TheCompilerSerializationMatchesTheReferenceCoefficientOrder()
    {
        LongfellowLogicFieldOperations field = NewBundle();
        byte[] element = FromLimbs(1, 2, 3, 4, 5, 6);

        var serialized = new byte[Fp24SexticBackend.ElementBytes];
        field.Compiler.WriteLittleEndian(element, serialized);

        var expected = new byte[Fp24SexticBackend.ElementBytes];
        for(uint i = 0; i < LimbCount; i++)
        {
            //Coefficient i as a little-endian 32-bit value at offset 4i, the reference layout.
            expected[4 * i] = (byte)(i + 1);
        }

        Assert.AreSequenceEqual(expected, serialized, "The little-endian serialization must reproduce the reference coefficient order.");
    }


    /// <summary>Pins the bundle constants and the bounded <c>of_scalar</c>: two halves to one, the last representable basis index works, and the base modulus is rejected exactly where the reference panics.</summary>
    [TestMethod]
    public void TheBundleConstantsAndScalarBoundBehave()
    {
        LongfellowLogicFieldOperations field = NewBundle();

        var product = new byte[ScalarSize];
        field.Compiler.Multiply(field.Two.Span, field.Half.Span, product, field.Compiler.Curve);
        Assert.AreSequenceEqual(field.Compiler.One.ToArray(), product, "Two times half must be one.");

        Assert.AreSequenceEqual(
            FromLimbs(1u << LastRepresentableBasisIndex, 0, 0, 0, 0, 0),
            field.Beta(LastRepresentableBasisIndex).ToArray(),
            "The last representable basis element must embed in the constant coefficient.");
        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => field.Beta(FirstUnrepresentableBasisIndex), "A basis element at or beyond the base modulus must be rejected.");
        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => field.OfScalar(Modulus), "The base modulus itself must be rejected.");
    }


    /// <summary>Builds the Logic bundle over the backend delegates.</summary>
    /// <returns>The bundle.</returns>
    private static LongfellowLogicFieldOperations NewBundle()
    {
        return LongfellowLogicFieldOperations.CreateFp24Sextic(Add, Subtract, Multiply, Invert, FromLimbs(Modulus - 1, 0, 0, 0, 0, 0));
    }


    /// <summary>Produces the next six deterministic coefficients below the modulus.</summary>
    /// <param name="state">The generator state, advanced per coefficient.</param>
    /// <returns>The coefficients.</returns>
    private static uint[] NextCoefficients(ref ulong state)
    {
        var limbs = new uint[LimbCount];
        for(int i = 0; i < LimbCount; i++)
        {
            state = (state * FillMultiplier) + FillIncrement;
            limbs[i] = (uint)((state >> 32) % Modulus);
        }

        return limbs;
    }


    /// <summary>The model's coefficient-wise addition.</summary>
    /// <param name="a">The left coefficients.</param>
    /// <param name="b">The right coefficients.</param>
    /// <returns>The sum's coefficients.</returns>
    private static uint[] ModelAdd(uint[] a, uint[] b)
    {
        var sum = new uint[LimbCount];
        for(int i = 0; i < LimbCount; i++)
        {
            sum[i] = (uint)(((ulong)a[i] + b[i]) % Modulus);
        }

        return sum;
    }


    /// <summary>The model's coefficient-wise subtraction.</summary>
    /// <param name="a">The left coefficients.</param>
    /// <param name="b">The right coefficients.</param>
    /// <returns>The difference's coefficients.</returns>
    private static uint[] ModelSubtract(uint[] a, uint[] b)
    {
        var difference = new uint[LimbCount];
        for(int i = 0; i < LimbCount; i++)
        {
            difference[i] = (uint)(((ulong)a[i] + Modulus - b[i]) % Modulus);
        }

        return difference;
    }


    /// <summary>The model's polynomial multiplication: a <see cref="BigInteger"/> convolution, the <c>x^6</c> fold, and one reduction per coefficient.</summary>
    /// <param name="a">The left coefficients.</param>
    /// <param name="b">The right coefficients.</param>
    /// <returns>The product's coefficients.</returns>
    private static uint[] ModelMultiply(uint[] a, uint[] b)
    {
        var convolution = new BigInteger[(2 * LimbCount) - 1];
        for(int i = 0; i < LimbCount; i++)
        {
            for(int j = 0; j < LimbCount; j++)
            {
                convolution[i + j] += (BigInteger)a[i] * b[j];
            }
        }

        var product = new uint[LimbCount];
        for(int i = 0; i < LimbCount; i++)
        {
            BigInteger folded = convolution[i];
            if(i < LimbCount - 1)
            {
                folded += convolution[i + LimbCount] * ExtensionResidue;
            }

            product[i] = (uint)(folded % Modulus);
        }

        return product;
    }


    /// <summary>Builds a canonical container from coefficients: <c>e[i]</c> big-endian at byte offset <c>28 − 4i</c>.</summary>
    /// <param name="limbs">The coefficients, constant term first.</param>
    /// <returns>The canonical element.</returns>
    private static byte[] FromLimbs(params uint[] limbs)
    {
        var element = new byte[ScalarSize];
        for(int i = 0; i < limbs.Length; i++)
        {
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(element.AsSpan(ScalarSize - ((i + 1) * 4), 4), limbs[i]);
        }

        return element;
    }
}
