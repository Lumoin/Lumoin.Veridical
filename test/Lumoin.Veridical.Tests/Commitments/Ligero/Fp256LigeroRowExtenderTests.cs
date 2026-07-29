using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Buffers.Binary;

namespace Lumoin.Veridical.Tests.Commitments.Ligero;

/// <summary>
/// The byte-identity gate for the FFT convolution row extender: over every
/// representative Ligero shape — power-of-two PCS shapes and the tableau's
/// non-power-of-two block shapes — the <see cref="Fp256LigeroRowExtenders"/>
/// engine must produce exactly the codeword the barycentric
/// <see cref="LigeroReedSolomonEncoder"/> reference path produces. Field
/// arithmetic is exact, so equality of the mathematical map is equality of
/// the bytes; this gate is what licenses swapping the engine under committed
/// fixtures.
/// </summary>
[TestClass]
internal sealed class Fp256LigeroRowExtenderTests
{
    private static ScalarAddDelegate Add { get; } = P256BaseFieldMontgomeryBackend.GetAdd();
    private static ScalarSubtractDelegate Subtract { get; } = P256BaseFieldMontgomeryBackend.GetSubtract();
    private static ScalarMultiplyDelegate Multiply { get; } = P256BaseFieldMontgomeryBackend.GetMultiply();
    private static ScalarInvertDelegate Invert { get; } = P256BaseFieldMontgomeryBackend.GetInvert();
    private static ScalarReduceDelegate Reduce { get; } = P256BaseFieldMontgomeryBackend.GetReduce();

    private const int ScalarSize = Scalar.SizeBytes;

    //A fill salt distinct from the streams other Ligero tests draw.
    private const int MessageFillSalt = 1201;

    //The representative shapes: the anchor suite's small shapes, a
    //power-of-two PCS-style shape, and the tableau's shapes at the age-gadget
    //parameters (block 64, inverse rate 4: blockEncoded = (2+4)·64 − 1 = 383,
    //doubleBlock = 2·64 − 1 = 127) — including the (block, doubleBlock) aext
    //shape, the one family with messageLength < codewordLength < 2·messageLength.
    private static (int MessageLength, int CodewordLength)[] Shapes { get; } =
    [
        (5, 16),
        (9, 23),
        (16, 64),
        (64, 127),
        (64, 383),
        (127, 383),
    ];


    [TestMethod]
    public void TheConvolutionExtenderMatchesTheBarycentricEncoderByteForByte()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using Fp256LigeroRowExtenders extenders = NewExtenders(pool);

        foreach((int messageLength, int codewordLength) in Shapes)
        {
            using IMemoryOwner<byte> messageOwner = pool.Rent(messageLength * ScalarSize);
            Span<byte> message = messageOwner.Memory.Span[..(messageLength * ScalarSize)];
            DeterministicScalarFill.FillCanonical(message, MessageFillSalt + messageLength, Reduce, CurveParameterSet.None);

            using IMemoryOwner<byte> barycentricOwner = pool.Rent(codewordLength * ScalarSize);
            Span<byte> barycentric = barycentricOwner.Memory.Span[..(codewordLength * ScalarSize)];
            LigeroReedSolomonEncoder.Encode(message, messageLength, barycentric, codewordLength, Add, Subtract, Multiply, Invert, CurveParameterSet.None, pool);

            using IMemoryOwner<byte> convolvedOwner = pool.Rent(codewordLength * ScalarSize);
            Span<byte> convolved = convolvedOwner.Memory.Span[..(codewordLength * ScalarSize)];
            message.CopyTo(convolved[..(messageLength * ScalarSize)]);
            LigeroRowExtender? extender = extenders.Create(messageLength, codewordLength);
            Assert.IsNotNull(extender, $"The extender factory must accept the ({messageLength}, {codewordLength}) shape.");
            extender(convolved);

            Assert.IsTrue(convolved.SequenceEqual(barycentric), $"The convolution codeword must be byte-identical to the barycentric codeword at shape ({messageLength}, {codewordLength}).");
        }
    }


    [TestMethod]
    public void TheExtenderLeavesTheSystematicPrefixUntouched()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using Fp256LigeroRowExtenders extenders = NewExtenders(pool);

        const int MessageLength = 9;
        const int CodewordLength = 23;
        using IMemoryOwner<byte> codewordOwner = pool.Rent(CodewordLength * ScalarSize);
        Span<byte> codeword = codewordOwner.Memory.Span[..(CodewordLength * ScalarSize)];
        codeword.Clear();
        DeterministicScalarFill.FillCanonical(codeword[..(MessageLength * ScalarSize)], MessageFillSalt, Reduce, CurveParameterSet.None);
        Span<byte> expectedPrefix = stackalloc byte[MessageLength * ScalarSize];
        codeword[..(MessageLength * ScalarSize)].CopyTo(expectedPrefix);

        LigeroRowExtender? extender = extenders.Create(MessageLength, CodewordLength);
        Assert.IsNotNull(extender);
        extender(codeword);

        Assert.IsTrue(codeword[..(MessageLength * ScalarSize)].SequenceEqual(expectedPrefix), "The systematic prefix must be unchanged by the extension.");
    }


    private static Fp256LigeroRowExtenders NewExtenders(BaseMemoryPool pool)
    {
        Span<byte> root = stackalloc byte[Fp256QuadraticExtension.ElementSize];
        LongfellowFp256Encoding.RootOfUnity(root);
        var fft = new Fp256RealFft(root, LongfellowFp256Encoding.OmegaOrder, Add, Subtract, Multiply, Invert, WriteCanonicalUInt, CurveParameterSet.None, pool);

        return new Fp256LigeroRowExtenders(fft, Add, Subtract, Multiply, Invert, WriteCanonicalUInt, CurveParameterSet.None, pool);
    }


    private static void WriteCanonicalUInt(uint value, Span<byte> destination)
    {
        destination.Clear();
        BinaryPrimitives.WriteUInt32BigEndian(destination[(ScalarSize - sizeof(uint))..], value);
    }
}
