using System;
using System.Buffers.Binary;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow.Compiler;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;

/// <summary>
/// The host-side witness helper for the small-list revocation statement, a faithful port of the
/// reference's <c>compute_mdoc_revocation_list_witness</c>
/// (<c>circuits/tests/mdoc/mdoc_revocation_witness.h</c>).
/// </summary>
internal static class LongfellowMdocRevocationListWitness
{
    /// <summary>
    /// Computes the inverse of <c>Π (list[i] − id)</c>, the private witness of
    /// <see cref="LongfellowMdocRevocationListCircuit.AssertNotOnList"/>. A listed identifier
    /// zeroes the product, which has no inverse; the helper then returns zero without consulting
    /// the inversion backend (whose zero behavior is backend-defined), and the statement's equality
    /// assertion rejects the zero non-witness exactly as the reference's Fermat inversion of zero
    /// does.
    /// </summary>
    /// <param name="field">The base-field bundle.</param>
    /// <param name="id">The identifier, canonical big-endian.</param>
    /// <param name="list">The revocation list elements, canonical big-endian.</param>
    /// <returns>The canonical product inverse, or zero when the identifier is listed.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="id"/> is not exactly <see cref="Scalar.SizeBytes"/> bytes.</exception>
    public static byte[] ComputeProductInverse(LongfellowLogicFieldOperations field, ReadOnlySpan<byte> id, ReadOnlyMemory<byte>[] list)
    {
        ArgumentNullException.ThrowIfNull(field);
        ArgumentNullException.ThrowIfNull(list);

        if(id.Length != Scalar.SizeBytes)
        {
            throw new ArgumentException($"The identifier is a canonical {Scalar.SizeBytes}-byte scalar.", nameof(id));
        }

        byte[] product = new byte[Scalar.SizeBytes];
        field.Compiler.One.Span.CopyTo(product);

        //The delegates' aliasing behavior is unspecified, so the running product ping-pongs
        //through a scratch buffer instead of multiplying into itself.
        Span<byte> difference = stackalloc byte[Scalar.SizeBytes];
        Span<byte> scratch = stackalloc byte[Scalar.SizeBytes];
        for(int i = 0; i < list.Length; i++)
        {
            field.Subtract(list[i].Span, id, difference, field.Compiler.Curve);
            field.Compiler.Multiply(product, difference, scratch, field.Compiler.Curve);
            scratch.CopyTo(product);
        }

        if(LongfellowCompilerFieldOperations.ElementIsZero(product))
        {
            return new byte[Scalar.SizeBytes];
        }

        byte[] inverse = new byte[Scalar.SizeBytes];
        field.Invert(product, inverse, field.Compiler.Curve);

        return inverse;
    }
}


/// <summary>
/// Computes the private witness column for the span revocation statement, a faithful port of
/// google/longfellow-zk's <c>MdocRevocationSpanWitness</c>
/// (<c>circuits/tests/mdoc/mdoc_revocation_witness.h</c>): the span signature's ECDSA advice, the
/// little-endian span <c>epoch || l || r</c> with its two-block SHA-256 advice, and the identifier
/// and digest bits, emitted in the order
/// <see cref="LongfellowMdocRevocationSpanCircuit.InputWitness"/> declares wires in.
/// </summary>
/// <remarks>
/// The generator does not check <c>l &lt; id &lt; r</c>, exactly like the reference: an
/// out-of-span identifier still fills a complete column, and the statement's range assertions
/// reject it at proving time. Witness generation runs prover-side over the prover's own
/// credential and span data; the single-subtraction digest reduction takes a data-dependent early
/// exit, as in the ported ECDSA and JWT generators.
/// </remarks>
internal sealed class LongfellowMdocRevocationSpanWitness
{
    /// <summary>One SHA-256 block's byte width.</summary>
    private const int BytesPerBlock = 64;

    /// <summary>The words one SHA-256 block's advice records: the schedule extension, both per-round registers, and the final state.</summary>
    private const int WordsPerBlock = 48 + 64 + 64 + 8;

    private readonly LongfellowLogicFieldOperations field;
    private readonly LongfellowEcdsaVerifyWitness signature;
    private readonly LongfellowBitPluckerEncoder encoder;
    private readonly byte[] basePrime;

    private readonly byte[] spanR;
    private readonly byte[] spanS;
    private readonly byte[] digest;
    private readonly byte[] preimage;
    private readonly byte[] idBits;
    private readonly byte[] eBits;
    private readonly LongfellowFlatSha256BlockWitness[] blocks;


    /// <summary>
    /// Constructs the generator over the same field bundles and curve the statement circuit uses.
    /// </summary>
    /// <param name="field">The base-field bundle.</param>
    /// <param name="orderMultiply">The order-field multiplication, canonical in and out.</param>
    /// <param name="orderSubtract">The order-field subtraction, canonical in and out.</param>
    /// <param name="orderInvert">The order-field inversion, canonical in and out.</param>
    /// <param name="orderCurve">The curve parameter set the order-field delegates dispatch on.</param>
    /// <param name="curve">The curve constants.</param>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    public LongfellowMdocRevocationSpanWitness(
        LongfellowLogicFieldOperations field,
        ScalarMultiplyDelegate orderMultiply,
        ScalarSubtractDelegate orderSubtract,
        ScalarInvertDelegate orderInvert,
        CurveParameterSet orderCurve,
        LongfellowEllipticCurveParameters curve)
    {
        ArgumentNullException.ThrowIfNull(field);
        ArgumentNullException.ThrowIfNull(curve);

        this.field = field;
        signature = new LongfellowEcdsaVerifyWitness(field, orderMultiply, orderSubtract, orderInvert, orderCurve, curve);
        encoder = new LongfellowBitPluckerEncoder(field, LongfellowMdocRevocationConstants.ShaRevocationPluckerBits);
        basePrime = LongfellowEcdsaVerifyWitness.DeriveBasePrime(field);

        spanR = new byte[Scalar.SizeBytes];
        spanS = new byte[Scalar.SizeBytes];
        digest = new byte[Scalar.SizeBytes];
        preimage = new byte[LongfellowMdocRevocationConstants.SpanBlockCount * BytesPerBlock];
        idBits = new byte[LongfellowLogic.BitWidth256];
        eBits = new byte[LongfellowLogic.BitWidth256];
        blocks = new LongfellowFlatSha256BlockWitness[LongfellowMdocRevocationConstants.SpanBlockCount];
        for(int i = 0; i < blocks.Length; i++)
        {
            blocks[i] = new LongfellowFlatSha256BlockWitness();
        }
    }


    /// <summary>The column length in elements: the signature scalars and span digest, the ECDSA advice, the preimage and identifier and digest bits, and the packed SHA-256 advice.</summary>
    public int ElementCount =>
        3
        + signature.ElementCount
        + (LongfellowMdocRevocationConstants.SpanBlockCount * BytesPerBlock * LongfellowLogic.BitWidth8)
        + (2 * LongfellowLogic.BitWidth256)
        + (LongfellowMdocRevocationConstants.SpanBlockCount * WordsPerBlock * encoder.PackedV32ElementCount);


    /// <summary>
    /// The reference's <c>compute_witness</c>: verifies the span signature witness-side, lays the
    /// span out as little-endian <c>epoch || l || r</c>, hashes it into the two-block SHA-256
    /// advice, and records the identifier and digest bits.
    /// </summary>
    /// <param name="pkX">The revocation authority public key's x coordinate, canonical big-endian.</param>
    /// <param name="pkY">The revocation authority public key's y coordinate, canonical big-endian.</param>
    /// <param name="e">The span digest the authority signed, canonical big-endian.</param>
    /// <param name="r">The span signature's <c>r</c>, canonical big-endian.</param>
    /// <param name="s">The span signature's <c>s</c>, canonical big-endian.</param>
    /// <param name="id">The credential identifier, canonical big-endian.</param>
    /// <param name="lowerBound">The span's lower bound <c>l</c>, canonical big-endian.</param>
    /// <param name="upperBound">The span's upper bound <c>r</c>, canonical big-endian.</param>
    /// <param name="epoch">The span's epoch.</param>
    /// <returns>Whether the signature produced a complete advice bundle.</returns>
    /// <exception cref="ArgumentException">When a scalar argument is not exactly <see cref="Scalar.SizeBytes"/> bytes.</exception>
    public bool ComputeWitness(
        ReadOnlySpan<byte> pkX,
        ReadOnlySpan<byte> pkY,
        ReadOnlySpan<byte> e,
        ReadOnlySpan<byte> r,
        ReadOnlySpan<byte> s,
        ReadOnlySpan<byte> id,
        ReadOnlySpan<byte> lowerBound,
        ReadOnlySpan<byte> upperBound,
        ulong epoch)
    {
        if(pkX.Length != Scalar.SizeBytes
            || pkY.Length != Scalar.SizeBytes
            || e.Length != Scalar.SizeBytes
            || r.Length != Scalar.SizeBytes
            || s.Length != Scalar.SizeBytes
            || id.Length != Scalar.SizeBytes
            || lowerBound.Length != Scalar.SizeBytes
            || upperBound.Length != Scalar.SizeBytes)
        {
            throw new ArgumentException($"Every scalar argument is a canonical {Scalar.SizeBytes}-byte value.");
        }

        if(!signature.ComputeWitness(pkX, pkY, e, r, s))
        {
            return false;
        }

        r.CopyTo(spanR);
        s.CopyTo(spanS);
        ReduceOnce(e, basePrime, digest);

        //The signed span: the epoch, then both bounds, all little endian.
        Span<byte> message = stackalloc byte[LongfellowMdocRevocationConstants.SpanMessageLength];
        BinaryPrimitives.WriteUInt64LittleEndian(message, epoch);
        WriteLittleEndianBound(message[LongfellowMdocRevocationConstants.LowerBoundByteOffset..], lowerBound);
        WriteLittleEndianBound(message[LongfellowMdocRevocationConstants.UpperBoundByteOffset..], upperBound);

        for(int i = 0; i < LongfellowLogic.BitWidth256; i++)
        {
            idBits[i] = (byte)((id[Scalar.SizeBytes - 1 - (i / 8)] >> (i % 8)) & 1);
            eBits[i] = (byte)((e[Scalar.SizeBytes - 1 - (i / 8)] >> (i % 8)) & 1);
        }

        LongfellowFlatSha256Witness.TransformAndWitnessMessage(message, LongfellowMdocRevocationConstants.SpanBlockCount, out _, preimage, blocks);

        return true;
    }


    /// <summary>
    /// The reference's <c>fill_witness</c>: writes the private witness region in declaration order.
    /// </summary>
    /// <param name="destination">Receives <see cref="ElementCount"/> elements of <see cref="Scalar.SizeBytes"/> bytes each.</param>
    /// <exception cref="ArgumentException">When <paramref name="destination"/> is not exactly the column's byte length.</exception>
    public void FillWitness(Span<byte> destination)
    {
        if(destination.Length != ElementCount * Scalar.SizeBytes)
        {
            throw new ArgumentException($"The column is exactly {ElementCount} elements of {Scalar.SizeBytes} bytes.", nameof(destination));
        }

        int cursor = 0;
        WriteElement(destination, ref cursor, spanR);
        WriteElement(destination, ref cursor, spanS);
        WriteElement(destination, ref cursor, digest);

        signature.FillWitness(destination.Slice(cursor * Scalar.SizeBytes, signature.ElementCount * Scalar.SizeBytes));
        cursor += signature.ElementCount;

        for(int i = 0; i < preimage.Length; i++)
        {
            WriteBits(destination, ref cursor, preimage[i], LongfellowLogic.BitWidth8);
        }

        for(int i = 0; i < idBits.Length; i++)
        {
            WriteBits(destination, ref cursor, idBits[i], 1);
        }

        for(int i = 0; i < eBits.Length; i++)
        {
            WriteBits(destination, ref cursor, eBits[i], 1);
        }

        for(int j = 0; j < blocks.Length; j++)
        {
            FillShaBlock(destination, ref cursor, blocks[j]);
        }
    }


    /// <summary>Writes one bound into the span, reversing canonical big-endian into the span's little-endian layout.</summary>
    /// <param name="destination">The span region receiving the bound.</param>
    /// <param name="bound">The bound, canonical big-endian.</param>
    private static void WriteLittleEndianBound(Span<byte> destination, ReadOnlySpan<byte> bound)
    {
        for(int i = 0; i < LongfellowMdocRevocationConstants.BoundByteLength; i++)
        {
            destination[i] = bound[Scalar.SizeBytes - 1 - i];
        }
    }


    /// <summary>
    /// The reference's <c>fill_sha</c>: one block's advice as plucker-packed words — the schedule
    /// extension, the per-round register pairs interleaved, then the final state.
    /// </summary>
    /// <param name="destination">The column being filled.</param>
    /// <param name="cursor">The element cursor.</param>
    /// <param name="block">The block advice.</param>
    private void FillShaBlock(Span<byte> destination, ref int cursor, in LongfellowFlatSha256BlockWitness block)
    {
        for(int k = 0; k < block.ScheduleExtension.Length; k++)
        {
            WritePackedWord(destination, ref cursor, block.ScheduleExtension[k]);
        }

        for(int k = 0; k < block.RegisterEWitness.Length; k++)
        {
            WritePackedWord(destination, ref cursor, block.RegisterEWitness[k]);
            WritePackedWord(destination, ref cursor, block.RegisterAWitness[k]);
        }

        for(int k = 0; k < block.FinalState.Length; k++)
        {
            WritePackedWord(destination, ref cursor, block.FinalState[k]);
        }
    }


    /// <summary>Writes one 32-bit word as its plucker-packed elements.</summary>
    /// <param name="destination">The column being filled.</param>
    /// <param name="cursor">The element cursor.</param>
    /// <param name="word">The word to pack.</param>
    private void WritePackedWord(Span<byte> destination, ref int cursor, uint word)
    {
        ReadOnlyMemory<byte>[] packed = encoder.MakePackedV32(word);
        for(int i = 0; i < packed.Length; i++)
        {
            packed[i].Span.CopyTo(destination.Slice(cursor * Scalar.SizeBytes, Scalar.SizeBytes));
            cursor++;
        }
    }


    /// <summary>Writes a value's bits, least significant first, one field element per bit (the reference filler's <c>push_back(x, bits, F)</c>).</summary>
    /// <param name="destination">The column being filled.</param>
    /// <param name="cursor">The element cursor.</param>
    /// <param name="value">The value.</param>
    /// <param name="bitCount">The bit count.</param>
    private void WriteBits(Span<byte> destination, ref int cursor, ulong value, int bitCount)
    {
        for(int i = 0; i < bitCount; i++)
        {
            ReadOnlyMemory<byte> element = ((value >> i) & 1UL) != 0UL ? field.Compiler.One : field.Compiler.Zero;
            element.Span.CopyTo(destination.Slice(cursor * Scalar.SizeBytes, Scalar.SizeBytes));
            cursor++;
        }
    }


    /// <summary>Writes one element into the column and advances the cursor.</summary>
    /// <param name="destination">The column.</param>
    /// <param name="cursor">The element cursor.</param>
    /// <param name="element">The element to write.</param>
    private static void WriteElement(Span<byte> destination, ref int cursor, byte[] element)
    {
        element.CopyTo(destination.Slice(cursor * Scalar.SizeBytes, Scalar.SizeBytes));
        cursor++;
    }


    /// <summary>Reduces a raw 256-bit value once modulo <paramref name="modulus"/> (the same single conditional subtraction the ECDSA witness generator uses).</summary>
    /// <param name="value">The raw big-endian value.</param>
    /// <param name="modulus">The modulus.</param>
    /// <param name="destination">Receives the reduced value.</param>
    private static void ReduceOnce(ReadOnlySpan<byte> value, ReadOnlySpan<byte> modulus, Span<byte> destination)
    {
        bool subtract = true;
        for(int i = 0; i < Scalar.SizeBytes; i++)
        {
            if(value[i] != modulus[i])
            {
                subtract = value[i] > modulus[i];

                break;
            }
        }

        if(!subtract)
        {
            value.CopyTo(destination);

            return;
        }

        int borrow = 0;
        for(int i = Scalar.SizeBytes - 1; i >= 0; i--)
        {
            int difference = value[i] - modulus[i] - borrow;
            borrow = difference < 0 ? 1 : 0;
            destination[i] = (byte)(difference & 0xFF);
        }
    }
}
