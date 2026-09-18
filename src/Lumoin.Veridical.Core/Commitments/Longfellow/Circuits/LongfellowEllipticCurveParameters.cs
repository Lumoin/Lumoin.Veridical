using System;
using System.Buffers;
using System.Globalization;
using Lumoin.Veridical.Core.Algebraic;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;

/// <summary>
/// The short-Weierstrass curve constants the ECDSA statement circuits consume, the port of the
/// surface google/longfellow-zk's <c>EllipticCurve</c> template exposes to
/// <c>circuits/ecdsa/verify_circuit.h</c> (<c>a_</c>, <c>b_</c>, <c>k3b</c>, <c>gx_</c>,
/// <c>gy_</c>, <c>kBits</c>, and the group order the verifier range-checks scalars against). Every
/// element is a canonical big-endian <see cref="Scalar.SizeBytes"/>-byte base-field scalar in the
/// same convention the rest of the gadget layer uses.
/// </summary>
/// <remarks>
/// <see cref="BTimes3"/> is the Renes–Costello–Batina precomputed <c>3·b</c> constant the complete
/// addition and doubling formulas consume (the reference computes it once in the curve
/// constructor); it is embedded here already reduced so the circuit and the witness generator agree
/// byte for byte without re-deriving it.
/// </remarks>
internal sealed class LongfellowEllipticCurveParameters: IDisposable
{
    /// <summary>The six canonical curve parameters occupy one scalar slot each.</summary>
    private const int ConstantCount = 6;

    /// <summary>The sensitive owner of every exposed constant; views borrow this owner's lifetime.</summary>
    private LongfellowCircuitStorage Storage { get; }

    /// <summary>The curve coefficient <c>a</c>, canonical big-endian.</summary>
    public ReadOnlyMemory<byte> A { get; }

    /// <summary>The curve coefficient <c>b</c>, canonical big-endian.</summary>
    public ReadOnlyMemory<byte> B { get; }

    /// <summary>The precomputed <c>3·b mod p</c> constant, canonical big-endian.</summary>
    public ReadOnlyMemory<byte> BTimes3 { get; }

    /// <summary>The generator's affine x coordinate, canonical big-endian.</summary>
    public ReadOnlyMemory<byte> GeneratorX { get; }

    /// <summary>The generator's affine y coordinate, canonical big-endian.</summary>
    public ReadOnlyMemory<byte> GeneratorY { get; }

    /// <summary>The group order <c>n</c>, canonical big-endian.</summary>
    public ReadOnlyMemory<byte> Order { get; }

    /// <summary>The scalar bit count (the reference's <c>kBits</c>).</summary>
    public int ScalarBitCount { get; }


    /// <summary>
    /// Constructs the bundle from already-reduced canonical constants. Prefer
    /// <see cref="CreateP256"/>.
    /// </summary>
    /// <param name="a">The curve coefficient <c>a</c>.</param>
    /// <param name="b">The curve coefficient <c>b</c>.</param>
    /// <param name="bTimes3">The precomputed <c>3·b mod p</c>.</param>
    /// <param name="generatorX">The generator's affine x coordinate.</param>
    /// <param name="generatorY">The generator's affine y coordinate.</param>
    /// <param name="order">The group order.</param>
    /// <param name="scalarBitCount">The scalar bit count.</param>
    /// <param name="pool">The pool supplying independent owned copies of all input constants.</param>
    /// <exception cref="ArgumentException">When a constant is not exactly <see cref="Scalar.SizeBytes"/> bytes.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="scalarBitCount"/> is not positive or exceeds the order's bit capacity.</exception>
    public LongfellowEllipticCurveParameters(
        ReadOnlyMemory<byte> a,
        ReadOnlyMemory<byte> b,
        ReadOnlyMemory<byte> bTimes3,
        ReadOnlyMemory<byte> generatorX,
        ReadOnlyMemory<byte> generatorY,
        ReadOnlyMemory<byte> order,
        int scalarBitCount,
        BaseMemoryPool pool)
    {
        if(a.Length != Scalar.SizeBytes || b.Length != Scalar.SizeBytes || bTimes3.Length != Scalar.SizeBytes
            || generatorX.Length != Scalar.SizeBytes || generatorY.Length != Scalar.SizeBytes || order.Length != Scalar.SizeBytes)
        {
            throw new ArgumentException($"Curve constants are canonical {Scalar.SizeBytes}-byte scalars.");
        }

        ArgumentOutOfRangeException.ThrowIfLessThan(scalarBitCount, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(scalarBitCount, Scalar.SizeBytes * 8);

        ScalarBitCount = scalarBitCount;
        Storage = new LongfellowCircuitStorage(pool);
        try
        {
            A = Storage.Copy(a.Span);
            B = Storage.Copy(b.Span);
            BTimes3 = Storage.Copy(bTimes3.Span);
            GeneratorX = Storage.Copy(generatorX.Span);
            GeneratorY = Storage.Copy(generatorY.Span);
            Order = Storage.Copy(order.Span);
        }
        catch
        {
            Storage.Dispose();
            throw;
        }
    }


    /// <summary>
    /// The NIST P-256 constants (the reference's <c>p256.cc</c>): <c>a = p − 3</c>, the SEC2
    /// coefficient <c>b</c>, its tripled Renes–Costello–Batina form, the SEC2 generator, and the
    /// group order.
    /// </summary>
    /// <param name="pool">The pool supplying the constants and their parsing workspace.</param>
    /// <returns>The disposable P-256 bundle.</returns>
    public static LongfellowEllipticCurveParameters CreateP256(BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        using IMemoryOwner<byte> owner = pool.Rent(ConstantCount * Scalar.SizeBytes);
        Span<byte> buffer = owner.Memory.Span[..(ConstantCount * Scalar.SizeBytes)];
        FromHex("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", buffer.Slice(0 * Scalar.SizeBytes, Scalar.SizeBytes));
        FromHex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", buffer.Slice(1 * Scalar.SizeBytes, Scalar.SizeBytes));
        FromHex("1052a18afeafbbb61bc3380063c994352f57141164fb12e2b36ab4ba777720e2", buffer.Slice(2 * Scalar.SizeBytes, Scalar.SizeBytes));
        FromHex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", buffer.Slice(3 * Scalar.SizeBytes, Scalar.SizeBytes));
        FromHex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", buffer.Slice(4 * Scalar.SizeBytes, Scalar.SizeBytes));
        FromHex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", buffer.Slice(5 * Scalar.SizeBytes, Scalar.SizeBytes));

        return new LongfellowEllipticCurveParameters(
            owner.Memory.Slice(0 * Scalar.SizeBytes, Scalar.SizeBytes),
            owner.Memory.Slice(1 * Scalar.SizeBytes, Scalar.SizeBytes),
            owner.Memory.Slice(2 * Scalar.SizeBytes, Scalar.SizeBytes),
            owner.Memory.Slice(3 * Scalar.SizeBytes, Scalar.SizeBytes),
            owner.Memory.Slice(4 * Scalar.SizeBytes, Scalar.SizeBytes),
            owner.Memory.Slice(5 * Scalar.SizeBytes, Scalar.SizeBytes),
            Scalar.SizeBytes * 8, pool);
    }


    /// <summary>
    /// Reads bit <paramref name="index"/> of <see cref="Order"/>, least significant bit first (the
    /// reference's <c>order.bit(i)</c> the verify circuit builds <c>bits_n_</c> from).
    /// </summary>
    /// <param name="index">The bit index.</param>
    /// <returns>The bit.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="index"/> is outside the scalar bit range.</exception>
    public int OrderBit(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(index, ScalarBitCount);

        return (Order.Span[Scalar.SizeBytes - 1 - (index / 8)] >> (index % 8)) & 1;
    }


    /// <summary>Parses a 64-character hex constant into its canonical big-endian form.</summary>
    /// <param name="hex">The hex constant.</param>
    /// <param name="destination">Receives the canonical scalar.</param>
    private static void FromHex(string hex, Span<byte> destination)
    {
        for(int i = 0; i < Scalar.SizeBytes; i++)
        {
            destination[i] = byte.Parse(hex.AsSpan(2 * i, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        }
    }

    /// <summary>Clears and releases every constant. Repeated disposal has no effect.</summary>
    public void Dispose()
    {
        Storage.Dispose();
    }
}
