using System;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;

namespace Lumoin.Veridical.Hashing.Internal;

/// <summary>
/// Portable scalar implementation of the SHA-256 block-compression
/// function. Mirrors FIPS 180-4 Section 6.2.2: expand the sixteen
/// big-endian message words into a sixty-four word schedule, run sixty-four
/// rounds with the eight working variables a..h and the round constants
/// <see cref="Sha256Constants.K"/>, then add the working variables back into
/// the chaining state.
/// </summary>
/// <remarks>
/// <para>
/// This is the correctness reference for every other SHA-256 backend. A
/// future SHA-NI / AArch64 backend implements the same
/// <see cref="Sha256CompressionDelegate"/> and is agreement-tested against
/// this baseline.
/// </para>
/// <para>
/// The implementation is pure managed C# — no <c>unsafe</c>, no platform
/// intrinsics, no P/Invoke — so it runs unchanged under AOT and in a browser
/// via WebAssembly. The eight working variables are held in
/// <see langword="ref"/> locals and passed between <see cref="Round"/> and
/// the caller so the JIT keeps them in registers across the sixty-four
/// rounds, the same register-residency strategy
/// <see cref="Blake3PortableBackend"/> uses for its state words.
/// </para>
/// </remarks>
internal static class Sha256PortableBackend
{
    /// <summary>Returns the portable compression delegate.</summary>
    public static Sha256CompressionDelegate GetCompression() => Compress;


    /// <summary>Returns the full portable backend bundle.</summary>
    public static Sha256Backend GetBackend() => new(GetCompression());


    /// <summary>
    /// Portable single-block compression. The eight chaining-state words
    /// and the eight working variables a..h are held in local
    /// <see cref="uint"/> variables so the JIT can keep them in CPU
    /// registers across the sixty-four rounds. The message schedule is a
    /// stack-local span, expanded once per block.
    /// </summary>
    private static void Compress(Span<uint> state8, ReadOnlySpan<byte> block64)
    {
        ReadOnlySpan<uint> k = Sha256Constants.K;

        //Expand the sixteen big-endian message words into the sixty-four
        //word schedule. W[0..16) are the raw big-endian block words; the
        //remainder fold the lower-sigma functions over earlier words.
        Span<uint> w = stackalloc uint[Sha256Constants.ScheduleWords];
        for(int t = 0; t < Sha256Constants.BlockWords; t++)
        {
            w[t] = BinaryPrimitives.ReadUInt32BigEndian(
                block64.Slice(start: t * Sha256Constants.WordSizeBytes, length: Sha256Constants.WordSizeBytes));
        }

        for(int t = Sha256Constants.BlockWords; t < Sha256Constants.ScheduleWords; t++)
        {
            w[t] = unchecked(LowerSigma1(w[t - 2]) + w[t - 7] + LowerSigma0(w[t - 15]) + w[t - 16]);
        }

        uint a = state8[0];
        uint b = state8[1];
        uint c = state8[2];
        uint d = state8[3];
        uint e = state8[4];
        uint f = state8[5];
        uint g = state8[6];
        uint h = state8[7];

        for(int t = 0; t < Sha256Constants.ScheduleWords; t++)
        {
            Round(ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, k[t], w[t]);
        }

        state8[0] = unchecked(state8[0] + a);
        state8[1] = unchecked(state8[1] + b);
        state8[2] = unchecked(state8[2] + c);
        state8[3] = unchecked(state8[3] + d);
        state8[4] = unchecked(state8[4] + e);
        state8[5] = unchecked(state8[5] + f);
        state8[6] = unchecked(state8[6] + g);
        state8[7] = unchecked(state8[7] + h);
    }


    /// <summary>
    /// One SHA-256 round operating on the eight working variables a..h held
    /// in <see langword="ref"/> locals, mixing in one round constant and one
    /// schedule word. The variables rotate down by one position
    /// (h&lt;-g&lt;-f&lt;-e..., a&lt;-T1+T2) without copying the whole bank.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Round(
        ref uint a,
        ref uint b,
        ref uint c,
        ref uint d,
        ref uint e,
        ref uint f,
        ref uint g,
        ref uint h,
        uint kt,
        uint wt)
    {
        uint t1 = unchecked(h + UpperSigma1(e) + Choose(e, f, g) + kt + wt);
        uint t2 = unchecked(UpperSigma0(a) + Majority(a, b, c));

        h = g;
        g = f;
        f = e;
        e = unchecked(d + t1);
        d = c;
        c = b;
        b = a;
        a = unchecked(t1 + t2);
    }


    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint Choose(uint x, uint y, uint z) => (x & y) ^ (~x & z);


    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint Majority(uint x, uint y, uint z) => (x & y) ^ (x & z) ^ (y & z);


    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint UpperSigma0(uint x) =>
        BitOperations.RotateRight(x, 2) ^ BitOperations.RotateRight(x, 13) ^ BitOperations.RotateRight(x, 22);


    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint UpperSigma1(uint x) =>
        BitOperations.RotateRight(x, 6) ^ BitOperations.RotateRight(x, 11) ^ BitOperations.RotateRight(x, 25);


    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint LowerSigma0(uint x) =>
        BitOperations.RotateRight(x, 7) ^ BitOperations.RotateRight(x, 18) ^ (x >> 3);


    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint LowerSigma1(uint x) =>
        BitOperations.RotateRight(x, 17) ^ BitOperations.RotateRight(x, 19) ^ (x >> 10);
}
