using Lumoin.Veridical.Backends.Managed;
using System;

namespace Lumoin.Veridical.Longfellow;

/// <summary>
/// Checks a supplier of prover randomness can run against its own source and against pre-sampled
/// field elements, for example from a unit test. Comparisons over secret-derived bytes are constant time.
/// </summary>
public static class LongfellowRandomnessChecks
{
    //A P-256 base-field element is 32 big-endian bytes.
    private const int FieldElementBytes = 32;

    //Bit position of the sign bit of a 32-bit difference, which carries the borrow of a byte subtraction.
    private const int BorrowShift = 31;

    //The two draws the source check compares, each one field element wide.
    private const int ProbeDrawBytes = FieldElementBytes;

    private static byte[] BaseFieldPrimeBytes { get; } = BuildBaseFieldPrimeBytes();


    extension(ReadOnlySpan<byte> value)
    {
        /// <summary>
        /// Whether the value is exactly 32 bytes and, read big-endian, a canonical P-256 base-field
        /// element, that is strictly below the field prime. The comparison runs over every byte with no
        /// data-dependent branch; only the length is checked early.
        /// </summary>
        /// <returns><see langword="true"/> when the value is a canonical element.</returns>
        public bool IsBelowP256BaseFieldPrime()
        {
            if(value.Length != FieldElementBytes)
            {
                return false;
            }

            //value - prime with borrow propagation from the least significant byte; a final borrow
            //means value < prime.
            int borrow = 0;
            for(int i = FieldElementBytes - 1; i >= 0; i--)
            {
                int difference = value[i] - BaseFieldPrimeBytes[i] - borrow;
                borrow = (int)((uint)difference >> BorrowShift);
            }

            return borrow == 1;
        }


        /// <summary>
        /// Whether at least one byte of the value is non-zero. The scan covers every byte regardless of
        /// content. An empty value is all zero.
        /// </summary>
        /// <returns><see langword="true"/> when some byte is non-zero.</returns>
        public bool IsNotAllZero()
        {
            int accumulated = 0;
            for(int i = 0; i < value.Length; i++)
            {
                accumulated |= value[i];
            }

            return accumulated != 0;
        }
    }


    extension(LongfellowEntropyDelegate source)
    {
        /// <summary>
        /// Draws two blocks from the source and checks the degenerate failures: each block is not
        /// all zero and the two blocks differ. A healthy secure generator fails this with negligible
        /// probability; a stuck, zero or repeating source fails it at once. It is a smoke test, not a
        /// proof of randomness.
        /// </summary>
        /// <returns><see langword="true"/> when both draws are non-zero and distinct.</returns>
        public bool ProducesDistinctNonZeroDraws()
        {
            ArgumentNullException.ThrowIfNull(source);

            Span<byte> first = stackalloc byte[ProbeDrawBytes];
            Span<byte> second = stackalloc byte[ProbeDrawBytes];
            source(first);
            source(second);

            int difference = 0;
            for(int i = 0; i < ProbeDrawBytes; i++)
            {
                difference |= first[i] ^ second[i];
            }

            ReadOnlySpan<byte> firstDraw = first;
            ReadOnlySpan<byte> secondDraw = second;
            bool distinctNonZero = firstDraw.IsNotAllZero() & secondDraw.IsNotAllZero() & (difference != 0);
            first.Clear();
            second.Clear();

            return distinctNonZero;
        }
    }


    private static byte[] BuildBaseFieldPrimeBytes()
    {
        byte[] canonical = new byte[FieldElementBytes];
        _ = P256BigIntegerG1Reference.BaseFieldPrime.TryWriteBytes(canonical, out _, isUnsigned: true, isBigEndian: true);

        return canonical;
    }
}
