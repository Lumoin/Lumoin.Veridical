using System;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The reduction <c>e = 1 + (x mod (q − 1))</c> of Verheul Algorithm 22 step 4 and Algorithm 23 step 8, where
/// <c>x</c> is the big-endian integer in the derived <c>|q| + 8</c> bytes and <c>q</c> is the P-256 group order. The
/// extra 8 bytes make the bias of the reduction negligible; adding 1 keeps the key in <c>[1, q − 1]</c>.
/// </summary>
/// <remarks>
/// The ephemeral keys are secret, so the reduction runs in time that depends only on the input length: it
/// shifts the input in bit by bit and subtracts the modulus under a mask, with no branch or table index on a
/// secret value.
/// </remarks>
internal static class P256SeededKeyReduction
{
    /// <summary>The number of derived bytes the reduction consumes: <c>|q| + 8</c>.</summary>
    internal const int WideSizeBytes = P256ScalarSizeBytes + 8;

    private const int P256ScalarSizeBytes = 32;

    //The accumulator is one byte wider than a scalar because 2·acc + 1 can reach 2^257 - 1 before the subtraction.
    private const int AccumulatorSizeBytes = P256ScalarSizeBytes + 1;


    /// <summary>Reduces <see cref="WideSizeBytes"/> derived bytes to a key in <c>[1, q − 1]</c>.</summary>
    /// <param name="wide">The derived bytes, big-endian.</param>
    /// <param name="key">Receives the 32-byte big-endian key.</param>
    /// <exception cref="ArgumentException">When a span has the wrong length.</exception>
    internal static void Reduce(ReadOnlySpan<byte> wide, Span<byte> key)
    {
        if(wide.Length != WideSizeBytes)
        {
            throw new ArgumentException($"Expected {WideSizeBytes} bytes; received {wide.Length}.", nameof(wide));
        }

        if(key.Length != P256ScalarSizeBytes)
        {
            throw new ArgumentException($"Expected {P256ScalarSizeBytes} bytes; received {key.Length}.", nameof(key));
        }

        //The modulus is q - 1 with a leading zero byte; the last byte of q is nonzero, so the decrement does not borrow.
        Span<byte> modulus = stackalloc byte[AccumulatorSizeBytes];
        Span<byte> accumulator = stackalloc byte[AccumulatorSizeBytes];
        Span<byte> difference = stackalloc byte[AccumulatorSizeBytes];
        P256ScalarValidation.OrderBytes.CopyTo(modulus[1..]);
        modulus[AccumulatorSizeBytes - 1]--;
        accumulator.Clear();
        try
        {
            for(int index = 0; index < wide.Length; index++)
            {
                for(int bit = 7; bit >= 0; bit--)
                {
                    //accumulator = 2·accumulator + incoming bit.
                    int carry = (wide[index] >> bit) & 1;
                    for(int position = AccumulatorSizeBytes - 1; position >= 0; position--)
                    {
                        int doubled = (accumulator[position] << 1) | carry;
                        accumulator[position] = (byte)doubled;
                        carry = doubled >> 8;
                    }

                    //difference = accumulator - modulus; the final borrow says whether the accumulator was smaller.
                    int borrow = 0;
                    for(int position = AccumulatorSizeBytes - 1; position >= 0; position--)
                    {
                        int subtracted = accumulator[position] - modulus[position] - borrow;
                        difference[position] = (byte)subtracted;
                        borrow = (subtracted >> 8) & 1;
                    }

                    //Keep the accumulator when it was smaller than the modulus, otherwise take the difference.
                    int keep = 0 - borrow;
                    for(int position = 0; position < AccumulatorSizeBytes; position++)
                    {
                        accumulator[position] = (byte)((accumulator[position] & keep) | (difference[position] & ~keep));
                    }
                }
            }

            //key = accumulator + 1; the accumulator is below q - 1, so the sum is at most q - 1 and cannot overflow.
            int increment = 1;
            for(int position = P256ScalarSizeBytes - 1; position >= 0; position--)
            {
                int sum = accumulator[position + 1] + increment;
                key[position] = (byte)sum;
                increment = sum >> 8;
            }
        }
        finally
        {
            accumulator.Clear();
            difference.Clear();
        }
    }
}
