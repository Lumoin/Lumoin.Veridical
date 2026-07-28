using System;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;

/// <summary>
/// Shifts an array by a wire-valued amount, a faithful port of google/longfellow-zk's
/// <c>Routing&lt;Logic&gt;</c> (<c>circuits/logic/routing.h</c>): a barrel shifter that consumes the
/// amount's bits over one or more rounds, materializing for each round the equality selectors
/// <c>amount_is[j]</c> against every candidate residue and muxing each output lane through them.
/// <see cref="Shift(LongfellowBitWire[], LongfellowBitWire[], LongfellowBitWire[], LongfellowBitWire, int)"/>
/// reads <c>destination[i] = source[i + amount]</c> and its <c>Unshift</c> mirror writes
/// <c>destination[i + amount] = source[i]</c>, both falling back to the default value outside the
/// source, with the amount implicitly reduced modulo two to the power of its bit width.
/// </summary>
/// <remarks>
/// The <c>unroll</c> parameter trades rounds for selector fan-in exactly as the reference does: the
/// round count is the ceiling of the amount width over <c>unroll</c>, and the per-round consumed bit
/// counts are equalized (the reference's <c>(target_nrounds, consumed)</c> schedule) rather than
/// greedily taking <c>unroll</c> bits until the residue runs short. Rounds consume the amount's
/// high-order bits first for <c>Shift</c> and low-order first for <c>Unshift</c>, which the
/// reference chose so a caller wanting only a contiguous output prefix pays wires proportional to
/// that prefix.
/// </remarks>
internal sealed class LongfellowRouting
{
    //The reference's own size table stops at ten amount bits and an unroll of eight, and each round
    //materializes two-to-the-consumed-bits equality selectors; the caps keep a hostile shape from
    //driving an exponential selector allocation.
    private const int MaxAmountBitWidth = 16;
    private const int MaxUnrollBitCount = 8;

    private readonly LongfellowLogic logic;


    /// <summary>
    /// Constructs the gadget over a gadget layer.
    /// </summary>
    /// <param name="logic">The gadget layer every selector and mux builds on.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="logic"/> is <see langword="null"/>.</exception>
    public LongfellowRouting(LongfellowLogic logic)
    {
        ArgumentNullException.ThrowIfNull(logic);

        this.logic = logic;
    }


    /// <summary>
    /// The reference's <c>shift</c> over element wires: sets <c>destination[i] =
    /// source[i + amount]</c> for every destination index, reading the default value beyond the
    /// source's end.
    /// </summary>
    /// <param name="amount">The shift amount's bits, least significant first.</param>
    /// <param name="destination">Receives the shifted lanes.</param>
    /// <param name="source">The lanes to shift.</param>
    /// <param name="defaultValue">The wire read in place of any source index past the end.</param>
    /// <param name="unroll">The per-round amount-bit budget.</param>
    public void Shift(LongfellowBitWire[] amount, int[] destination, int[] source, int defaultValue, int unroll)
    {
        GuardShape(amount, destination, source, unroll);

        var temporary = new int[source.Length];
        Array.Copy(source, temporary, source.Length);

        RunShiftRounds(amount, unroll, (consumed, offset, shift) =>
        {
            LongfellowBitWire[] selectors = AmountSelectors(amount, offset, consumed);
            ReallyShift(selectors, temporary, destination.Length, shift, defaultValue);
        });

        for(int i = 0; i < destination.Length; i++)
        {
            destination[i] = i < temporary.Length ? temporary[i] : defaultValue;
        }
    }


    /// <summary>
    /// The reference's <c>shift</c> over single-bit lanes: sets <c>destination[i] =
    /// source[i + amount]</c> for every destination index, reading the default value beyond the
    /// source's end.
    /// </summary>
    /// <param name="amount">The shift amount's bits, least significant first.</param>
    /// <param name="destination">Receives the shifted lanes.</param>
    /// <param name="source">The lanes to shift.</param>
    /// <param name="defaultValue">The bit read in place of any source index past the end.</param>
    /// <param name="unroll">The per-round amount-bit budget.</param>
    public void Shift(LongfellowBitWire[] amount, LongfellowBitWire[] destination, LongfellowBitWire[] source, LongfellowBitWire defaultValue, int unroll)
    {
        GuardShape(amount, destination, source, unroll);

        var temporary = new LongfellowBitWire[source.Length];
        Array.Copy(source, temporary, source.Length);

        RunShiftRounds(amount, unroll, (consumed, offset, shift) =>
        {
            LongfellowBitWire[] selectors = AmountSelectors(amount, offset, consumed);
            ReallyShift(selectors, temporary, destination.Length, shift, defaultValue);
        });

        for(int i = 0; i < destination.Length; i++)
        {
            destination[i] = i < temporary.Length ? temporary[i] : defaultValue;
        }
    }


    /// <summary>
    /// The reference's <c>shift</c> over bit-vector lanes: sets <c>destination[i] =
    /// source[i + amount]</c> for every destination index, reading the default value beyond the
    /// source's end. Lane arrays are mutated in place bit by bit, so the destination entries must be
    /// distinct arrays the caller owns.
    /// </summary>
    /// <param name="amount">The shift amount's bits, least significant first.</param>
    /// <param name="destination">Receives the shifted lanes.</param>
    /// <param name="source">The lanes to shift.</param>
    /// <param name="defaultValue">The bit vector read in place of any source index past the end.</param>
    /// <param name="unroll">The per-round amount-bit budget.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="defaultValue"/> is <see langword="null"/>.</exception>
    public void Shift(LongfellowBitWire[] amount, LongfellowBitWire[][] destination, LongfellowBitWire[][] source, LongfellowBitWire[] defaultValue, int unroll)
    {
        GuardShape(amount, destination, source, unroll);
        ArgumentNullException.ThrowIfNull(defaultValue);

        var temporary = new LongfellowBitWire[source.Length][];
        for(int i = 0; i < source.Length; i++)
        {
            temporary[i] = (LongfellowBitWire[])source[i].Clone();
        }

        RunShiftRounds(amount, unroll, (consumed, offset, shift) =>
        {
            LongfellowBitWire[] selectors = AmountSelectors(amount, offset, consumed);
            ReallyShift(selectors, temporary, destination.Length, shift, defaultValue);
        });

        for(int i = 0; i < destination.Length; i++)
        {
            LongfellowBitWire[] value = i < temporary.Length ? temporary[i] : defaultValue;
            Array.Copy(value, destination[i], destination[i].Length);
        }
    }


    /// <summary>
    /// The reference's <c>unshift</c> over element wires: sets <c>destination[i + amount] =
    /// source[i]</c> for every source index, writing the default value everywhere else.
    /// </summary>
    /// <param name="amount">The shift amount's bits, least significant first.</param>
    /// <param name="destination">Receives the unshifted lanes.</param>
    /// <param name="source">The lanes to unshift.</param>
    /// <param name="defaultValue">The wire written wherever no source lane lands.</param>
    /// <param name="unroll">The per-round amount-bit budget.</param>
    public void Unshift(LongfellowBitWire[] amount, int[] destination, int[] source, int defaultValue, int unroll)
    {
        GuardShape(amount, destination, source, unroll);

        for(int i = 0; i < destination.Length; i++)
        {
            destination[i] = i < source.Length ? source[i] : defaultValue;
        }

        RunUnshiftRounds(amount, unroll, (consumed, offset, shift) =>
        {
            LongfellowBitWire[] selectors = AmountSelectors(amount, offset, consumed);
            ReallyUnshift(selectors, destination, source.Length, shift, defaultValue);
        });
    }


    /// <summary>
    /// The reference's <c>unshift</c> over single-bit lanes: sets <c>destination[i + amount] =
    /// source[i]</c> for every source index, writing the default value everywhere else.
    /// </summary>
    /// <param name="amount">The shift amount's bits, least significant first.</param>
    /// <param name="destination">Receives the unshifted lanes.</param>
    /// <param name="source">The lanes to unshift.</param>
    /// <param name="defaultValue">The bit written wherever no source lane lands.</param>
    /// <param name="unroll">The per-round amount-bit budget.</param>
    public void Unshift(LongfellowBitWire[] amount, LongfellowBitWire[] destination, LongfellowBitWire[] source, LongfellowBitWire defaultValue, int unroll)
    {
        GuardShape(amount, destination, source, unroll);

        for(int i = 0; i < destination.Length; i++)
        {
            destination[i] = i < source.Length ? source[i] : defaultValue;
        }

        RunUnshiftRounds(amount, unroll, (consumed, offset, shift) =>
        {
            LongfellowBitWire[] selectors = AmountSelectors(amount, offset, consumed);
            ReallyUnshift(selectors, destination, source.Length, shift, defaultValue);
        });
    }


    /// <summary>
    /// The reference's <c>unshift</c> over bit-vector lanes: sets <c>destination[i + amount] =
    /// source[i]</c> for every source index, writing the default value everywhere else. Lane arrays
    /// are mutated in place bit by bit, so the destination entries must be distinct arrays the
    /// caller owns.
    /// </summary>
    /// <param name="amount">The shift amount's bits, least significant first.</param>
    /// <param name="destination">Receives the unshifted lanes.</param>
    /// <param name="source">The lanes to unshift.</param>
    /// <param name="defaultValue">The bit vector written wherever no source lane lands.</param>
    /// <param name="unroll">The per-round amount-bit budget.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="defaultValue"/> is <see langword="null"/>.</exception>
    public void Unshift(LongfellowBitWire[] amount, LongfellowBitWire[][] destination, LongfellowBitWire[][] source, LongfellowBitWire[] defaultValue, int unroll)
    {
        GuardShape(amount, destination, source, unroll);
        ArgumentNullException.ThrowIfNull(defaultValue);

        for(int i = 0; i < destination.Length; i++)
        {
            LongfellowBitWire[] value = i < source.Length ? source[i] : defaultValue;
            Array.Copy(value, destination[i], destination[i].Length);
        }

        RunUnshiftRounds(amount, unroll, (consumed, offset, shift) =>
        {
            LongfellowBitWire[] selectors = AmountSelectors(amount, offset, consumed);
            ReallyUnshift(selectors, destination, source.Length, shift, defaultValue);
        });
    }


    /// <summary>
    /// Runs the reference's descending round schedule for <c>shift</c>: rounds consume the
    /// high-order amount bits first, with per-round consumption equalized over the remaining
    /// rounds, invoking <paramref name="round"/> with each round's consumed bit count, the amount
    /// offset it starts at, and the lane stride two to the power of the bits still unconsumed.
    /// </summary>
    /// <param name="amount">The shift amount's bits, least significant first.</param>
    /// <param name="unroll">The per-round amount-bit budget.</param>
    /// <param name="round">The per-round muxing step.</param>
    private static void RunShiftRounds(LongfellowBitWire[] amount, int unroll, Action<int, int, int> round)
    {
        int remaining = amount.Length;
        int targetRounds = CeilingDivide(amount.Length, unroll);
        while(targetRounds > 0)
        {
            int consumed = CeilingDivide(remaining, targetRounds);
            targetRounds--;

            remaining -= consumed;
            int shift = 1 << remaining;
            round(consumed, remaining, shift);
        }
    }


    /// <summary>
    /// Runs the reference's ascending round schedule for <c>unshift</c>: rounds consume the
    /// low-order amount bits first, with per-round consumption equalized over the remaining rounds.
    /// </summary>
    /// <param name="amount">The shift amount's bits, least significant first.</param>
    /// <param name="unroll">The per-round amount-bit budget.</param>
    /// <param name="round">The per-round muxing step.</param>
    private static void RunUnshiftRounds(LongfellowBitWire[] amount, int unroll, Action<int, int, int> round)
    {
        int consumedSoFar = 0;
        int targetRounds = CeilingDivide(amount.Length, unroll);
        while(targetRounds > 0)
        {
            int consumed = CeilingDivide(amount.Length - consumedSoFar, targetRounds);
            targetRounds--;

            int shift = 1 << consumedSoFar;
            round(consumed, consumedSoFar, shift);

            consumedSoFar += consumed;
        }
    }


    /// <summary>
    /// The selector cache both step kinds share: for every candidate residue of the consumed bits,
    /// the equality of that residue's constant bit pattern against the amount slice, in the
    /// reference's argument order (constants first).
    /// </summary>
    /// <param name="amount">The shift amount's bits, least significant first.</param>
    /// <param name="offset">The first amount bit this round consumes.</param>
    /// <param name="consumed">The consumed bit count.</param>
    /// <returns>The selector bits, indexed by candidate residue.</returns>
    private LongfellowBitWire[] AmountSelectors(LongfellowBitWire[] amount, int offset, int consumed)
    {
        var slice = new LongfellowBitWire[consumed];
        Array.Copy(amount, offset, slice, 0, consumed);

        int candidateCount = 1 << consumed;
        var selectors = new LongfellowBitWire[candidateCount];
        var residueBits = new LongfellowBitWire[consumed];
        for(int i = 0; i < candidateCount; i++)
        {
            logic.Bits(residueBits, (ulong)i);
            selectors[i] = logic.Equal(residueBits, slice);
        }

        return selectors;
    }


    /// <summary>The reference's element-wire <c>really_shift</c>: muxes each surviving lane through the selectors with a ranged fold of bit-scaled terms.</summary>
    /// <param name="selectors">The selector bits, indexed by candidate residue.</param>
    /// <param name="temporary">The in-place lane buffer.</param>
    /// <param name="destinationCount">The destination lane count bounding the surviving prefix.</param>
    /// <param name="shift">This round's lane stride.</param>
    /// <param name="defaultValue">The wire read past the buffer's end.</param>
    private void ReallyShift(LongfellowBitWire[] selectors, int[] temporary, int destinationCount, int shift, int defaultValue)
    {
        for(int i = 0; i < temporary.Length && i < destinationCount + shift; i++)
        {
            int lane = i;
            temporary[i] = logic.Add(0, selectors.Length, j =>
            {
                long candidate = lane + ((long)j * shift);
                int value = candidate < temporary.Length ? temporary[(int)candidate] : defaultValue;

                return logic.Multiply(selectors[j], value);
            });
        }
    }


    /// <summary>The reference's element-wire <c>really_unshift</c>: muxes each lane downward through the selectors with a ranged fold of bit-scaled terms.</summary>
    /// <param name="selectors">The selector bits, indexed by candidate residue.</param>
    /// <param name="destination">The in-place lane buffer.</param>
    /// <param name="sourceCount">The source lane count bounding the live region.</param>
    /// <param name="shift">This round's lane stride.</param>
    /// <param name="defaultValue">The wire read below the buffer's start.</param>
    private void ReallyUnshift(LongfellowBitWire[] selectors, int[] destination, int sourceCount, int shift, int defaultValue)
    {
        long ceiling = Math.Min(destination.Length, sourceCount + ((long)selectors.Length * shift));
        for(long i = ceiling - 1; i >= 0; i--)
        {
            long lane = i;
            destination[i] = logic.Add(0, selectors.Length, j =>
            {
                long candidate = lane - ((long)j * shift);
                int value = candidate >= 0 ? destination[(int)candidate] : defaultValue;

                return logic.Multiply(selectors[j], value);
            });
        }
    }


    /// <summary>The reference's single-bit <c>really_shift</c>: muxes each surviving lane through the selectors with an exclusive-or accumulation of conjunctions.</summary>
    /// <param name="selectors">The selector bits, indexed by candidate residue.</param>
    /// <param name="temporary">The in-place lane buffer.</param>
    /// <param name="destinationCount">The destination lane count bounding the surviving prefix.</param>
    /// <param name="shift">This round's lane stride.</param>
    /// <param name="defaultValue">The bit read past the buffer's end.</param>
    private void ReallyShift(LongfellowBitWire[] selectors, LongfellowBitWire[] temporary, int destinationCount, int shift, LongfellowBitWire defaultValue)
    {
        for(int i = 0; i < temporary.Length && i < destinationCount + shift; i++)
        {
            LongfellowBitWire accumulated = logic.Bit(0);
            for(int j = 0; j < selectors.Length; j++)
            {
                long candidate = i + ((long)j * shift);
                LongfellowBitWire value = candidate < temporary.Length ? temporary[(int)candidate] : defaultValue;
                accumulated = logic.OrExclusive(accumulated, logic.And(selectors[j], value));
            }

            temporary[i] = accumulated;
        }
    }


    /// <summary>The reference's single-bit <c>really_unshift</c>: muxes each lane downward through the selectors with an exclusive-or accumulation of conjunctions.</summary>
    /// <param name="selectors">The selector bits, indexed by candidate residue.</param>
    /// <param name="destination">The in-place lane buffer.</param>
    /// <param name="sourceCount">The source lane count bounding the live region.</param>
    /// <param name="shift">This round's lane stride.</param>
    /// <param name="defaultValue">The bit read below the buffer's start.</param>
    private void ReallyUnshift(LongfellowBitWire[] selectors, LongfellowBitWire[] destination, int sourceCount, int shift, LongfellowBitWire defaultValue)
    {
        long ceiling = Math.Min(destination.Length, sourceCount + ((long)selectors.Length * shift));
        for(long i = ceiling - 1; i >= 0; i--)
        {
            LongfellowBitWire accumulated = logic.Bit(0);
            for(int j = 0; j < selectors.Length; j++)
            {
                long candidate = i - ((long)j * shift);
                LongfellowBitWire value = candidate >= 0 ? destination[(int)candidate] : defaultValue;
                accumulated = logic.OrExclusive(accumulated, logic.And(selectors[j], value));
            }

            destination[i] = accumulated;
        }
    }


    /// <summary>The reference's bit-vector <c>really_shift</c>: the single-bit mux applied lane-wise per vector position.</summary>
    /// <param name="selectors">The selector bits, indexed by candidate residue.</param>
    /// <param name="temporary">The in-place lane buffer.</param>
    /// <param name="destinationCount">The destination lane count bounding the surviving prefix.</param>
    /// <param name="shift">This round's lane stride.</param>
    /// <param name="defaultValue">The bit vector read past the buffer's end.</param>
    private void ReallyShift(LongfellowBitWire[] selectors, LongfellowBitWire[][] temporary, int destinationCount, int shift, LongfellowBitWire[] defaultValue)
    {
        for(int i = 0; i < temporary.Length && i < destinationCount + shift; i++)
        {
            for(int w = 0; w < defaultValue.Length; w++)
            {
                LongfellowBitWire accumulated = logic.Bit(0);
                for(int j = 0; j < selectors.Length; j++)
                {
                    long candidate = i + ((long)j * shift);
                    LongfellowBitWire value = candidate < temporary.Length ? temporary[(int)candidate][w] : defaultValue[w];
                    accumulated = logic.OrExclusive(accumulated, logic.And(selectors[j], value));
                }

                temporary[i][w] = accumulated;
            }
        }
    }


    /// <summary>The reference's bit-vector <c>really_unshift</c>: the single-bit downward mux applied lane-wise per vector position.</summary>
    /// <param name="selectors">The selector bits, indexed by candidate residue.</param>
    /// <param name="destination">The in-place lane buffer.</param>
    /// <param name="sourceCount">The source lane count bounding the live region.</param>
    /// <param name="shift">This round's lane stride.</param>
    /// <param name="defaultValue">The bit vector read below the buffer's start.</param>
    private void ReallyUnshift(LongfellowBitWire[] selectors, LongfellowBitWire[][] destination, int sourceCount, int shift, LongfellowBitWire[] defaultValue)
    {
        long ceiling = Math.Min(destination.Length, sourceCount + ((long)selectors.Length * shift));
        for(long i = ceiling - 1; i >= 0; i--)
        {
            for(int w = 0; w < defaultValue.Length; w++)
            {
                LongfellowBitWire accumulated = logic.Bit(0);
                for(int j = 0; j < selectors.Length; j++)
                {
                    long candidate = i - ((long)j * shift);
                    LongfellowBitWire value = candidate >= 0 ? destination[(int)candidate][w] : defaultValue[w];
                    accumulated = logic.OrExclusive(accumulated, logic.And(selectors[j], value));
                }

                destination[i][w] = accumulated;
            }
        }
    }


    /// <summary>Validates the shared shift/unshift shape bounds.</summary>
    /// <param name="amount">The shift amount's bits.</param>
    /// <param name="destination">The destination lanes.</param>
    /// <param name="source">The source lanes.</param>
    /// <param name="unroll">The per-round amount-bit budget.</param>
    /// <exception cref="ArgumentNullException">When any array is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When the amount is wider than the cap or <paramref name="unroll"/> is outside its bounds.</exception>
    private static void GuardShape(LongfellowBitWire[] amount, Array destination, Array source, int unroll)
    {
        ArgumentNullException.ThrowIfNull(amount);
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentNullException.ThrowIfNull(source);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(amount.Length, MaxAmountBitWidth);
        ArgumentOutOfRangeException.ThrowIfLessThan(unroll, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(unroll, MaxUnrollBitCount);
    }


    /// <summary>The ceiling of <paramref name="numerator"/> divided by <paramref name="denominator"/> (the reference's <c>ceildiv</c>).</summary>
    /// <param name="numerator">The numerator.</param>
    /// <param name="denominator">The denominator.</param>
    /// <returns>The ceiling quotient.</returns>
    private static int CeilingDivide(int numerator, int denominator)
    {
        return (numerator + denominator - 1) / denominator;
    }
}
