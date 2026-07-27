using System;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;

/// <summary>
/// In-circuit evaluation of a polynomial given by its monomial coefficients, a faithful port of
/// google/longfellow-zk's <c>Polynomial&lt;Logic&gt;</c> (<c>circuits/logic/polynomial.h</c>). A
/// <see cref="LongfellowBitPlucker"/> or an element muxer gadget interpolates the coefficients once at
/// construction time and evaluates them here at every use.
/// </summary>
/// <remarks>
/// <see cref="PowersOfX"/> and <see cref="Evaluate"/> together are the reference's <c>eval</c> (a dot
/// product of the evaluation point's powers with the coefficients); <see cref="EvaluateHorner"/> is the
/// reference's <c>eval_horner</c>, a parallel Horner halving loop that is already iterative in the
/// reference and so needed no explicit-stack rewrite.
/// </remarks>
internal sealed class LongfellowCircuitPolynomial
{
    /// <summary>
    /// The Horner halving loop's pairing width (the reference's implicit binary combine of
    /// <c>c[2i]</c> and <c>c[2i + 1]</c>, and the ceiling-halving step of the outer loop).
    /// </summary>
    private const int HornerFanIn = 2;

    private readonly LongfellowLogicBackend backend;


    /// <summary>
    /// Constructs the gadget over a backend.
    /// </summary>
    /// <param name="backend">The backend every wire operation lowers to.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="backend"/> is <see langword="null"/>.</exception>
    public LongfellowCircuitPolynomial(LongfellowLogicBackend backend)
    {
        ArgumentNullException.ThrowIfNull(backend);

        this.backend = backend;
    }


    /// <summary>
    /// The reference's <c>powers_of_x</c>: fills <paramref name="destination"/> with <c>x^0, x^1, ...,
    /// x^(n − 1)</c> for <c>n = destination.Length</c>, extending the invariant <c>destination[k] =
    /// x^k</c> inductively via <c>destination[k] = destination[k − k/2] · destination[k/2]</c> instead
    /// of repeated multiplication by <paramref name="x"/>.
    /// </summary>
    /// <param name="destination">Receives the powers of <paramref name="x"/>, least significant first.</param>
    /// <param name="x">The evaluation point wire.</param>
    public void PowersOfX(Span<int> destination, int x)
    {
        int n = destination.Length;
        if(n == 0)
        {
            return;
        }

        destination[0] = backend.Constant(backend.Field.Compiler.One.Span);
        if(n == 1)
        {
            return;
        }

        destination[1] = x;
        for(int k = 2; k < n; k++)
        {
            destination[k] = backend.Mul(destination[k - (k / 2)], destination[k / 2]);
        }
    }


    /// <summary>
    /// The reference's <c>eval</c>: evaluates the polynomial with monomial coefficients
    /// <paramref name="coefficients"/> at <paramref name="x"/> via <see cref="PowersOfX"/> followed by a
    /// dot product against the coefficients.
    /// </summary>
    /// <param name="coefficients">The monomial coefficients, least significant first.</param>
    /// <param name="x">The evaluation point wire.</param>
    /// <returns>The wire holding the evaluated result.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="coefficients"/> is <see langword="null"/>.</exception>
    public int Evaluate(ReadOnlyMemory<byte>[] coefficients, int x)
    {
        ArgumentNullException.ThrowIfNull(coefficients);

        int n = coefficients.Length;
        var powers = new int[n];
        PowersOfX(powers, x);

        int r = backend.Constant(backend.Field.Compiler.Zero.Span);
        for(int i = 0; i < n; i++)
        {
            int scaled = backend.MultiplyScaled(coefficients[i].Span, powers[i]);
            r = backend.Add(r, scaled);
        }

        return r;
    }


    /// <summary>
    /// The reference's <c>eval_horner</c>: evaluates the polynomial with monomial coefficients
    /// <paramref name="coefficients"/> at <paramref name="x"/> via parallel Horner halving, folding
    /// <see cref="HornerFanIn"/> terms per round and squaring the evaluation point between rounds.
    /// </summary>
    /// <param name="coefficients">The monomial coefficients, least significant first.</param>
    /// <param name="x">The evaluation point wire.</param>
    /// <returns>The wire holding the evaluated result.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="coefficients"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="coefficients"/> is empty.</exception>
    public int EvaluateHorner(ReadOnlyMemory<byte>[] coefficients, int x)
    {
        ArgumentNullException.ThrowIfNull(coefficients);

        int n = coefficients.Length;
        if(n == 0)
        {
            throw new ArgumentException("Horner evaluation needs at least one coefficient.", nameof(coefficients));
        }

        var c = new int[n];
        for(int i = 0; i < n; i++)
        {
            c[i] = backend.Constant(coefficients[i].Span);
        }

        for(int width = n; width > 1; width = (width + HornerFanIn - 1) / HornerFanIn)
        {
            for(int i = 0; (HornerFanIn * i) < width; i++)
            {
                c[i] = c[HornerFanIn * i];
                if((HornerFanIn * i) + 1 < width)
                {
                    int scaled = backend.Mul(x, c[(HornerFanIn * i) + 1]);
                    c[i] = backend.Add(c[i], scaled);
                }
            }

            x = backend.Mul(x, x);
        }

        return c[0];
    }
}
