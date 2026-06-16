using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Globalization;
using System.Numerics;
using System.Text;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// An affine combination of variables over the integers:
/// <c>Σ cᵢ·xᵢ + k</c>, where each <c>xᵢ</c> is an
/// <see cref="R1csVariableIndex"/>, each <c>cᵢ</c> is a
/// <see cref="BigInteger"/> coefficient, and <c>k</c> is a constant term
/// (a coefficient on the implicit constant-one wire at index 0). One
/// linear combination is one row of one R1CS matrix.
/// </summary>
/// <remarks>
/// <para>
/// The type is immutable and normalised: <see cref="Terms"/> is sorted
/// ascending by variable index, terms on the same variable are summed, and
/// zero-coefficient terms are dropped. Two combinations that denote the
/// same affine form are therefore structurally equal regardless of how
/// they were built. Equality and hashing are structural.
/// </para>
/// <para>
/// Coefficients are arbitrary-precision integers at the builder layer; the
/// reduction modulo the scalar field order happens once, at
/// <see cref="R1csCircuit"/> compile time. This keeps the builder
/// curve-agnostic — the same circuit compiles against any wired curve.
/// </para>
/// <para>
/// It is a class rather than a record because it carries arithmetic
/// operator overloads (<c>+</c>, <c>-</c>, <c>*</c>) and the
/// record-generated structural members compose awkwardly with operator
/// overloading. Equality is implemented by hand to the same effect.
/// </para>
/// <para>
/// Operator note: C# sources user-defined operators only from the operand
/// types themselves, so <c>x + y</c> and <c>2 * x</c> do not compile when
/// <c>x</c>, <c>y</c> are bare <see cref="R1csVariableIndex"/> values — a
/// variable index is a position, not an expression (no operators live on
/// it). Promote a variable with <see cref="From(R1csVariableIndex)"/>
/// first: <c>2 * From(x) + From(y)</c>. The implicit conversion still
/// makes a bare index usable wherever a combination is expected as a
/// method argument (for example <c>AddConstraint(x, y, z)</c>).
/// </para>
/// </remarks>
public sealed class R1csLinearCombination: IEquatable<R1csLinearCombination>
{
    /// <summary>The combination's variable terms, sorted ascending by variable index, with no duplicate variables and no zero coefficients.</summary>
    public ImmutableArray<(R1csVariableIndex Variable, BigInteger Coefficient)> Terms { get; }

    /// <summary>The constant term — the coefficient on the implicit constant-one wire.</summary>
    public BigInteger Constant { get; }


    private R1csLinearCombination(
        ImmutableArray<(R1csVariableIndex Variable, BigInteger Coefficient)> normalisedTerms,
        BigInteger constant)
    {
        Terms = normalisedTerms;
        Constant = constant;
    }


    /// <summary>The zero combination: no terms, constant zero. The additive identity.</summary>
    public static R1csLinearCombination Zero { get; } =
        new(ImmutableArray<(R1csVariableIndex, BigInteger)>.Empty, BigInteger.Zero);


    /// <summary>Whether this combination is identically zero (no terms and a zero constant).</summary>
    public bool IsZero => Terms.Length == 0 && Constant.IsZero;


    /// <summary>
    /// Builds the single-variable combination <c>1·variable</c> from a
    /// variable index. This is the explicit form of the implicit
    /// <see cref="R1csVariableIndex"/> conversion; prefer it as the leading
    /// term of an operator expression (see the type remarks).
    /// </summary>
    public static R1csLinearCombination From(R1csVariableIndex variable)
    {
        var terms = ImmutableArray.Create((variable, BigInteger.One));
        return new R1csLinearCombination(terms, BigInteger.Zero);
    }


    /// <summary>Builds the constant combination <c>k</c> (no variable terms).</summary>
    public static R1csLinearCombination FromConstant(BigInteger constant) =>
        new(ImmutableArray<(R1csVariableIndex, BigInteger)>.Empty, constant);


    /// <summary>
    /// Builds a normalised combination from arbitrary (variable,
    /// coefficient) terms and a constant. Terms in any order, with repeats
    /// and zeros, are accepted; the result is normalised.
    /// </summary>
    public static R1csLinearCombination Create(
        IEnumerable<(R1csVariableIndex Variable, BigInteger Coefficient)> terms,
        BigInteger constant)
    {
        ArgumentNullException.ThrowIfNull(terms);
        return new R1csLinearCombination(Normalise(terms), constant);
    }


    /// <summary>
    /// Returns this combination's value as a single constant when it has no
    /// variable terms, throwing otherwise. Used where the API requires a
    /// literal field element (for example the elements of a membership set).
    /// </summary>
    /// <exception cref="InvalidOperationException">When the combination references any variable.</exception>
    public BigInteger ToConstantOrThrow()
    {
        if(Terms.Length != 0)
        {
            throw new InvalidOperationException(
                "Linear combination references variables and cannot be reduced to a constant.");
        }

        return Constant;
    }


    /// <summary>Implicitly promotes a variable index to the combination <c>1·variable</c>.</summary>
    public static implicit operator R1csLinearCombination(R1csVariableIndex variable) => From(variable);

    /// <summary>Implicitly promotes a constant to the combination with that constant term and no variables.</summary>
    public static implicit operator R1csLinearCombination(BigInteger constant) => FromConstant(constant);


    /// <summary>Adds two combinations term-by-term.</summary>
    public static R1csLinearCombination operator +(R1csLinearCombination left, R1csLinearCombination right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);

        var merged = new List<(R1csVariableIndex, BigInteger)>(left.Terms.Length + right.Terms.Length);
        foreach((R1csVariableIndex Variable, BigInteger Coefficient) term in left.Terms)
        {
            merged.Add(term);
        }

        foreach((R1csVariableIndex Variable, BigInteger Coefficient) term in right.Terms)
        {
            merged.Add(term);
        }

        return new R1csLinearCombination(Normalise(merged), left.Constant + right.Constant);
    }


    /// <summary>Subtracts <paramref name="right"/> from <paramref name="left"/>.</summary>
    public static R1csLinearCombination operator -(R1csLinearCombination left, R1csLinearCombination right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        return left + (-right);
    }


    /// <summary>Negates every coefficient and the constant.</summary>
    public static R1csLinearCombination operator -(R1csLinearCombination value)
    {
        ArgumentNullException.ThrowIfNull(value);

        var negated = ImmutableArray.CreateBuilder<(R1csVariableIndex, BigInteger)>(value.Terms.Length);
        foreach((R1csVariableIndex Variable, BigInteger Coefficient) term in value.Terms)
        {
            negated.Add((term.Variable, -term.Coefficient));
        }

        //Negation preserves the sorted, non-zero, deduplicated invariant,
        //so the result is already normalised.
        return new R1csLinearCombination(negated.MoveToImmutable(), -value.Constant);
    }


    /// <summary>Scales a combination by a constant (left-hand scalar).</summary>
    public static R1csLinearCombination operator *(BigInteger scalar, R1csLinearCombination value)
    {
        ArgumentNullException.ThrowIfNull(value);

        if(scalar.IsZero)
        {
            return Zero;
        }

        var scaled = ImmutableArray.CreateBuilder<(R1csVariableIndex, BigInteger)>(value.Terms.Length);
        foreach((R1csVariableIndex Variable, BigInteger Coefficient) term in value.Terms)
        {
            scaled.Add((term.Variable, term.Coefficient * scalar));
        }

        //Scaling by a non-zero constant cannot introduce zeros or reorder
        //terms, so the result stays normalised.
        return new R1csLinearCombination(scaled.MoveToImmutable(), value.Constant * scalar);
    }


    /// <summary>Scales a combination by a constant (right-hand scalar).</summary>
    public static R1csLinearCombination operator *(R1csLinearCombination value, BigInteger scalar) => scalar * value;


    /// <summary>Structural equality: equal constant and equal term sequences.</summary>
    public static bool operator ==(R1csLinearCombination? left, R1csLinearCombination? right) =>
        left is null ? right is null : left.Equals(right);

    /// <summary>Structural inequality.</summary>
    public static bool operator !=(R1csLinearCombination? left, R1csLinearCombination? right) => !(left == right);


    /// <inheritdoc/>
    public bool Equals(R1csLinearCombination? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        if(Constant != other.Constant || Terms.Length != other.Terms.Length)
        {
            return false;
        }

        for(int i = 0; i < Terms.Length; i++)
        {
            if(Terms[i].Variable != other.Terms[i].Variable || Terms[i].Coefficient != other.Terms[i].Coefficient)
            {
                return false;
            }
        }

        return true;
    }


    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as R1csLinearCombination);


    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Constant);
        foreach((R1csVariableIndex Variable, BigInteger Coefficient) term in Terms)
        {
            hash.Add(term.Variable);
            hash.Add(term.Coefficient);
        }

        return hash.ToHashCode();
    }


    /// <summary>Returns a human-readable form such as <c>2·x_3 + x_5 + 7</c> for inspection.</summary>
    public override string ToString()
    {
        if(IsZero)
        {
            return "0";
        }

        var builder = new StringBuilder();
        foreach((R1csVariableIndex Variable, BigInteger Coefficient) term in Terms)
        {
            AppendTerm(builder, term.Coefficient, term.Variable.ToString());
        }

        if(!Constant.IsZero)
        {
            AppendTerm(builder, Constant, variable: null);
        }

        return builder.ToString();
    }


    private static void AppendTerm(StringBuilder builder, BigInteger coefficient, string? variable)
    {
        bool first = builder.Length == 0;
        BigInteger magnitude = BigInteger.Abs(coefficient);
        string sign = coefficient.Sign < 0 ? "-" : "+";

        if(first)
        {
            if(coefficient.Sign < 0)
            {
                builder.Append('-');
            }
        }
        else
        {
            builder.Append(' ').Append(sign).Append(' ');
        }

        if(variable is null)
        {
            builder.Append(magnitude.ToString(CultureInfo.InvariantCulture));
        }
        else if(magnitude.IsOne)
        {
            builder.Append(variable);
        }
        else
        {
            builder.Append(magnitude.ToString(CultureInfo.InvariantCulture)).Append('·').Append(variable);
        }
    }


    private static ImmutableArray<(R1csVariableIndex Variable, BigInteger Coefficient)> Normalise(
        IEnumerable<(R1csVariableIndex Variable, BigInteger Coefficient)> terms)
    {
        //Sum coefficients per variable, then emit in ascending index order
        //dropping any that summed to zero. A SortedDictionary keyed by the
        //index value gives the ordering for free.
        var byIndex = new SortedDictionary<int, BigInteger>();
        foreach((R1csVariableIndex Variable, BigInteger Coefficient) term in terms)
        {
            int key = term.Variable.Value;
            byIndex[key] = byIndex.TryGetValue(key, out BigInteger existing)
                ? existing + term.Coefficient
                : term.Coefficient;
        }

        var builder = ImmutableArray.CreateBuilder<(R1csVariableIndex, BigInteger)>(byIndex.Count);
        foreach(KeyValuePair<int, BigInteger> entry in byIndex)
        {
            if(!entry.Value.IsZero)
            {
                builder.Add((new R1csVariableIndex(entry.Key), entry.Value));
            }
        }

        return builder.ToImmutable();
    }
}
