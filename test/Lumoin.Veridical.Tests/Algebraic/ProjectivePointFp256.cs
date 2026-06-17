using Lumoin.Veridical.Backends.Managed;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// A homogeneous-projective P-256 base-field point <c>(X : Y : Z)</c> over
/// <see cref="BigInteger"/> mod <c>p</c>, carrying the reference's
/// <em>complete</em> Renes–Costello–Batina addition and doubling formulas
/// (<see href="https://eprint.iacr.org/2015/1060.pdf">eprint 2015/1060</see>),
/// ported operation-for-operation from
/// <c>tempdocs/longfellow-zk-reference/lib/ec/elliptic_curve.h</c>.
/// </summary>
/// <remarks>
/// <para>
/// The point of byte-for-byte fidelity (not merely mathematical correctness) is
/// that <c>VerifyWitness3::compute_witness</c>
/// (<c>lib/circuits/ecdsa/verify_witness.h:147-187</c>) stores the
/// <em>un-normalized</em> projective intermediates <c>int_x/int_y/int_z</c>
/// produced by exactly this <c>addE</c>/<c>doubleE</c> sequence as witness
/// values a later phase's circuit asserts; the same operation order and the same
/// curve constant <c>k3b = 3·b</c> must therefore be reproduced here.
/// </para>
/// <para>
/// The field constants are reused from <see cref="EcdsaNonceRecovery"/>
/// (the affine oracle this type is gated against): the base-field prime
/// <see cref="EcdsaNonceRecovery.P"/> and the curve coefficient
/// <see cref="EcdsaNonceRecovery.A"/> (<c>a = p − 3</c>). The coefficient
/// <c>b</c> comes from <see cref="P256BigIntegerG1Reference.CurveB"/>, the same
/// source <c>P</c> and <c>A</c> derive from.
/// </para>
/// </remarks>
internal readonly struct ProjectivePointFp256
{
    private static readonly BigInteger Prime = EcdsaNonceRecovery.P;

    //a_ in elliptic_curve.h: the P-256 curve coefficient a = p − 3 (not the literal −3).
    private static readonly BigInteger A = EcdsaNonceRecovery.A;

    //k3b in elliptic_curve.h:65 — the EllipticCurve constructor sets k3b = mulf(of_scalar(3), b_),
    //i.e. k3b = 3·b mod p, with b the P-256 curve coefficient.
    private static readonly BigInteger K3b = Mod(3 * P256BigIntegerG1Reference.CurveB);


    private ProjectivePointFp256(BigInteger x, BigInteger y, BigInteger z)
    {
        X = x;
        Y = y;
        Z = z;
    }


    /// <summary>The projective X coordinate (mod <c>p</c>).</summary>
    public BigInteger X { get; }

    /// <summary>The projective Y coordinate (mod <c>p</c>).</summary>
    public BigInteger Y { get; }

    /// <summary>The projective Z coordinate (mod <c>p</c>); <c>Z = 0</c> marks the identity.</summary>
    public BigInteger Z { get; }


    /// <summary>
    /// The point at infinity <c>(0 : 1 : 0)</c> — <c>zero()</c> in
    /// elliptic_curve.h:69 (<c>ECPoint(f_.zero(), f_.one(), f_.zero())</c>).
    /// </summary>
    public static ProjectivePointFp256 Identity { get; } = new(BigInteger.Zero, BigInteger.One, BigInteger.Zero);


    /// <summary>Lifts an affine point <c>(x, y)</c> to projective <c>(x : y : 1)</c>.</summary>
    public static ProjectivePointFp256 FromAffine((BigInteger X, BigInteger Y) point) =>
        new(Mod(point.X), Mod(point.Y), BigInteger.One);


    /// <summary>
    /// Complete projective addition — Algorithm 1 of eprint 2015/1060, ported
    /// operation-for-operation from <c>addE</c> in elliptic_curve.h:172-218.
    /// Valid for all inputs, including equal points, the identity, and inverses.
    /// </summary>
    public static ProjectivePointFp256 Add(ProjectivePointFp256 p1, ProjectivePointFp256 p2)
    {
        BigInteger x1 = p1.X, y1 = p1.Y, z1 = p1.Z;
        BigInteger x2 = p2.X, y2 = p2.Y, z2 = p2.Z;

        //elliptic_curve.h:174-217 — same operation order and intermediate variables.
        BigInteger t0 = Mul(x1, x2);
        BigInteger t1 = Mul(y1, y2);
        BigInteger t2 = Mul(z1, z2);
        BigInteger t3 = Add(x1, y1);
        BigInteger t4 = Add(x2, y2);
        t3 = Mul(t3, t4);
        t4 = Add(t0, t1);
        t3 = Sub(t3, t4);
        t4 = Add(x1, z1);
        BigInteger t5 = Add(x2, z2);
        t4 = Mul(t4, t5);
        t5 = Add(t0, t2);
        t4 = Sub(t4, t5);
        t5 = Add(y1, z1);
        BigInteger x3t = Add(y2, z2);
        t5 = Mul(t5, x3t);
        x3t = Add(t1, t2);
        t5 = Sub(t5, x3t);
        BigInteger z3t = Mul(A, t4);
        x3t = Mul(K3b, t2);
        z3t = Add(x3t, z3t);
        x3t = Sub(t1, z3t);
        z3t = Add(t1, z3t);
        BigInteger y3t = Mul(x3t, z3t);
        t1 = Add(t0, t0);
        t1 = Add(t1, t0);
        t2 = Mul(A, t2);
        t4 = Mul(K3b, t4);
        t1 = Add(t1, t2);
        t2 = Sub(t0, t2);
        t2 = Mul(A, t2);
        t4 = Add(t4, t2);
        t0 = Mul(t1, t4);
        y3t = Add(y3t, t0);
        t0 = Mul(t5, t4);
        x3t = Mul(t3, x3t);
        x3t = Sub(x3t, t0);
        t0 = Mul(t3, t1);
        z3t = Mul(t5, z3t);
        z3t = Add(z3t, t0);

        return new ProjectivePointFp256(x3t, y3t, z3t);
    }


    /// <summary>
    /// Complete projective doubling — Algorithm 3 of eprint 2015/1060, ported
    /// operation-for-operation from <c>doubleE</c> in elliptic_curve.h:221-257.
    /// </summary>
    public static ProjectivePointFp256 Double(ProjectivePointFp256 p)
    {
        BigInteger x = p.X, y = p.Y, z = p.Z;

        //elliptic_curve.h:222-256 — same operation order and intermediate variables.
        BigInteger t0 = Mul(x, x);
        BigInteger t1 = Mul(y, y);
        BigInteger t2 = Mul(z, z);
        BigInteger t3 = Mul(x, y);
        t3 = Add(t3, t3);
        BigInteger z3t = Mul(x, z);
        z3t = Add(z3t, z3t);
        BigInteger x3t = Mul(A, z3t);
        BigInteger y3t = Mul(K3b, t2);
        y3t = Add(x3t, y3t);
        x3t = Sub(t1, y3t);
        y3t = Add(t1, y3t);
        y3t = Mul(x3t, y3t);
        x3t = Mul(t3, x3t);
        z3t = Mul(K3b, z3t);
        t2 = Mul(A, t2);
        t3 = Sub(t0, t2);
        t3 = Mul(A, t3);
        t3 = Add(t3, z3t);
        z3t = Add(t0, t0);
        t0 = Add(z3t, t0);
        t0 = Add(t0, t2);
        t0 = Mul(t0, t3);
        y3t = Add(y3t, t0);
        t2 = Mul(y, z);
        t2 = Add(t2, t2);
        t0 = Mul(t2, t3);
        x3t = Sub(x3t, t0);
        z3t = Mul(t2, t1);
        z3t = Add(z3t, z3t);
        z3t = Add(z3t, z3t);

        return new ProjectivePointFp256(x3t, y3t, z3t);
    }


    /// <summary>
    /// Returns the affine coordinates <c>(X/Z, Y/Z)</c>, or <see langword="null"/>
    /// for the identity (<c>Z == 0</c>). Mirrors <c>normalize</c>
    /// (elliptic_curve.h:105-111): divide by <c>Z</c> via field inversion.
    /// </summary>
    public (BigInteger X, BigInteger Y)? Normalize()
    {
        if(Z.IsZero)
        {
            return null;
        }

        BigInteger zInverse = ModInverse(Z);

        return (Mul(X, zInverse), Mul(Y, zInverse));
    }


    private static BigInteger Add(BigInteger a, BigInteger b) => Mod(a + b);

    private static BigInteger Sub(BigInteger a, BigInteger b) => Mod(a - b);

    private static BigInteger Mul(BigInteger a, BigInteger b) => Mod(a * b);

    private static BigInteger Mod(BigInteger value) => ((value % Prime) + Prime) % Prime;

    private static BigInteger ModInverse(BigInteger value) => BigInteger.ModPow(Mod(value), Prime - 2, Prime);
}
