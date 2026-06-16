using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Gates the complete projective <see cref="ProjectivePointFp256"/> formulas
/// (Renes–Costello–Batina Algorithm 1/3, ported from elliptic_curve.h) against
/// the affine P-256 oracle in <see cref="EcdsaNonceRecovery"/>: the projective
/// add/double, normalized to affine, must equal the affine add/double, and a
/// full double-and-add ladder over the projective formulas must normalize to the
/// affine <c>k·G</c>. The ladder gate is the load-bearing one — it exercises the
/// exact double-then-add sequence the later un-normalized witness ladder
/// (verify_witness.h:147-187) records.
/// </summary>
[TestClass]
internal sealed class ProjectivePointFp256Tests
{
    private static readonly BigInteger Prime = EcdsaNonceRecovery.P;
    private static readonly BigInteger A = EcdsaNonceRecovery.A;
    private static readonly BigInteger B = P256BigIntegerG1Reference.CurveB;

    //Deterministic generator seed — no System.Random/Date, so the sampled points are reproducible.
    private const ulong SampleSeed = 0x9E3779B97F4A7C15UL;
    private const int SamplePairCount = 16;

    //A handful of small scalars whose k·G the projective ladder must reproduce.
    private static readonly int[] LadderScalars = [1, 2, 3, 4, 5, 7, 16, 255, 1000, 65537];


    [TestMethod]
    public void ProjectiveAddNormalizesToAffineAdd()
    {
        SplitMix64 generator = new(SampleSeed);
        for(int sample = 0; sample < SamplePairCount; sample++)
        {
            (BigInteger X, BigInteger Y) a = RandomPoint(ref generator);
            (BigInteger X, BigInteger Y) b = RandomPoint(ref generator);

            (BigInteger X, BigInteger Y)? projective = ProjectivePointFp256
                .Add(ProjectivePointFp256.FromAffine(a), ProjectivePointFp256.FromAffine(b))
                .Normalize();

            //AffineAdd routes equal inputs to AffineDouble, so it matches the complete formula.
            (BigInteger X, BigInteger Y) affine = EcdsaNonceRecovery.AffineAdd(a, b);

            Assert.AreEqual(affine, projective, $"Projective Add disagrees with AffineAdd at sample {sample}.");
        }
    }


    [TestMethod]
    public void ProjectiveDoubleNormalizesToAffineDouble()
    {
        SplitMix64 generator = new(SampleSeed);
        for(int sample = 0; sample < SamplePairCount; sample++)
        {
            (BigInteger X, BigInteger Y) a = RandomPoint(ref generator);

            (BigInteger X, BigInteger Y)? projective = ProjectivePointFp256
                .Double(ProjectivePointFp256.FromAffine(a))
                .Normalize();

            (BigInteger X, BigInteger Y) affine = EcdsaNonceRecovery.AffineDouble(a);

            Assert.AreEqual(affine, projective, $"Projective Double disagrees with AffineDouble at sample {sample}.");
        }
    }


    [TestMethod]
    public void AddWithIdentityReturnsTheOtherPoint()
    {
        SplitMix64 generator = new(SampleSeed);
        for(int sample = 0; sample < SamplePairCount; sample++)
        {
            (BigInteger X, BigInteger Y) a = RandomPoint(ref generator);
            ProjectivePointFp256 point = ProjectivePointFp256.FromAffine(a);

            Assert.AreEqual(a, ProjectivePointFp256.Add(point, ProjectivePointFp256.Identity).Normalize(),
                $"P + O must equal P at sample {sample}.");
            Assert.AreEqual(a, ProjectivePointFp256.Add(ProjectivePointFp256.Identity, point).Normalize(),
                $"O + P must equal P at sample {sample}.");
        }
    }


    [TestMethod]
    public void DoubleOfIdentityIsIdentity() =>
        Assert.IsNull(ProjectivePointFp256.Double(ProjectivePointFp256.Identity).Normalize(),
            "Doubling the point at infinity must stay at infinity.");


    [TestMethod]
    public void AddPointAndItsNegationIsIdentity()
    {
        SplitMix64 generator = new(SampleSeed);
        for(int sample = 0; sample < SamplePairCount; sample++)
        {
            (BigInteger X, BigInteger Y) a = RandomPoint(ref generator);
            (BigInteger X, BigInteger Y) negated = (a.X, Mod(Prime - a.Y));

            Assert.IsNull(
                ProjectivePointFp256.Add(ProjectivePointFp256.FromAffine(a), ProjectivePointFp256.FromAffine(negated)).Normalize(),
                $"P + (−P) must be the identity at sample {sample}.");
        }
    }


    [TestMethod]
    public void ProjectiveLadderNormalizesToAffineScalarMultiply()
    {
        foreach(int scalar in LadderScalars)
        {
            (BigInteger X, BigInteger Y)? ladder = ScalarMultiplyProjective(scalar, EcdsaNonceRecovery.G).Normalize();
            (BigInteger X, BigInteger Y) affine = EcdsaNonceRecovery.ScalarMultiply(scalar, EcdsaNonceRecovery.G);

            Assert.AreEqual(affine, ladder, $"Projective ladder disagrees with ScalarMultiply for k = {scalar}.");
        }
    }


    [TestMethod]
    public void NormalizedResultsAreOnCurve()
    {
        foreach(int scalar in LadderScalars)
        {
            (BigInteger X, BigInteger Y)? point = ScalarMultiplyProjective(scalar, EcdsaNonceRecovery.G).Normalize();
            Assert.IsNotNull(point, $"k·G must be a finite point for k = {scalar}.");

            //y² == x³ + a·x + b (mod p).
            BigInteger left = Mod(point!.Value.Y * point.Value.Y);
            BigInteger x = point.Value.X;
            BigInteger right = Mod(Mod(Mod(x * x) * x) + Mod(A * x) + B);

            Assert.AreEqual(right, left, $"Normalized k·G must satisfy the curve equation for k = {scalar}.");
        }
    }


    //Double-and-add over the projective formulas — the exact double-then-add sequence
    //the un-normalized witness ladder (verify_witness.h:147-187) records.
    private static ProjectivePointFp256 ScalarMultiplyProjective(BigInteger scalar, (BigInteger X, BigInteger Y) point)
    {
        ProjectivePointFp256 accumulator = ProjectivePointFp256.Identity;
        ProjectivePointFp256 addend = ProjectivePointFp256.FromAffine(point);
        for(BigInteger bits = EcdsaNonceRecovery.ModN(scalar); bits > 0; bits >>= 1)
        {
            if(!(bits & BigInteger.One).IsZero)
            {
                accumulator = ProjectivePointFp256.Add(accumulator, addend);
            }

            addend = ProjectivePointFp256.Double(addend);
        }

        return accumulator;
    }


    //An on-curve point sampled deterministically: a random in-range scalar times G,
    //so every gated input is guaranteed to lie on the curve.
    private static (BigInteger X, BigInteger Y) RandomPoint(ref SplitMix64 generator)
    {
        BigInteger scalar = EcdsaNonceRecovery.ModN(generator.NextScalar());
        if(scalar.IsZero)
        {
            scalar = BigInteger.One;
        }

        return EcdsaNonceRecovery.ScalarMultiply(scalar, EcdsaNonceRecovery.G);
    }


    private static BigInteger Mod(BigInteger value) => ((value % Prime) + Prime) % Prime;


    //A SplitMix64 generator — deterministic, seed-driven, no System.Random.
    private struct SplitMix64
    {
        private ulong state;


        public SplitMix64(ulong seed) => state = seed;


        public ulong Next()
        {
            unchecked
            {
                state += 0x9E3779B97F4A7C15UL;
                ulong z = state;
                z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9UL;
                z = (z ^ (z >> 27)) * 0x94D049BB133111EBUL;

                return z ^ (z >> 31);
            }
        }


        //A 256-bit scalar assembled from four 64-bit draws.
        public BigInteger NextScalar()
        {
            BigInteger value = BigInteger.Zero;
            for(int word = 0; word < 4; word++)
            {
                value = (value << 64) | Next();
            }

            return value;
        }
    }
}
