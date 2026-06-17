using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// The public composition root for the BN254 optimal-ate pairing: assembles a
/// <see cref="PairingBackend"/> over the portable BigInteger reference, exposing the
/// bilinear map <c>e : G1 × G2 → Fp12</c> plus the auxiliary Fp12 Frobenius and
/// cyclotomic-square operations. An application calls <see cref="Create"/> once and
/// passes the bundle's delegates into the protocol code.
/// </summary>
/// <remarks>
/// The underlying implementation remains internal — callers compose through this
/// factory and the <see cref="PairingBackend"/> bundle. The pairing is
/// correctness-first BigInteger (Miller loop plus final exponentiation over the Fp
/// tower); it is not constant-time and not hardware-accelerated.
/// </remarks>
public static class Bn254ManagedPairingBackend
{
    /// <summary>Builds the BN254 pairing backend bundle: the pairing map, the Fp12 Frobenius, and the Fp12 cyclotomic square.</summary>
    public static PairingBackend Create()
    {
        return new PairingBackend(
            CurveParameterSet.Bn254,
            Bn254BigIntegerPairingReference.GetPairing(),
            Bn254BigIntegerPairingReference.GetFrobenius(),
            Bn254BigIntegerPairingReference.GetCyclotomicSquare());
    }
}
