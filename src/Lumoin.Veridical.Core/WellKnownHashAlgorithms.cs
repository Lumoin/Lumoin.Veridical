using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Core;

/// <summary>
/// Well-known hash algorithm identifiers, sizes, and conversion utilities.
/// </summary>
/// <remarks>
/// <para>
/// Different specifications use different naming conventions for the same hash
/// algorithm. This class provides constants for every variant the library
/// handles and methods to convert between them, enabling consistent
/// identification across JOSE, COSE, IETF, multibase, and circuit-internal
/// usage.
/// </para>
/// <para>
/// The class covers six families: SHA-2, SHA-3, SHAKE (extendable-output),
/// Keccak-256 (the pre-FIPS-202 variant used by Ethereum, distinct from SHA3-256),
/// BLAKE2, and Poseidon (zk-friendly, used inside circuits). Naming follows
/// the library convention: no infix for SHA-2 and BLAKE2 (<c>Sha256</c>,
/// <c>Blake2b256</c>); underscore between family and width for SHA-3 and
/// Keccak (<c>Sha3_256</c>).
/// </para>
/// <para>
/// The class names algorithms; it does not compute them. Hash computation is
/// supplied by a delegate the application wires in. Algorithms that are not
/// represented by a <see cref="HashAlgorithmName"/> in the .NET base class
/// library — Keccak-256, BLAKE2, Poseidon, and the SHAKE extendable-output
/// functions — are still named here because they appear in wire formats this
/// library serialises and deserialises. The .NET BCL exposes SHAKE through
/// the <c>Shake128</c> and <c>Shake256</c> classes rather than through
/// <see cref="HashAlgorithmName"/> values, so the conversion methods on
/// this class throw for SHAKE just as they do for Keccak and BLAKE2.
/// </para>
/// </remarks>
[SuppressMessage("Naming", "CA1707", Justification = "SHA-3 identifiers in this class use an underscore between family and width per the project naming convention (Sha3_256, Sha3_384, Sha3_512). Future width and parameter-set additions follow the same convention.")]
public static class WellKnownHashAlgorithms
{
    /// <summary>SHA-256 algorithm name in .NET format.</summary>
    /// <remarks>Matches <see cref="HashAlgorithmName.SHA256"/>.<see cref="HashAlgorithmName.Name"/>.</remarks>
    public const string Sha256 = "SHA256";

    /// <summary>SHA-256 algorithm name in IANA format.</summary>
    /// <remarks>Used in SD-JWT <c>_sd_alg</c> claim, multihash, and IETF specifications.</remarks>
    public const string Sha256Iana = "sha-256";

    /// <summary>SHA-256 algorithm name in COSE display format.</summary>
    /// <remarks>Used in the IANA COSE Algorithms registry display names.</remarks>
    public const string Sha256Cose = "SHA-256";

    /// <summary>SHA-384 algorithm name in .NET format.</summary>
    public const string Sha384 = "SHA384";

    /// <summary>SHA-384 algorithm name in IANA format.</summary>
    public const string Sha384Iana = "sha-384";

    /// <summary>SHA-384 algorithm name in COSE display format.</summary>
    public const string Sha384Cose = "SHA-384";

    /// <summary>SHA-512 algorithm name in .NET format.</summary>
    public const string Sha512 = "SHA512";

    /// <summary>SHA-512 algorithm name in IANA format.</summary>
    public const string Sha512Iana = "sha-512";

    /// <summary>SHA-512 algorithm name in COSE display format.</summary>
    public const string Sha512Cose = "SHA-512";

    /// <summary>SHA3-256 algorithm name in .NET format.</summary>
    /// <remarks>Matches <see cref="HashAlgorithmName.SHA3_256"/>.<see cref="HashAlgorithmName.Name"/>.</remarks>
    public const string Sha3_256 = "SHA3-256";

    /// <summary>SHA3-256 algorithm name in IANA format.</summary>
    public const string Sha3_256Iana = "sha3-256";

    /// <summary>SHA3-384 algorithm name in .NET format.</summary>
    public const string Sha3_384 = "SHA3-384";

    /// <summary>SHA3-384 algorithm name in IANA format.</summary>
    public const string Sha3_384Iana = "sha3-384";

    /// <summary>SHA3-512 algorithm name in .NET format.</summary>
    public const string Sha3_512 = "SHA3-512";

    /// <summary>SHA3-512 algorithm name in IANA format.</summary>
    public const string Sha3_512Iana = "sha3-512";

    /// <summary>SHAKE128 extendable-output function name.</summary>
    /// <remarks>
    /// SHAKE128 produces a variable-length output. The .NET base class library
    /// exposes SHAKE128 through the <c>Shake128</c> class rather than as a
    /// <see cref="HashAlgorithmName"/> value, so this name is used only as a
    /// wire-format identifier. SHAKE computation is supplied by the
    /// <c>HashFunctionDelegate</c> the application wires in. Size queries throw
    /// because the output length is determined by the caller.
    /// </remarks>
    public const string Shake128 = "SHAKE128";

    /// <summary>SHAKE128 algorithm name in IANA format.</summary>
    public const string Shake128Iana = "shake128";

    /// <summary>SHAKE256 extendable-output function name.</summary>
    /// <remarks>
    /// SHAKE256 produces a variable-length output. The .NET base class library
    /// exposes SHAKE256 through the <c>Shake256</c> class rather than as a
    /// <see cref="HashAlgorithmName"/> value, so this name is used only as a
    /// wire-format identifier. SHAKE computation is supplied by the
    /// <c>HashFunctionDelegate</c> the application wires in. Size queries throw
    /// because the output length is determined by the caller.
    /// </remarks>
    public const string Shake256 = "SHAKE256";

    /// <summary>SHAKE256 algorithm name in IANA format.</summary>
    public const string Shake256Iana = "shake256";

    /// <summary>Keccak-256 algorithm name (pre-FIPS-202 variant used by Ethereum).</summary>
    /// <remarks>
    /// Distinct from <see cref="Sha3_256"/> because the padding byte differs
    /// (Keccak uses 0x01, SHA-3 uses 0x06). Producing the correct output
    /// requires a Keccak implementation, not a SHA-3 implementation.
    /// </remarks>
    public const string Keccak256 = "Keccak-256";

    /// <summary>Keccak-256 algorithm name in lowercase IANA-style format.</summary>
    public const string Keccak256Iana = "keccak-256";

    /// <summary>Keccak-256 algorithm name in Ethereum and Solidity convention.</summary>
    public const string Keccak256Ethereum = "keccak256";

    /// <summary>BLAKE2b-256 algorithm name (BLAKE2b truncated to 32 bytes).</summary>
    public const string Blake2b256 = "BLAKE2b-256";

    /// <summary>BLAKE2b-256 algorithm name in lowercase IANA-style format.</summary>
    public const string Blake2b256Iana = "blake2b-256";

    /// <summary>BLAKE2b-512 algorithm name (full BLAKE2b output).</summary>
    public const string Blake2b512 = "BLAKE2b-512";

    /// <summary>BLAKE2b-512 algorithm name in lowercase IANA-style format.</summary>
    public const string Blake2b512Iana = "blake2b-512";

    /// <summary>BLAKE2s-256 algorithm name (BLAKE2s, full output).</summary>
    public const string Blake2s256 = "BLAKE2s-256";

    /// <summary>BLAKE2s-256 algorithm name in lowercase IANA-style format.</summary>
    public const string Blake2s256Iana = "blake2s-256";

    /// <summary>BLAKE3 algorithm name.</summary>
    /// <remarks>
    /// BLAKE3 produces a 32-byte default output and supports extendable-output
    /// (XOF) mode through the same primitive, used here by the Fiat-Shamir
    /// transcript's squeeze operation. The .NET base class library does not
    /// represent BLAKE3 — implementations come from external packages or the
    /// project's future managed backend.
    /// </remarks>
    public const string Blake3 = "BLAKE3";

    /// <summary>BLAKE3 algorithm name in lowercase IANA-style format.</summary>
    public const string Blake3Iana = "blake3";

    /// <summary>
    /// Poseidon hash family identifier. A concrete Poseidon instantiation
    /// requires a parameter set covering the underlying field, S-box exponent,
    /// width, and rate, none of which are universally standardised yet.
    /// </summary>
    /// <remarks>
    /// Output size depends on the parameter set; for most circuit uses it
    /// equals one scalar-field element of the chosen curve (32 bytes for
    /// BLS12-381 or BN254). Per-instantiation constants will be added as
    /// parameter sets stabilise.
    /// </remarks>
    public const string Poseidon = "Poseidon";


    /// <summary>SHA-256 output size in bytes.</summary>
    public const int Sha256SizeBytes = 32;

    /// <summary>SHA-384 output size in bytes.</summary>
    public const int Sha384SizeBytes = 48;

    /// <summary>SHA-512 output size in bytes.</summary>
    public const int Sha512SizeBytes = 64;

    /// <summary>SHA3-256 output size in bytes.</summary>
    public const int Sha3_256SizeBytes = 32;

    /// <summary>SHA3-384 output size in bytes.</summary>
    public const int Sha3_384SizeBytes = 48;

    /// <summary>SHA3-512 output size in bytes.</summary>
    public const int Sha3_512SizeBytes = 64;

    /// <summary>Keccak-256 output size in bytes.</summary>
    public const int Keccak256SizeBytes = 32;

    /// <summary>BLAKE2b-256 output size in bytes.</summary>
    public const int Blake2b256SizeBytes = 32;

    /// <summary>BLAKE2b-512 output size in bytes.</summary>
    public const int Blake2b512SizeBytes = 64;

    /// <summary>BLAKE2s-256 output size in bytes.</summary>
    public const int Blake2s256SizeBytes = 32;

    /// <summary>BLAKE3 default fixed-output size in bytes (the XOF mode is variable).</summary>
    public const int Blake3DefaultSizeBytes = 32;


    /// <summary>SHA-256 output size in bits.</summary>
    public const int Sha256SizeBits = 256;

    /// <summary>SHA-384 output size in bits.</summary>
    public const int Sha384SizeBits = 384;

    /// <summary>SHA-512 output size in bits.</summary>
    public const int Sha512SizeBits = 512;

    /// <summary>SHA3-256 output size in bits.</summary>
    public const int Sha3_256SizeBits = 256;

    /// <summary>SHA3-384 output size in bits.</summary>
    public const int Sha3_384SizeBits = 384;

    /// <summary>SHA3-512 output size in bits.</summary>
    public const int Sha3_512SizeBits = 512;

    /// <summary>Keccak-256 output size in bits.</summary>
    public const int Keccak256SizeBits = 256;

    /// <summary>BLAKE2b-256 output size in bits.</summary>
    public const int Blake2b256SizeBits = 256;

    /// <summary>BLAKE2b-512 output size in bits.</summary>
    public const int Blake2b512SizeBits = 512;

    /// <summary>BLAKE2s-256 output size in bits.</summary>
    public const int Blake2s256SizeBits = 256;

    /// <summary>BLAKE3 default fixed-output size in bits.</summary>
    public const int Blake3DefaultSizeBits = 256;


    /// <summary>Determines whether the specified value represents SHA-256.</summary>
    public static bool IsSha256(string? value)
    {
        if(string.IsNullOrEmpty(value))
        {
            return false;
        }


        return string.Equals(value, Sha256, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, Sha256Iana, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, Sha256Cose, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "sha256", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Determines whether the specified value represents SHA-384.</summary>
    public static bool IsSha384(string? value)
    {
        if(string.IsNullOrEmpty(value))
        {
            return false;
        }


        return string.Equals(value, Sha384, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, Sha384Iana, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, Sha384Cose, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "sha384", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Determines whether the specified value represents SHA-512.</summary>
    public static bool IsSha512(string? value)
    {
        if(string.IsNullOrEmpty(value))
        {
            return false;
        }


        return string.Equals(value, Sha512, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, Sha512Iana, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, Sha512Cose, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "sha512", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Determines whether the specified value represents SHA3-256.</summary>
    public static bool IsSha3_256(string? value)
    {
        if(string.IsNullOrEmpty(value))
        {
            return false;
        }


        return string.Equals(value, Sha3_256, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, Sha3_256Iana, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "sha3_256", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Determines whether the specified value represents SHA3-384.</summary>
    public static bool IsSha3_384(string? value)
    {
        if(string.IsNullOrEmpty(value))
        {
            return false;
        }


        return string.Equals(value, Sha3_384, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, Sha3_384Iana, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "sha3_384", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Determines whether the specified value represents SHA3-512.</summary>
    public static bool IsSha3_512(string? value)
    {
        if(string.IsNullOrEmpty(value))
        {
            return false;
        }


        return string.Equals(value, Sha3_512, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, Sha3_512Iana, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "sha3_512", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Determines whether the specified value represents SHAKE128.</summary>
    public static bool IsShake128(string? value)
    {
        if(string.IsNullOrEmpty(value))
        {
            return false;
        }


        return string.Equals(value, Shake128, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, Shake128Iana, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "shake-128", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Determines whether the specified value represents SHAKE256.</summary>
    public static bool IsShake256(string? value)
    {
        if(string.IsNullOrEmpty(value))
        {
            return false;
        }


        return string.Equals(value, Shake256, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, Shake256Iana, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "shake-256", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Determines whether the specified value represents Keccak-256.</summary>
    public static bool IsKeccak256(string? value)
    {
        if(string.IsNullOrEmpty(value))
        {
            return false;
        }


        return string.Equals(value, Keccak256, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, Keccak256Iana, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, Keccak256Ethereum, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "keccak_256", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Determines whether the specified value represents BLAKE2b-256.</summary>
    public static bool IsBlake2b256(string? value)
    {
        if(string.IsNullOrEmpty(value))
        {
            return false;
        }


        return string.Equals(value, Blake2b256, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, Blake2b256Iana, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "blake2b256", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Determines whether the specified value represents BLAKE2b-512.</summary>
    public static bool IsBlake2b512(string? value)
    {
        if(string.IsNullOrEmpty(value))
        {
            return false;
        }


        return string.Equals(value, Blake2b512, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, Blake2b512Iana, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "blake2b512", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Determines whether the specified value represents BLAKE2s-256.</summary>
    public static bool IsBlake2s256(string? value)
    {
        if(string.IsNullOrEmpty(value))
        {
            return false;
        }


        return string.Equals(value, Blake2s256, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, Blake2s256Iana, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "blake2s256", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Determines whether the specified value represents BLAKE3.</summary>
    public static bool IsBlake3(string? value)
    {
        if(string.IsNullOrEmpty(value))
        {
            return false;
        }


        return string.Equals(value, Blake3, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, Blake3Iana, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "blake-3", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Determines whether the specified value represents the Poseidon family.</summary>
    /// <remarks>
    /// Returns true for the bare family name <c>Poseidon</c>. Concrete parameter-set
    /// identifiers (curve, S-box exponent, width, rate) are not standardised and
    /// must be matched explicitly by the caller when they appear.
    /// </remarks>
    public static bool IsPoseidon(string? value) =>
        !string.IsNullOrEmpty(value)
            && string.Equals(value, Poseidon, StringComparison.OrdinalIgnoreCase);

    /// <summary>Determines whether the specified value represents any SHA-2 algorithm.</summary>
    public static bool IsAnySha2(string? value) =>
        IsSha256(value) || IsSha384(value) || IsSha512(value);

    /// <summary>Determines whether the specified value represents any SHA-3 fixed-output algorithm.</summary>
    public static bool IsAnySha3(string? value) =>
        IsSha3_256(value) || IsSha3_384(value) || IsSha3_512(value);

    /// <summary>Determines whether the specified value represents any SHAKE function.</summary>
    public static bool IsAnyShake(string? value) =>
        IsShake128(value) || IsShake256(value);

    /// <summary>Determines whether the specified value represents any BLAKE2 algorithm.</summary>
    public static bool IsAnyBlake2(string? value) =>
        IsBlake2b256(value) || IsBlake2b512(value) || IsBlake2s256(value);

    /// <summary>
    /// Determines whether the specified algorithm produces a variable-length
    /// (extendable) output. SHAKE128, SHAKE256, and BLAKE3 in XOF mode are
    /// extendable; the fixed-output algorithms in this class are not.
    /// </summary>
    public static bool IsVariableOutput(string? value) =>
        IsAnyShake(value) || IsBlake3(value);


    /// <summary>
    /// Converts a string algorithm name to a <see cref="HashAlgorithmName"/>
    /// for algorithms that the .NET base class library represents.
    /// </summary>
    /// <param name="value">The algorithm name in any supported format.</param>
    /// <returns>The corresponding <see cref="HashAlgorithmName"/>.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown for algorithms that have no <see cref="HashAlgorithmName"/>
    /// counterpart in the .NET base class library — the SHAKE extendable-output
    /// functions, Keccak-256, BLAKE2, and Poseidon. These algorithms are still
    /// named in this class for wire-format identification but require an
    /// external implementation.
    /// </exception>
    public static HashAlgorithmName ToHashAlgorithmName(string value) => value switch
    {
        _ when IsSha256(value) => HashAlgorithmName.SHA256,
        _ when IsSha384(value) => HashAlgorithmName.SHA384,
        _ when IsSha512(value) => HashAlgorithmName.SHA512,
        _ when IsSha3_256(value) => HashAlgorithmName.SHA3_256,
        _ when IsSha3_384(value) => HashAlgorithmName.SHA3_384,
        _ when IsSha3_512(value) => HashAlgorithmName.SHA3_512,
        _ => throw new ArgumentException($"No HashAlgorithmName representation for '{value}'. The algorithm is named in this class for wire-format identification but requires an external implementation.", nameof(value))
    };


    /// <summary>
    /// Converts a <see cref="HashAlgorithmName"/> to its IANA-format name.
    /// </summary>
    /// <exception cref="ArgumentException">Thrown for unsupported algorithms.</exception>
    public static string ToIanaName(HashAlgorithmName algorithm) =>
        algorithm.Name switch
        {
            Sha256 => Sha256Iana,
            Sha384 => Sha384Iana,
            Sha512 => Sha512Iana,
            Sha3_256 => Sha3_256Iana,
            Sha3_384 => Sha3_384Iana,
            Sha3_512 => Sha3_512Iana,
            _ => throw new ArgumentException($"Unsupported hash algorithm: '{algorithm.Name}'.", nameof(algorithm))
        };

    /// <summary>
    /// Converts a string algorithm name to its IANA-format name.
    /// </summary>
    /// <exception cref="ArgumentException">Thrown for unrecognised algorithm names.</exception>
    public static string ToIanaName(string value) => value switch
    {
        _ when IsSha256(value) => Sha256Iana,
        _ when IsSha384(value) => Sha384Iana,
        _ when IsSha512(value) => Sha512Iana,
        _ when IsSha3_256(value) => Sha3_256Iana,
        _ when IsSha3_384(value) => Sha3_384Iana,
        _ when IsSha3_512(value) => Sha3_512Iana,
        _ when IsShake128(value) => Shake128Iana,
        _ when IsShake256(value) => Shake256Iana,
        _ when IsKeccak256(value) => Keccak256Iana,
        _ when IsBlake2b256(value) => Blake2b256Iana,
        _ when IsBlake2b512(value) => Blake2b512Iana,
        _ when IsBlake2s256(value) => Blake2s256Iana,
        _ when IsBlake3(value) => Blake3Iana,
        _ => throw new ArgumentException($"Unrecognised hash algorithm: '{value}'.", nameof(value))
    };


    /// <summary>
    /// Converts a <see cref="HashAlgorithmName"/> to its COSE display name.
    /// </summary>
    /// <exception cref="ArgumentException">Thrown for unsupported algorithms.</exception>
    public static string ToCoseName(HashAlgorithmName algorithm) =>
        algorithm.Name switch
        {
            Sha256 => Sha256Cose,
            Sha384 => Sha384Cose,
            Sha512 => Sha512Cose,
            _ => throw new ArgumentException($"No COSE display name registered for '{algorithm.Name}'.", nameof(algorithm))
        };

    /// <summary>
    /// Converts a string algorithm name to its COSE display name. Only the
    /// SHA-2 family currently has standardised COSE display names in this
    /// class; other algorithms throw.
    /// </summary>
    /// <exception cref="ArgumentException">Thrown for algorithms with no COSE display name.</exception>
    public static string ToCoseName(string value) => value switch
    {
        _ when IsSha256(value) => Sha256Cose,
        _ when IsSha384(value) => Sha384Cose,
        _ when IsSha512(value) => Sha512Cose,
        _ => throw new ArgumentException($"No COSE display name registered for '{value}'.", nameof(value))
    };


    /// <summary>
    /// Returns the output size in bytes for the specified algorithm.
    /// </summary>
    /// <exception cref="ArgumentException">Thrown for algorithms with variable output (SHAKE) or no fixed default size (Poseidon).</exception>
    public static int GetSizeBytes(HashAlgorithmName algorithm) =>
        algorithm.Name switch
        {
            Sha256 => Sha256SizeBytes,
            Sha384 => Sha384SizeBytes,
            Sha512 => Sha512SizeBytes,
            Sha3_256 => Sha3_256SizeBytes,
            Sha3_384 => Sha3_384SizeBytes,
            Sha3_512 => Sha3_512SizeBytes,
            _ => throw new ArgumentException($"Unknown hash algorithm: '{algorithm.Name}'.", nameof(algorithm))
        };

    /// <summary>
    /// Returns the output size in bytes for the specified algorithm name.
    /// </summary>
    /// <exception cref="ArgumentException">Thrown for unrecognised names, variable-output algorithms, or algorithms with no fixed default size.</exception>
    public static int GetSizeBytes(string value) => value switch
    {
        _ when IsSha256(value) => Sha256SizeBytes,
        _ when IsSha384(value) => Sha384SizeBytes,
        _ when IsSha512(value) => Sha512SizeBytes,
        _ when IsSha3_256(value) => Sha3_256SizeBytes,
        _ when IsSha3_384(value) => Sha3_384SizeBytes,
        _ when IsSha3_512(value) => Sha3_512SizeBytes,
        _ when IsKeccak256(value) => Keccak256SizeBytes,
        _ when IsBlake2b256(value) => Blake2b256SizeBytes,
        _ when IsBlake2b512(value) => Blake2b512SizeBytes,
        _ when IsBlake2s256(value) => Blake2s256SizeBytes,
        _ when IsBlake3(value) => Blake3DefaultSizeBytes,
        _ when IsAnyShake(value) => throw new ArgumentException($"'{value}' has variable output length; size is determined by the caller.", nameof(value)),
        _ when IsPoseidon(value) => throw new ArgumentException("Poseidon output size depends on the parameter set; specify a concrete instantiation.", nameof(value)),
        _ => throw new ArgumentException($"Unrecognised hash algorithm: '{value}'.", nameof(value))
    };

    /// <summary>
    /// Returns the output size in bits for the specified algorithm.
    /// </summary>
    /// <exception cref="ArgumentException">Thrown for variable-output algorithms or algorithms with no fixed default size.</exception>
    public static int GetSizeBits(HashAlgorithmName algorithm) =>
        checked(GetSizeBytes(algorithm) * 8);

    /// <summary>
    /// Returns the output size in bits for the specified algorithm name.
    /// </summary>
    /// <exception cref="ArgumentException">Thrown for unrecognised names, variable-output algorithms, or algorithms with no fixed default size.</exception>
    public static int GetSizeBits(string value) =>
        checked(GetSizeBytes(value) * 8);
}