// Synchronous platform cryptography for the tests, backed by Node's crypto module. The runtime
// has no implementation of AES, ECDSA, ECDH or X.509 parsing of its own, so the host registers
// this module as the import 'platform-crypto' and the C# side calls these functions through
// JSImport. Every function takes and returns Uint8Array values and is synchronous.
import { createCipheriv, createECDH, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify, X509Certificate } from 'node:crypto';

const componentSize = 32;
const curveName = 'P-256';

// The P-256 domain parameters, for the verification of a signature over a digest the caller
// computed: Node's verify always hashes its input, so a pre-hashed check is done directly.
const fieldPrime = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const groupOrder = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const curveA = fieldPrime - 3n;
const curveB = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
const generator = [
    0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
    0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
];

function toBase64Url(bytes) {
    return Buffer.from(bytes).toString('base64url');
}

function fromBase64Url(text) {
    const raw = Buffer.from(text, 'base64url');
    const padded = new Uint8Array(componentSize);
    padded.set(raw, componentSize - raw.length);

    return padded;
}

function toInteger(bytes) {
    return bytes.length === 0 ? 0n : BigInt('0x' + Buffer.from(bytes).toString('hex'));
}

function publicJwk(publicX, publicY) {
    return { kty: 'EC', crv: curveName, x: toBase64Url(publicX), y: toBase64Url(publicY) };
}

function concatenate(...parts) {
    const result = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
    let offset = 0;
    for (const part of parts) {
        result.set(part, offset);
        offset += part.length;
    }

    return result;
}

export function aesEncryptBlock(key, input) {
    const cipher = createCipheriv(`aes-${key.length * 8}-ecb`, key, null);
    cipher.setAutoPadding(false);

    return new Uint8Array(Buffer.concat([cipher.update(input), cipher.final()]));
}

// Returns d || x || y, each 32 bytes.
export function p256Generate() {
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: curveName });
    const jwk = privateKey.export({ format: 'jwk' });

    return concatenate(fromBase64Url(jwk.d), fromBase64Url(jwk.x), fromBase64Url(jwk.y));
}

export function p256Sign(privateKey, publicX, publicY, message) {
    const key = createPrivateKey({
        key: { ...publicJwk(publicX, publicY), d: toBase64Url(privateKey) },
        format: 'jwk',
    });

    return new Uint8Array(sign('sha256', message, { key, dsaEncoding: 'ieee-p1363' }));
}

export function p256Verify(publicX, publicY, message, signature) {
    if (signature.length !== 2 * componentSize) {
        return false;
    }

    const key = createPublicKey({ key: publicJwk(publicX, publicY), format: 'jwk' });

    return verify('sha256', message, { key, dsaEncoding: 'ieee-p1363' }, signature);
}

function modulo(value, modulus) {
    return ((value % modulus) + modulus) % modulus;
}

function power(base, exponent, modulus) {
    let result = 1n;
    let factor = modulo(base, modulus);
    for (let remaining = exponent; remaining > 0n; remaining >>= 1n) {
        if ((remaining & 1n) === 1n) {
            result = (result * factor) % modulus;
        }

        factor = (factor * factor) % modulus;
    }

    return result;
}

function invert(value, modulus) {
    return power(value, modulus - 2n, modulus);
}

function addPoints(first, second) {
    if (first === null) {
        return second;
    }

    if (second === null) {
        return first;
    }

    const [x1, y1] = first;
    const [x2, y2] = second;
    let slope;
    if (x1 === x2) {
        if (modulo(y1 + y2, fieldPrime) === 0n) {
            return null;
        }

        slope = modulo((3n * x1 * x1 + curveA) * invert(2n * y1, fieldPrime), fieldPrime);
    } else {
        slope = modulo((y2 - y1) * invert(x2 - x1, fieldPrime), fieldPrime);
    }

    const x3 = modulo(slope * slope - x1 - x2, fieldPrime);

    return [x3, modulo(slope * (x1 - x3) - y1, fieldPrime)];
}

function multiplyPoint(scalar, point) {
    let result = null;
    let addend = point;
    for (let remaining = scalar; remaining > 0n; remaining >>= 1n) {
        if ((remaining & 1n) === 1n) {
            result = addPoints(result, addend);
        }

        addend = addPoints(addend, addend);
    }

    return result;
}

export function p256VerifyDigest(publicX, publicY, digest, signature) {
    if (signature.length !== 2 * componentSize) {
        return false;
    }

    const x = toInteger(publicX);
    const y = toInteger(publicY);
    if (x >= fieldPrime || y >= fieldPrime || modulo(y * y, fieldPrime) !== modulo(x * x * x + curveA * x + curveB, fieldPrime)) {
        return false;
    }

    const r = toInteger(signature.subarray(0, componentSize));
    const s = toInteger(signature.subarray(componentSize));
    if (r < 1n || r >= groupOrder || s < 1n || s >= groupOrder) {
        return false;
    }

    const e = toInteger(digest.subarray(0, componentSize)) % groupOrder;
    const inverse = invert(s, groupOrder);
    const point = addPoints(
        multiplyPoint(modulo(e * inverse, groupOrder), generator),
        multiplyPoint(modulo(r * inverse, groupOrder), [x, y]));

    return point !== null && modulo(point[0], groupOrder) === r;
}

export function p256Agree(privateKey, peerX, peerY) {
    const agreement = createECDH('prime256v1');
    agreement.setPrivateKey(privateKey);

    return new Uint8Array(agreement.computeSecret(concatenate(Uint8Array.of(0x04), peerX, peerY)));
}

// Returns x || y for a P-256 certificate key, or an empty array for any other key type.
export function certificatePublicKey(certificate) {
    const jwk = new X509Certificate(certificate).publicKey.export({ format: 'jwk' });
    if (jwk.kty !== 'EC' || jwk.crv !== curveName) {
        return new Uint8Array(0);
    }

    return concatenate(fromBase64Url(jwk.x), fromBase64Url(jwk.y));
}
