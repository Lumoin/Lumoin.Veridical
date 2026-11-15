using System;
using System.CommandLine;

namespace Lumoin.Veridical.Cli;

/// <summary>
/// The SECDSA subcommands of the command line. Each forwards to <see cref="SecdsaOperations"/>, the same
/// operations the MCP tools call, and maps one-to-one onto a primitive of <c>Lumoin.Veridical.Secdsa</c>.
/// Public values (points, hashes, proofs, salts) are hex options; secret scalars are read only from the file
/// an option names, or standard input for <c>-</c>, and are never echoed.
/// </summary>
internal static class SecdsaCliCommands
{
    /// <summary>Builds <c>secdsa-split-sign</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildSplitSignCommand()
    {
        Option<string> pinKeyFile = SecretFile("--pin-key-file", "the PIN-key scalar P (hex)");
        Option<string> hardwareKeyFile = SecretFile("--hardware-key-file", "the hardware-key scalar u (hex)");
        Option<string> messageHash = Hex("--message-hash", "The message hash e = H(M), 32 bytes as hex.");

        Command command = new("secdsa-split-sign", "SECDSA split sign over software keys: produces a standard ECDSA signature r || s (hex) under d = P*u. The key scalars are read only from their files and are never echoed.")
        {
            pinKeyFile,
            hardwareKeyFile,
            messageHash
        };

        command.SetAction(parseResult =>
        {
            if(!ReadSecret(parseResult, pinKeyFile, "pin key", out string pin) || !ReadSecret(parseResult, hardwareKeyFile, "hardware key", out string hardware))
            {
                return 1;
            }

            return Produce(() => SecdsaOperations.SplitSign(pin, hardware, parseResult.GetValue(messageHash) ?? string.Empty));
        });

        return command;
    }


    /// <summary>Builds <c>secdsa-public-key</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildPublicKeyCommand()
    {
        Option<string> pinKeyFile = SecretFile("--pin-key-file", "the PIN-key scalar P (hex)");
        Option<string> hardwareKeyFile = SecretFile("--hardware-key-file", "the hardware-key scalar u (hex)");

        Command command = new("secdsa-public-key", "Derive the split public key (P*u)*G as a compressed point (hex). The key scalars are read only from their files and are never echoed.")
        {
            pinKeyFile,
            hardwareKeyFile
        };

        command.SetAction(parseResult =>
        {
            if(!ReadSecret(parseResult, pinKeyFile, "pin key", out string pin) || !ReadSecret(parseResult, hardwareKeyFile, "hardware key", out string hardware))
            {
                return 1;
            }

            return Produce(() => SecdsaOperations.DerivePublicKey(pin, hardware));
        });

        return command;
    }


    /// <summary>Builds <c>secdsa-verify</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildVerifyCommand()
    {
        Option<string> publicKey = Hex("--public-key", "The compressed public key, 33 bytes as hex.");
        Option<string> messageHash = Hex("--message-hash", "The message hash, 32 bytes as hex.");
        Option<string> signature = Hex("--signature", "The signature r || s, 64 bytes as hex.");

        Command command = new("secdsa-verify", "Verify an ECDSA signature r || s under a public key (exit non-zero when it does not verify).")
        {
            publicKey,
            messageHash,
            signature
        };

        command.SetAction(parseResult => Report(() => SecdsaOperations.Verify(
            parseResult.GetValue(publicKey) ?? string.Empty,
            parseResult.GetValue(messageHash) ?? string.Empty,
            parseResult.GetValue(signature) ?? string.Empty)));

        return command;
    }


    /// <summary>Builds <c>secdsa-recover-nonce-point</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildRecoverNoncePointCommand()
    {
        Option<string> publicKey = Hex("--public-key", "The compressed public key, 33 bytes as hex.");
        Option<string> messageHash = Hex("--message-hash", "The message hash, 32 bytes as hex.");
        Option<string> signature = Hex("--signature", "The signature r || s, 64 bytes as hex.");

        Command command = new("secdsa-recover-nonce-point", "Recover the nonce point R of a signature as a compressed point (hex).")
        {
            publicKey,
            messageHash,
            signature
        };

        command.SetAction(parseResult => Produce(() => SecdsaOperations.RecoverNoncePoint(
            parseResult.GetValue(publicKey) ?? string.Empty,
            parseResult.GetValue(messageHash) ?? string.Empty,
            parseResult.GetValue(signature) ?? string.Empty)));

        return command;
    }


    /// <summary>Builds <c>secdsa-verify-full</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildVerifyFullCommand()
    {
        Option<string> publicKey = Hex("--public-key", "The compressed public key, 33 bytes as hex.");
        Option<string> messageHash = Hex("--message-hash", "The message hash, 32 bytes as hex.");
        Option<string> noncePoint = Hex("--nonce-point", "The compressed nonce point R, 33 bytes as hex.");
        Option<string> s = Hex("--s", "The component s, 32 bytes as hex.");

        Command command = new("secdsa-verify-full", "Verify a signature given as its nonce point R and s (exit non-zero when it does not verify).")
        {
            publicKey,
            messageHash,
            noncePoint,
            s
        };

        command.SetAction(parseResult => Report(() => SecdsaOperations.VerifyFull(
            parseResult.GetValue(publicKey) ?? string.Empty,
            parseResult.GetValue(messageHash) ?? string.Empty,
            parseResult.GetValue(noncePoint) ?? string.Empty,
            parseResult.GetValue(s) ?? string.Empty)));

        return command;
    }


    /// <summary>Builds <c>secdsa-dl-prove</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildDlEqualityProveCommand()
    {
        Option<string> witnessFile = SecretFile("--witness-file", "the private key d (hex)");
        Option<string> generators = Hex("--generators", "The concatenated compressed generators G_i as hex.");
        Option<string> publicKeys = Hex("--public-keys", "The concatenated compressed public keys D_i = d*G_i as hex.");
        Option<string> challenge = OptionalHex("--challenge", "The challenge byte string N as hex; omit for an empty challenge.");

        Command command = new("secdsa-dl-prove", "Prove that every pair (G_i, D_i) shares one private key d (DL-equality NIZK); writes the proof r || s as hex. The witness is read only from its file and is never echoed.")
        {
            witnessFile,
            generators,
            publicKeys,
            challenge
        };

        command.SetAction(parseResult =>
        {
            if(!ReadSecret(parseResult, witnessFile, "witness", out string witness))
            {
                return 1;
            }

            return Produce(() => SecdsaOperations.DlEqualityProve(
                witness,
                parseResult.GetValue(generators) ?? string.Empty,
                parseResult.GetValue(publicKeys) ?? string.Empty,
                parseResult.GetValue(challenge) ?? string.Empty));
        });

        return command;
    }


    /// <summary>Builds <c>secdsa-dl-verify</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildDlEqualityVerifyCommand()
    {
        Option<string> generators = Hex("--generators", "The concatenated compressed generators G_i as hex.");
        Option<string> publicKeys = Hex("--public-keys", "The concatenated compressed public keys D_i as hex.");
        Option<string> challenge = OptionalHex("--challenge", "The challenge byte string N as hex; omit for an empty challenge.");
        Option<string> proof = Hex("--proof", "The proof r || s, 64 bytes as hex.");

        Command command = new("secdsa-dl-verify", "Verify a DL-equality proof (exit non-zero when it does not verify).")
        {
            generators,
            publicKeys,
            challenge,
            proof
        };

        command.SetAction(parseResult => Report(() => SecdsaOperations.DlEqualityVerify(
            parseResult.GetValue(generators) ?? string.Empty,
            parseResult.GetValue(publicKeys) ?? string.Empty,
            parseResult.GetValue(challenge) ?? string.Empty,
            parseResult.GetValue(proof) ?? string.Empty)));

        return command;
    }


    /// <summary>Builds <c>secdsa-blinding-prove</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildBlindingProveCommand()
    {
        Option<string> g = Hex("--g", "The standard base point G, compressed, as hex.");
        Option<string> gDoublePrime = Hex("--g-double-prime", "The point G'', compressed, as hex.");
        Option<string> yPrime = Hex("--y-prime", "The point Y', compressed, as hex.");
        Option<string> yDoublePrime = Hex("--y-double-prime", "The point Y'', compressed, as hex.");
        Option<string> witnessFile = SecretFile("--witness-file", "the blinding witness (hex)");

        Command command = new("secdsa-blinding-prove", "Prove the blinding relation ZKP[(G,G''),(Y',Y'')]; writes the proof r || s as hex. The witness is read only from its file and is never echoed.")
        {
            g,
            gDoublePrime,
            yPrime,
            yDoublePrime,
            witnessFile
        };

        command.SetAction(parseResult =>
        {
            if(!ReadSecret(parseResult, witnessFile, "witness", out string witness))
            {
                return 1;
            }

            return Produce(() => SecdsaOperations.BlindingRelationProve(
                parseResult.GetValue(g) ?? string.Empty,
                parseResult.GetValue(gDoublePrime) ?? string.Empty,
                parseResult.GetValue(yPrime) ?? string.Empty,
                parseResult.GetValue(yDoublePrime) ?? string.Empty,
                witness));
        });

        return command;
    }


    /// <summary>Builds <c>secdsa-blinding-verify</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildBlindingVerifyCommand()
    {
        Option<string> g = Hex("--g", "The standard base point G, compressed, as hex.");
        Option<string> gDoublePrime = Hex("--g-double-prime", "The point G'', compressed, as hex.");
        Option<string> yPrime = Hex("--y-prime", "The point Y', compressed, as hex.");
        Option<string> yDoublePrime = Hex("--y-double-prime", "The point Y'', compressed, as hex.");
        Option<string> proof = Hex("--proof", "The proof r || s, 64 bytes as hex.");

        Command command = new("secdsa-blinding-verify", "Verify the blinding relation (exit non-zero when it does not verify).")
        {
            g,
            gDoublePrime,
            yPrime,
            yDoublePrime,
            proof
        };

        command.SetAction(parseResult => Report(() => SecdsaOperations.BlindingRelationVerify(
            parseResult.GetValue(g) ?? string.Empty,
            parseResult.GetValue(gDoublePrime) ?? string.Empty,
            parseResult.GetValue(yPrime) ?? string.Empty,
            parseResult.GetValue(yDoublePrime) ?? string.Empty,
            parseResult.GetValue(proof) ?? string.Empty)));

        return command;
    }


    /// <summary>Builds <c>secdsa-control-prove</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildControlProveCommand()
    {
        Option<string> h = Hex("--h", "The point H, compressed, as hex.");
        Option<string> w = Hex("--w", "The point W, compressed, as hex.");
        Option<string> hPrime = Hex("--h-prime", "The point H', compressed, as hex.");
        Option<string> wPrime = Hex("--w-prime", "The point W', compressed, as hex.");
        Option<string> witnessFile = SecretFile("--witness-file", "the control witness (hex)");
        Option<string> recordContext = Hex("--record-context", "The record context T_I as hex.");

        Command command = new("secdsa-control-prove", "Prove the control relation ZKP[(H,H'),(W,W'),H(T_I)]; writes the proof r || s as hex. The witness is read only from its file and is never echoed.")
        {
            h,
            w,
            hPrime,
            wPrime,
            witnessFile,
            recordContext
        };

        command.SetAction(parseResult =>
        {
            if(!ReadSecret(parseResult, witnessFile, "witness", out string witness))
            {
                return 1;
            }

            return Produce(() => SecdsaOperations.ControlRelationProve(
                parseResult.GetValue(h) ?? string.Empty,
                parseResult.GetValue(w) ?? string.Empty,
                parseResult.GetValue(hPrime) ?? string.Empty,
                parseResult.GetValue(wPrime) ?? string.Empty,
                witness,
                parseResult.GetValue(recordContext) ?? string.Empty));
        });

        return command;
    }


    /// <summary>Builds <c>secdsa-control-verify</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildControlVerifyCommand()
    {
        Option<string> h = Hex("--h", "The point H, compressed, as hex.");
        Option<string> w = Hex("--w", "The point W, compressed, as hex.");
        Option<string> hPrime = Hex("--h-prime", "The point H', compressed, as hex.");
        Option<string> wPrime = Hex("--w-prime", "The point W', compressed, as hex.");
        Option<string> recordContext = Hex("--record-context", "The record context T_I as hex.");
        Option<string> proof = Hex("--proof", "The proof r || s, 64 bytes as hex.");

        Command command = new("secdsa-control-verify", "Verify the control relation (exit non-zero when it does not verify).")
        {
            h,
            w,
            hPrime,
            wPrime,
            recordContext,
            proof
        };

        command.SetAction(parseResult => Report(() => SecdsaOperations.ControlRelationVerify(
            parseResult.GetValue(h) ?? string.Empty,
            parseResult.GetValue(w) ?? string.Empty,
            parseResult.GetValue(hPrime) ?? string.Empty,
            parseResult.GetValue(wPrime) ?? string.Empty,
            parseResult.GetValue(recordContext) ?? string.Empty,
            parseResult.GetValue(proof) ?? string.Empty)));

        return command;
    }


    /// <summary>Builds <c>secdsa-ecdh-mac-derive-key</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildEcdhMacDeriveKeyCommand()
    {
        Option<string> privateKeyFile = SecretFile("--private-key-file", "the private scalar (hex)");
        Option<string> peerPublicPoint = Hex("--peer-public-point", "The peer's compressed public point as hex.");
        Option<string> salt = OptionalHex("--salt", "The HKDF salt as hex; omit for an empty salt.");
        Option<string> sharedInfo = OptionalHex("--shared-info", "The HKDF info as hex; omit for empty info.");
        Option<string> output = new("--output") { Description = "Path the derived MAC key (hex) is written to. The file must not exist and is readable by its owner only; the MAC key is never printed.", Required = true };

        Command command = new("secdsa-ecdh-mac-derive-key", "Derive the ECDH-MAC key shared with a peer public point; writes it to --output. The private scalar is read only from its file and is never echoed.")
        {
            privateKeyFile,
            peerPublicPoint,
            salt,
            sharedInfo,
            output
        };

        command.SetAction(parseResult =>
        {
            if(!ReadSecret(parseResult, privateKeyFile, "private key", out string privateKey))
            {
                return 1;
            }

            string macKey;
            try
            {
                macKey = SecdsaOperations.EcdhMacDeriveKey(
                    privateKey,
                    parseResult.GetValue(peerPublicPoint) ?? string.Empty,
                    parseResult.GetValue(salt) ?? string.Empty,
                    parseResult.GetValue(sharedInfo) ?? string.Empty);
            }
            catch(ArgumentException error)
            {
                Console.Error.WriteLine($"Error: {error.Message}");

                return 1;
            }

            if(!CliFiles.TryWriteSecret(parseResult.GetValue(output) ?? string.Empty, macKey, "MAC key file", out string failure))
            {
                Console.Error.WriteLine($"Error: {failure}");

                return 1;
            }

            return 0;
        });

        return command;
    }


    /// <summary>Builds <c>secdsa-ecdh-mac-sign</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildEcdhMacSignCommand()
    {
        Option<string> privateKeyFile = SecretFile("--private-key-file", "the prover's private scalar (hex)");
        Option<string> verifierKey = Hex("--verifier-ephemeral-public-key", "The verifier's ephemeral compressed public key as hex.");
        Option<string> salt = OptionalHex("--salt", "The HKDF salt as hex; omit for an empty salt.");
        Option<string> sharedInfo = OptionalHex("--shared-info", "The HKDF info as hex; omit for empty info.");
        Option<string> message = OptionalHex("--message", "The message as hex; omit for an empty message.");

        Command command = new("secdsa-ecdh-mac-sign", "Compute the ECDH-MAC of a message (hex to standard output). The private scalar is read only from its file and is never echoed.")
        {
            privateKeyFile,
            verifierKey,
            salt,
            sharedInfo,
            message
        };

        command.SetAction(parseResult =>
        {
            if(!ReadSecret(parseResult, privateKeyFile, "private key", out string privateKey))
            {
                return 1;
            }

            return Produce(() => SecdsaOperations.EcdhMacSign(
                privateKey,
                parseResult.GetValue(verifierKey) ?? string.Empty,
                parseResult.GetValue(salt) ?? string.Empty,
                parseResult.GetValue(sharedInfo) ?? string.Empty,
                parseResult.GetValue(message) ?? string.Empty));
        });

        return command;
    }


    /// <summary>Builds <c>secdsa-ecdh-mac-verify</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildEcdhMacVerifyCommand()
    {
        Option<string> proverKey = Hex("--prover-public-key", "The prover's compressed public key as hex.");
        Option<string> verifierKeyFile = SecretFile("--verifier-ephemeral-private-key-file", "the verifier's ephemeral private scalar (hex)");
        Option<string> salt = OptionalHex("--salt", "The HKDF salt as hex; omit for an empty salt.");
        Option<string> sharedInfo = OptionalHex("--shared-info", "The HKDF info as hex; omit for empty info.");
        Option<string> message = OptionalHex("--message", "The message as hex; omit for an empty message.");
        Option<string> mac = Hex("--mac", "The MAC, 32 bytes as hex.");

        Command command = new("secdsa-ecdh-mac-verify", "Verify an ECDH-MAC (exit non-zero when it does not verify). The verifier's private scalar is read only from its file and is never echoed.")
        {
            proverKey,
            verifierKeyFile,
            salt,
            sharedInfo,
            message,
            mac
        };

        command.SetAction(parseResult =>
        {
            if(!ReadSecret(parseResult, verifierKeyFile, "verifier ephemeral private key", out string verifierKey))
            {
                return 1;
            }

            return Report(() => SecdsaOperations.EcdhMacVerify(
                parseResult.GetValue(proverKey) ?? string.Empty,
                verifierKey,
                parseResult.GetValue(salt) ?? string.Empty,
                parseResult.GetValue(sharedInfo) ?? string.Empty,
                parseResult.GetValue(message) ?? string.Empty,
                parseResult.GetValue(mac) ?? string.Empty));
        });

        return command;
    }


    /// <summary>Builds <c>secdsa-ecdh-mac-split-sign</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildEcdhMacSplitSignCommand()
    {
        Option<string> walletShareFile = SecretFile("--wallet-key-share-file", "the wallet key share (hex)");
        Option<string> wscaShareFile = SecretFile("--wsca-key-share-file", "the WSCA key share (hex)");
        Option<string> baseKeyFile = SecretFile("--base-key-file", "the base key (hex)");
        Option<string> verifierKey = Hex("--verifier-ephemeral-public-key", "The verifier's ephemeral compressed public key as hex.");
        Option<string> salt = OptionalHex("--salt", "The HKDF salt as hex; omit for an empty salt.");
        Option<string> sharedInfo = OptionalHex("--shared-info", "The HKDF info as hex; omit for empty info.");
        Option<string> message = OptionalHex("--message", "The message as hex; omit for an empty message.");

        Command command = new("secdsa-ecdh-mac-split-sign", "Compute the ECDH-MAC from the wallet and WSCA key shares and the base key (hex to standard output). The shares are read only from their files and are never echoed.")
        {
            walletShareFile,
            wscaShareFile,
            baseKeyFile,
            verifierKey,
            salt,
            sharedInfo,
            message
        };

        command.SetAction(parseResult =>
        {
            if(!ReadSecret(parseResult, walletShareFile, "wallet key share", out string walletShare)
                || !ReadSecret(parseResult, wscaShareFile, "WSCA key share", out string wscaShare)
                || !ReadSecret(parseResult, baseKeyFile, "base key", out string baseKey))
            {
                return 1;
            }

            return Produce(() => SecdsaOperations.EcdhMacSplitSign(
                walletShare,
                wscaShare,
                baseKey,
                parseResult.GetValue(verifierKey) ?? string.Empty,
                parseResult.GetValue(salt) ?? string.Empty,
                parseResult.GetValue(sharedInfo) ?? string.Empty,
                parseResult.GetValue(message) ?? string.Empty));
        });

        return command;
    }


    /// <summary>Builds <c>secdsa-split-sign-prepare</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildSplitSignPrepareCommand()
    {
        Option<string> pinKeyFile = SecretFile("--pin-key-file", "the PIN-key scalar P (hex)");
        Option<string> messageHash = Hex("--message-hash", "The message hash e = H(M), 32 bytes as hex.");
        Option<string> output = new("--output") { Description = "Path the blinded representative e' (hex) is written to, for the key holder's raw ECDSA sign. The file must not exist and is readable by its owner only; e' is never printed, because e' together with the message hash reveals P.", Required = true };

        Command command = new("secdsa-split-sign-prepare", "SECDSA split sign, prepare phase: writes the blinded representative e' = P^-1 * e to --output; the key holder raw-ECDSA-signs e' under its key and returns (r, s0). The PIN key is read only from its file and is never echoed.")
        {
            pinKeyFile,
            messageHash,
            output
        };

        command.SetAction(parseResult =>
        {
            if(!ReadSecret(parseResult, pinKeyFile, "pin key", out string pinKey))
            {
                return 1;
            }

            return ProduceToSecretFile(
                () => SecdsaOperations.SplitSignPrepare(pinKey, parseResult.GetValue(messageHash) ?? string.Empty),
                parseResult.GetValue(output) ?? string.Empty,
                "blinded representative file");
        });

        return command;
    }


    /// <summary>Builds <c>secdsa-split-sign-complete</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildSplitSignCompleteCommand()
    {
        Option<string> pinKeyFile = SecretFile("--pin-key-file", "the PIN-key scalar P (hex)");
        Option<string> messageHash = Hex("--message-hash", "The message hash e = H(M) given to the prepare phase, 32 bytes as hex.");
        Option<string> publicKey = Hex("--public-key", "The composite compressed public key Y = (P*u)*G, 33 bytes as hex.");
        Option<string> rawSignatureFile = SecretFile("--raw-signature-file", "the key holder's raw signature r || s0 (hex, 64 bytes)");

        Command command = new("secdsa-split-sign-complete", "SECDSA split sign, complete phase: masks the key holder's raw signature r || s0 with the PIN key and prints the ECDSA signature r || s (hex) only if it verifies under the public key; exits non-zero and prints nothing otherwise. The PIN key and s0 are read only from their files and are never echoed.")
        {
            pinKeyFile,
            messageHash,
            publicKey,
            rawSignatureFile
        };

        command.SetAction(parseResult =>
        {
            if(!ReadSecret(parseResult, pinKeyFile, "pin key", out string pinKey) || !ReadSecret(parseResult, rawSignatureFile, "raw signature", out string rawSignature))
            {
                return 1;
            }

            return Produce(() => SecdsaOperations.SplitSignComplete(
                pinKey,
                parseResult.GetValue(messageHash) ?? string.Empty,
                parseResult.GetValue(publicKey) ?? string.Empty,
                rawSignature));
        });

        return command;
    }


    /// <summary>Builds <c>secdsa-ecdh-mac-prepare</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildEcdhMacPrepareCommand()
    {
        Option<string> peerPublicKey = Hex("--peer-public-key", "The verifier's ephemeral compressed public key as hex.");

        Command command = new("secdsa-ecdh-mac-prepare", "ECDH-MAC prepare phase: validates the verifier's ephemeral public key (length, not infinity, on the curve) and prints the canonical point (hex) to send to the key holder's ECDH.")
        {
            peerPublicKey
        };

        command.SetAction(parseResult => Produce(() => SecdsaOperations.EcdhMacPrepare(parseResult.GetValue(peerPublicKey) ?? string.Empty)));

        return command;
    }


    /// <summary>Builds <c>secdsa-ecdh-mac-apply-key-share</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildEcdhMacApplyKeyShareCommand()
    {
        Option<string> keyShareFile = SecretFile("--key-share-file", "the key-share scalar (hex)");
        Option<string> point = Hex("--point", "The compressed point to multiply as hex: the verifier's ephemeral key for the wallet, the wallet's output for the WSCA.");

        Command command = new("secdsa-ecdh-mac-apply-key-share", "Split ECDH-MAC, wallet and WSCA step: multiplies a point by the party's key share (E' = zU*E, E'' = zW*E') and prints the compressed product (hex). The key share is read only from its file and is never echoed.")
        {
            keyShareFile,
            point
        };

        command.SetAction(parseResult =>
        {
            if(!ReadSecret(parseResult, keyShareFile, "key share", out string keyShare))
            {
                return 1;
            }

            return Produce(() => SecdsaOperations.EcdhMacApplyKeyShare(keyShare, parseResult.GetValue(point) ?? string.Empty));
        });

        return command;
    }


    /// <summary>Builds <c>secdsa-ecdh-mac-complete-sign</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildEcdhMacCompleteSignCommand()
    {
        Option<string> sharedSecretFile = SecretFile("--shared-secret-file", "the shared secret Z_AB the key holder's ECDH returned (hex, 32 bytes)");
        Option<string> salt = OptionalHex("--salt", "The HKDF salt as hex; omit for an empty salt.");
        Option<string> sharedInfo = OptionalHex("--shared-info", "The HKDF info as hex; omit for empty info.");
        Option<string> message = OptionalHex("--message", "The message as hex; omit for an empty message.");

        Command command = new("secdsa-ecdh-mac-complete-sign", "ECDH-MAC complete phase for signing: derives K = HKDF(Z_AB, SharedInfo) from the key holder's shared secret and prints the MAC (hex). The shared secret is read only from its file and is never echoed.")
        {
            sharedSecretFile,
            salt,
            sharedInfo,
            message
        };

        command.SetAction(parseResult =>
        {
            if(!ReadSecret(parseResult, sharedSecretFile, "shared secret", out string sharedSecret))
            {
                return 1;
            }

            return Produce(() => SecdsaOperations.EcdhMacCompleteSign(
                sharedSecret,
                parseResult.GetValue(salt) ?? string.Empty,
                parseResult.GetValue(sharedInfo) ?? string.Empty,
                parseResult.GetValue(message) ?? string.Empty));
        });

        return command;
    }


    /// <summary>Builds <c>secdsa-ecdh-mac-complete-verify</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildEcdhMacCompleteVerifyCommand()
    {
        Option<string> sharedSecretFile = SecretFile("--shared-secret-file", "the shared secret Z_AB the verifier's key holder returned (hex, 32 bytes)");
        Option<string> salt = OptionalHex("--salt", "The HKDF salt as hex; omit for an empty salt.");
        Option<string> sharedInfo = OptionalHex("--shared-info", "The HKDF info as hex; omit for empty info.");
        Option<string> message = OptionalHex("--message", "The message as hex; omit for an empty message.");
        Option<string> mac = Hex("--mac", "The MAC, 32 bytes as hex.");

        Command command = new("secdsa-ecdh-mac-complete-verify", "ECDH-MAC complete phase for verification: derives K from the verifier's key holder's shared secret and compares the MAC in constant time (exit non-zero when it does not verify). The shared secret is read only from its file and is never echoed.")
        {
            sharedSecretFile,
            salt,
            sharedInfo,
            message,
            mac
        };

        command.SetAction(parseResult =>
        {
            if(!ReadSecret(parseResult, sharedSecretFile, "shared secret", out string sharedSecret))
            {
                return 1;
            }

            return Report(() => SecdsaOperations.EcdhMacCompleteVerify(
                sharedSecret,
                parseResult.GetValue(salt) ?? string.Empty,
                parseResult.GetValue(sharedInfo) ?? string.Empty,
                parseResult.GetValue(message) ?? string.Empty,
                parseResult.GetValue(mac) ?? string.Empty));
        });

        return command;
    }


    /// <summary>Builds <c>secdsa-ecdh-mac-verify-mac</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildEcdhMacVerifyMacCommand()
    {
        Option<string> macKeyFile = SecretFile("--mac-key-file", "the MAC key K the key holder derived (hex)");
        Option<string> message = OptionalHex("--message", "The message as hex; omit for an empty message.");
        Option<string> mac = Hex("--mac", "The MAC, 32 bytes as hex.");

        Command command = new("secdsa-ecdh-mac-verify-mac", "Verify an ECDH-MAC under a MAC key the key holder derived itself, comparing in constant time (exit non-zero when it does not verify). The key is read only from its file and is never echoed.")
        {
            macKeyFile,
            message,
            mac
        };

        command.SetAction(parseResult =>
        {
            if(!ReadSecret(parseResult, macKeyFile, "MAC key", out string macKey))
            {
                return 1;
            }

            return Report(() => SecdsaOperations.EcdhMacVerifyMac(
                macKey,
                parseResult.GetValue(message) ?? string.Empty,
                parseResult.GetValue(mac) ?? string.Empty));
        });

        return command;
    }


    /// <summary>Builds <c>secdsa-result-prove</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildResultProveCommand()
    {
        Option<string> publicKey = Hex("--public-key", "The user public key Q_U, 33 bytes as hex.");
        Option<string> messageHash = Hex("--message-hash", "The message hash, 32 bytes as hex.");
        Option<string> signature = Hex("--signature", "The signature r || s, 64 bytes as hex.");

        Command command = new("secdsa-result-prove", "Signature-result conformity, prover side: proves that a signature result is consistent with the user key and prints the record (R, G'', Q_U'', proof) as hex.")
        {
            publicKey,
            messageHash,
            signature
        };

        command.SetAction(parseResult => Produce(() => SecdsaProofOperations.ResultProve(
            parseResult.GetValue(publicKey) ?? string.Empty,
            parseResult.GetValue(messageHash) ?? string.Empty,
            parseResult.GetValue(signature) ?? string.Empty)));

        return command;
    }


    /// <summary>Builds <c>secdsa-result-check</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildResultCheckCommand()
    {
        Option<string> publicKey = Hex("--public-key", "The user public key Q_U, 33 bytes as hex.");
        Option<string> messageHash = Hex("--message-hash", "The message hash, 32 bytes as hex.");
        Option<string> record = Hex("--record", "The record produced by secdsa-result-prove, as hex.");

        Command command = new("secdsa-result-check", "Signature-result conformity, verifier side: checks the proof and the nonce-point equation of a record (exit non-zero on a compromise alarm).")
        {
            publicKey,
            messageHash,
            record
        };

        command.SetAction(parseResult => Report(() => SecdsaProofOperations.ResultCheck(
            parseResult.GetValue(publicKey) ?? string.Empty,
            parseResult.GetValue(messageHash) ?? string.Empty,
            parseResult.GetValue(record) ?? string.Empty)));

        return command;
    }


    /// <summary>Builds <c>secdsa-ecies-encrypt</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildEciesEncryptCommand()
    {
        Option<string> recipientPublicKey = Hex("--recipient-public-key", "The recipient public key, 33 bytes as hex.");
        Option<string> plaintextFile = SecretFile("--plaintext-file", "the plaintext (hex)");
        Option<string> associatedData = OptionalHex("--aad", "The additional authenticated data as hex; omit for none.");

        Command command = new("secdsa-ecies-encrypt", "ECIES encryption (X9.63 over SHA-256, AES-256-GCM, 96-bit IV, 128-bit tag): prints the ciphertext E || T || C as hex. The plaintext is read only from its file and is never echoed.")
        {
            recipientPublicKey,
            plaintextFile,
            associatedData
        };

        command.SetAction(parseResult =>
        {
            if(!ReadSecret(parseResult, plaintextFile, "plaintext", out string plaintext))
            {
                return 1;
            }

            return Produce(() => SecdsaProofOperations.EciesEncrypt(
                parseResult.GetValue(recipientPublicKey) ?? string.Empty, plaintext, parseResult.GetValue(associatedData) ?? string.Empty));
        });

        return command;
    }


    /// <summary>Builds <c>secdsa-ecies-decrypt</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildEciesDecryptCommand()
    {
        Option<string> privateKeyFile = SecretFile("--private-key-file", "the recipient private scalar (hex)");
        Option<string> ciphertext = Hex("--ciphertext", "The ciphertext E || T || C as hex.");
        Option<string> associatedData = OptionalHex("--aad", "The additional authenticated data as hex; omit for none.");
        Option<string> output = PlaintextOutput();

        Command command = new("secdsa-ecies-decrypt", "ECIES decryption with the private key in this process: writes the plaintext (hex) to --output only if the tag verifies; exits non-zero and writes nothing otherwise. The key is read only from its file and is never echoed.")
        {
            privateKeyFile,
            ciphertext,
            associatedData,
            output
        };

        command.SetAction(parseResult =>
        {
            if(!ReadSecret(parseResult, privateKeyFile, "private key", out string privateKey))
            {
                return 1;
            }

            return ProduceToSecretFile(
                () => SecdsaProofOperations.EciesDecrypt(privateKey, parseResult.GetValue(ciphertext) ?? string.Empty, parseResult.GetValue(associatedData) ?? string.Empty),
                parseResult.GetValue(output) ?? string.Empty,
                "plaintext file");
        });

        return command;
    }


    /// <summary>Builds <c>secdsa-ecies-prepare-decryption</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildEciesPrepareDecryptionCommand()
    {
        Option<string> ciphertext = Hex("--ciphertext", "The ciphertext E || T || C as hex.");

        Command command = new("secdsa-ecies-prepare-decryption", "ECIES decryption, prepare phase: validates the ephemeral public key E of a ciphertext (not infinity, on the curve, canonical) and prints it (hex) to send to the key holder's ECDH.")
        {
            ciphertext
        };

        command.SetAction(parseResult => Produce(() => SecdsaProofOperations.EciesPrepareDecryption(parseResult.GetValue(ciphertext) ?? string.Empty)));

        return command;
    }


    /// <summary>Builds <c>secdsa-ecies-agree</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildEciesAgreeCommand()
    {
        Option<string> privateKeyFile = SecretFile("--private-key-file", "the private scalar (hex)");
        Option<string> point = Hex("--point", "The compressed point to agree with, such as the ephemeral public key, as hex.");
        Option<string> output = new("--output") { Description = "Path the shared secret Z_AB (hex) is written to. The file must not exist and is readable by its owner only; Z_AB is never printed.", Required = true };

        Command command = new("secdsa-ecies-agree", "The key holder's raw agreement in software: writes Z_AB = x(d*E) (hex) to --output. The key is read only from its file and is never echoed.")
        {
            privateKeyFile,
            point,
            output
        };

        command.SetAction(parseResult =>
        {
            if(!ReadSecret(parseResult, privateKeyFile, "private key", out string privateKey))
            {
                return 1;
            }

            return ProduceToSecretFile(
                () => SecdsaProofOperations.EciesAgree(privateKey, parseResult.GetValue(point) ?? string.Empty),
                parseResult.GetValue(output) ?? string.Empty,
                "shared secret file");
        });

        return command;
    }


    /// <summary>Builds <c>secdsa-ecies-complete-decryption</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildEciesCompleteDecryptionCommand()
    {
        Option<string> sharedSecretFile = SecretFile("--shared-secret-file", "the shared secret Z_AB the key holder returned (hex, 32 bytes)");
        Option<string> ciphertext = Hex("--ciphertext", "The ciphertext E || T || C as hex.");
        Option<string> associatedData = OptionalHex("--aad", "The additional authenticated data as hex; omit for none.");
        Option<string> output = PlaintextOutput();

        Command command = new("secdsa-ecies-complete-decryption", "ECIES decryption, complete phase: derives the key from the key holder's shared secret and writes the plaintext (hex) to --output only if the tag verifies. The shared secret is read only from its file and is never echoed.")
        {
            sharedSecretFile,
            ciphertext,
            associatedData,
            output
        };

        command.SetAction(parseResult =>
        {
            if(!ReadSecret(parseResult, sharedSecretFile, "shared secret", out string sharedSecret))
            {
                return 1;
            }

            return ProduceToSecretFile(
                () => SecdsaProofOperations.EciesCompleteDecryption(sharedSecret, parseResult.GetValue(ciphertext) ?? string.Empty, parseResult.GetValue(associatedData) ?? string.Empty),
                parseResult.GetValue(output) ?? string.Empty,
                "plaintext file");
        });

        return command;
    }


    /// <summary>Builds <c>secdsa-proof-challenge</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildProofChallengeCommand()
    {
        Option<string> signingKeyFile = SecretFile("--signing-key-file", "the challenger's signing scalar (hex)");
        Option<string> generators = Hex("--generators", "The concatenated compressed generators G_0..G_n as hex.");
        Option<string> publicKeys = Hex("--public-keys", "The concatenated compressed public keys D_0..D_n as hex, pairwise with the generators.");
        Option<string> associatedData = OptionalHex("--aad", "The additional authenticated data as hex; omit for none.");
        Option<string> secretDataFile = new("--additional-secret-data-file") { Description = "Path to a file holding the additional secret data (hex), or - for standard input; omit for none." };
        Option<string> layout = Layout();

        Command command = new("secdsa-proof-challenge", "Transferable proof, challenge generation (Algorithm 22): prints a JSON object with the signed challenge and the ECIES ciphertext (hex). The key and the additional secret data are read only from files and are never echoed.")
        {
            signingKeyFile,
            generators,
            publicKeys,
            associatedData,
            secretDataFile,
            layout
        };

        command.SetAction(parseResult =>
        {
            if(!ReadSecret(parseResult, signingKeyFile, "signing key", out string signingKey) || !ReadOptionalSecret(parseResult, secretDataFile, "additional secret data", out string secretData))
            {
                return 1;
            }

            return Produce(() => SecdsaProofOperations.ProofChallenge(
                signingKey,
                parseResult.GetValue(generators) ?? string.Empty,
                parseResult.GetValue(publicKeys) ?? string.Empty,
                parseResult.GetValue(associatedData) ?? string.Empty,
                secretData,
                parseResult.GetValue(layout) ?? SecdsaProofOperations.ProvisionalLayoutName));
        });

        return command;
    }


    /// <summary>Builds <c>secdsa-proof-respond-prepare</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildProofRespondPrepareCommand()
    {
        Option<string> challenge = Hex("--challenge", "The challenge as hex.");
        Option<string> generators = Hex("--generators", "The concatenated compressed generators as hex.");
        Option<string> publicKeys = Hex("--public-keys", "The concatenated compressed public keys as hex.");
        Option<string> associatedData = OptionalHex("--aad", "The additional authenticated data the prover expects, as hex; omit for none.");
        Option<string> challengerPublicKey = Hex("--challenger-public-key", "The challenger's public key S, 33 bytes as hex.");
        Option<string> layout = Layout();

        Command command = new("secdsa-proof-respond-prepare", "Transferable proof, response prepare phase (Algorithm 23 steps 1 to 4): verifies the challenge for the statement and prints the validated ephemeral public key E (hex) to send to the key holder's ECDH.")
        {
            challenge,
            generators,
            publicKeys,
            associatedData,
            challengerPublicKey,
            layout
        };

        command.SetAction(parseResult => Produce(() => SecdsaProofOperations.ProofRespondPrepare(
            parseResult.GetValue(challenge) ?? string.Empty,
            parseResult.GetValue(generators) ?? string.Empty,
            parseResult.GetValue(publicKeys) ?? string.Empty,
            parseResult.GetValue(associatedData) ?? string.Empty,
            parseResult.GetValue(challengerPublicKey) ?? string.Empty,
            parseResult.GetValue(layout) ?? SecdsaProofOperations.ProvisionalLayoutName)));

        return command;
    }


    /// <summary>Builds <c>secdsa-proof-respond-complete</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildProofRespondCompleteCommand()
    {
        Option<string> sharedSecretFile = SecretFile("--shared-secret-file", "the shared secret Z_AB the key holder returned (hex, 32 bytes)");
        Option<string> challenge = Hex("--challenge", "The challenge as hex.");
        Option<string> ciphertext = Hex("--ciphertext", "The ECIES ciphertext E || T || C as hex.");
        Option<string> generators = Hex("--generators", "The concatenated compressed generators as hex.");
        Option<string> publicKeys = Hex("--public-keys", "The concatenated compressed public keys as hex.");
        Option<string> associatedData = OptionalHex("--aad", "The additional authenticated data the prover expects, as hex; omit for none.");
        Option<string> signingKeyFile = SecretFile("--signing-key-file", "the prover's record signing scalar (hex)");
        Option<string> challengerPublicKey = Hex("--challenger-public-key", "The challenger's public key S, 33 bytes as hex, under which the challenge signature is verified.");
        Option<string> layout = Layout();
        Option<string> secretDataOutput = new("--additional-secret-data-output") { Description = "Path the recovered additional secret data (hex) is written to. The file must not exist and is readable by its owner only; the data is never printed." };

        Command command = new("secdsa-proof-respond-complete", "Transferable proof, response complete phase (Algorithm 23 steps 4 and 6 to 15): verifies the challenge signature, decrypts the seed with the key holder's shared secret, repeats the decryption under the key from the public keys (step 11), and prints the signed response (hex). The additional secret data goes to --additional-secret-data-output. Exits non-zero and prints nothing if any check fails.")
        {
            sharedSecretFile,
            challenge,
            ciphertext,
            generators,
            publicKeys,
            associatedData,
            signingKeyFile,
            challengerPublicKey,
            layout,
            secretDataOutput
        };

        command.SetAction(parseResult =>
        {
            if(!ReadSecret(parseResult, sharedSecretFile, "shared secret", out string sharedSecret) || !ReadSecret(parseResult, signingKeyFile, "signing key", out string signingKey))
            {
                return 1;
            }

            ProofResponseResult result;
            try
            {
                result = SecdsaProofOperations.ProofRespondComplete(
                    sharedSecret,
                    parseResult.GetValue(challenge) ?? string.Empty,
                    parseResult.GetValue(ciphertext) ?? string.Empty,
                    parseResult.GetValue(generators) ?? string.Empty,
                    parseResult.GetValue(publicKeys) ?? string.Empty,
                    parseResult.GetValue(associatedData) ?? string.Empty,
                    signingKey,
                    parseResult.GetValue(challengerPublicKey) ?? string.Empty,
                    parseResult.GetValue(layout) ?? SecdsaProofOperations.ProvisionalLayoutName);
            }
            catch(ArgumentException error)
            {
                Console.Error.WriteLine($"Error: {error.Message}");

                return 1;
            }

            string outputPath = parseResult.GetValue(secretDataOutput) ?? string.Empty;
            if(outputPath.Length > 0 && !CliFiles.TryWriteSecret(outputPath, result.AdditionalSecretData, "additional secret data file", out string failure))
            {
                Console.Error.WriteLine($"Error: {failure}");

                return 1;
            }

            Console.WriteLine(result.Response);

            return 0;
        });

        return command;
    }


    /// <summary>Builds <c>secdsa-proof-verify</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildProofVerifyCommand()
    {
        Option<string> challenge = Hex("--challenge", "The challenge as hex.");
        Option<string> response = Hex("--response", "The response as hex.");
        Option<string> generators = Hex("--generators", "The concatenated compressed generators as hex.");
        Option<string> publicKeys = Hex("--public-keys", "The concatenated compressed public keys as hex.");
        Option<string> associatedData = OptionalHex("--aad", "The additional authenticated data as hex; omit for none.");
        Option<string> challengerPublicKey = Hex("--challenger-public-key", "The challenger's public key S, 33 bytes as hex.");
        Option<string> proverPublicKey = Hex("--prover-public-key", "The prover's record public key V, 33 bytes as hex.");
        Option<string> layout = Layout();

        Command command = new("secdsa-proof-verify", "Transferable proof, verification by a third party (Algorithm 24): checks the profile, the statement, both signatures and H2 = H(H1) (exit non-zero when the proof is rejected).")
        {
            challenge,
            response,
            generators,
            publicKeys,
            associatedData,
            challengerPublicKey,
            proverPublicKey,
            layout
        };

        command.SetAction(parseResult => Report(() => SecdsaProofOperations.ProofVerify(
            parseResult.GetValue(challenge) ?? string.Empty,
            parseResult.GetValue(response) ?? string.Empty,
            parseResult.GetValue(generators) ?? string.Empty,
            parseResult.GetValue(publicKeys) ?? string.Empty,
            parseResult.GetValue(associatedData) ?? string.Empty,
            parseResult.GetValue(challengerPublicKey) ?? string.Empty,
            parseResult.GetValue(proverPublicKey) ?? string.Empty,
            parseResult.GetValue(layout) ?? SecdsaProofOperations.ProvisionalLayoutName)));

        return command;
    }


    private static Option<string> Layout() => new Option<string>("--layout")
    {
        Description = "The byte layout of the signed structures and of the challenge, ciphertext and response: provisional (length-prefixed binary), der (ASN.1 DER) or cbor (deterministic CBOR). A value formed under one layout is rejected under another.",
        DefaultValueFactory = _ => SecdsaProofOperations.ProvisionalLayoutName
    }.AcceptOnlyFromAmong(SecdsaProofOperations.LayoutNames);


    private static Option<string> PlaintextOutput() => new("--output") { Description = "Path the plaintext (hex) is written to. The file must not exist and is readable by its owner only; the plaintext is never printed.", Required = true };


    private static bool ReadOptionalSecret(ParseResult parseResult, Option<string> option, string what, out string secret)
    {
        string path = parseResult.GetValue(option) ?? string.Empty;
        if(path.Length == 0)
        {
            secret = string.Empty;

            return true;
        }

        return ReadSecret(parseResult, option, what, out secret);
    }


    private static int ProduceToSecretFile(Func<string> operation, string outputPath, string what)
    {
        string secret;
        try
        {
            secret = operation();
        }
        catch(ArgumentException error)
        {
            Console.Error.WriteLine($"Error: {error.Message}");

            return 1;
        }

        if(!CliFiles.TryWriteSecret(outputPath, secret, what, out string failure))
        {
            Console.Error.WriteLine($"Error: {failure}");

            return 1;
        }

        return 0;
    }


    private static Option<string> Hex(string name, string description) => new(name) { Description = description, Required = true };


    private static Option<string> OptionalHex(string name, string description) => new(name) { Description = description, DefaultValueFactory = _ => string.Empty };


    private static Option<string> SecretFile(string name, string what) => new(name) { Description = $"Path to a file holding {what}, or - for standard input. Secrets are read only from here, never from an argument value, and are never echoed.", Required = true };


    private static bool ReadSecret(ParseResult parseResult, Option<string> option, string what, out string secret)
    {
        if(Program.TryReadInput(parseResult.GetValue(option) ?? string.Empty, what, out string text))
        {
            secret = text.Trim();

            return true;
        }

        secret = string.Empty;

        return false;
    }


    private static int Produce(Func<string> operation)
    {
        try
        {
            Console.WriteLine(operation());

            return 0;
        }
        catch(ArgumentException error)
        {
            Console.Error.WriteLine($"Error: {error.Message}");

            return 1;
        }
    }


    private static int Report(Func<VerificationResult> operation)
    {
        VerificationResult result = operation();
        Console.WriteLine(result.ToReport());

        return result.IsValid ? 0 : 1;
    }
}
