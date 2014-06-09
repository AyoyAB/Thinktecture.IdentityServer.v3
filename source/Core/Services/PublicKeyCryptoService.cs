﻿namespace Thinktecture.IdentityServer.Core.Services
{
    using System.Security.Cryptography;
    using System.Text;

    using Thinktecture.IdentityModel;

    /// <summary>
    /// The public key crypto service provider.
    /// </summary>
    public static class PublicKeyCryptoService
    {
        /// <summary>
        /// The size of generated challenges.
        /// </summary>
        private const int ChallengeSize = 16;

        /// <summary>
        /// The public key algorithm to use.
        /// </summary>
        private static readonly CngAlgorithm PublicKeyAlgorithm = CngAlgorithm.ECDsaP256;

        /// <summary>
        /// The hash algorithm to use.
        /// </summary>
        private static readonly CngAlgorithm HashAlgorithm = CngAlgorithm.Sha256;

        /// <summary>
        /// Generates a challenge string to sign.
        /// </summary>
        /// <returns>
        /// The base64url-encoded generated challenge.
        /// </returns>
        public static string GenerateChallenge()
        {
            var bytes = new byte[ChallengeSize];

            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(bytes);
            }

            return Base64Url.Encode(bytes);
        }

        /// <summary>
        /// Generates a private signing key.
        /// </summary>
        /// <returns>The base64url-encoded private key.</returns>
        public static string GeneratePrivateKey()
        {
            using (
                var key = CngKey.Create(
                    PublicKeyAlgorithm,
                    null,
                    new CngKeyCreationParameters { ExportPolicy = CngExportPolicies.AllowPlaintextExport }))
            {
                return Base64Url.Encode(key.Export(CngKeyBlobFormat.EccPrivateBlob));
            }
        }

        /// <summary>
        /// Extracts the public key from a private key.
        /// </summary>
        /// <param name="privateKey">he base64url-encoded private key.</param>
        /// <returns>The base64url-encoded public key.</returns>
        public static string ExtractPublicKey(string privateKey)
        {
            using (var key = CngKey.Import(Base64Url.Decode(privateKey), CngKeyBlobFormat.EccPrivateBlob))
            {
                return Base64Url.Encode(key.Export(CngKeyBlobFormat.EccPublicBlob));
            }
        }

        /// <summary>
        /// Signs a challenge using the specified private key and hash algorithm.
        /// </summary>
        /// <param name="privateKey">The base64url-encoded private signing key to use.</param>
        /// <param name="challenge">The base64url-encoded challenge to sign.</param>
        /// <returns>The resulting base64url-encoded signature.</returns>
        public static string SignChallenge(string privateKey, string challenge)
        {
            using (var key = CngKey.Import(Base64Url.Decode(privateKey), CngKeyBlobFormat.EccPrivateBlob))
            {
                using (var signer = new ECDsaCng(key))
                {
                    signer.HashAlgorithm = HashAlgorithm;
                    var signature = signer.SignData(Encoding.ASCII.GetBytes(challenge));

                    return Base64Url.Encode(signature);
                }
            }
        }

        /// <summary>
        /// Verifies a signature against a specified public key and challenge.
        /// </summary>
        /// <param name="publicKey">The base64url-encoded public key.</param>
        /// <param name="challenge">The base64url-encoded challenge.</param>
        /// <param name="signature">The base64url-encoded signature.</param>
        /// <returns>True if the signature was successfully verified.</returns>
        public static bool VerifySignature(string publicKey, string challenge, string signature)
        {
            try
            {
                using (var key = CngKey.Import(Base64Url.Decode(publicKey), CngKeyBlobFormat.EccPublicBlob))
                {
                    using (var verifier = new ECDsaCng(key))
                    {
                        return verifier.VerifyData(Encoding.ASCII.GetBytes(challenge), Base64Url.Decode(signature));
                    }
                }
            }
            catch
            {
                return false;
            }
        }
    }
}
