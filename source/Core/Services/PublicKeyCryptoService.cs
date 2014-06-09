namespace Thinktecture.IdentityServer.Core.Services
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
        /// <remarks>
        /// <para>
        /// The results don't appear difficult to convert to a JWK, which is probably a preferential format.
        /// </para>
        /// <para>
        /// An eight-byte header: "ECS2" | 0x20000000 (0x20 => P-256 key size)
        /// 32 bytes of, presumably, the public key curve point x coordinate.
        /// 32 bytes of, presumably, the public key curve point y coordinate.
        /// 32 bytes of the private key integer d.
        /// </para>
        /// <para>
        /// P-384 testing confirms this. In this case the header is "ECS4" | 0x30000000 (0x30 => P-384 key size)
        /// The three 48 byte key components follow as above.
        /// </para>
        /// <para>
        /// P-521 produces the same kind of results. The header is "ECS6" | 0x42000000 (0x42 => P-521 key size)
        /// The three 66 byte key components follow as above.
        /// </para>
        /// </remarks>
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
        /// <remarks>
        /// <para>
        /// The results don't appear difficult to convert to a JWK, which is probably a preferential format.
        /// </para>
        /// <para>
        /// An eight-byte header: "ECS1" | 0x20000000 (0x20 => P-256 key size)
        /// 32 bytes of, presumably, the public key curve point x coordinate.
        /// 32 bytes of, presumably, the public key curve point y coordinate.
        /// </para>
        /// <para>
        /// P-384 testing confirms this. In this case the header is "ECS3" | 0x30000000 (0x30 => P-384 key size)
        /// The two 48 byte key components follow as above.
        /// </para>
        /// <para>
        /// P-521 produces the same kind of results. The header is "ECS5" | 0x42000000 (0x42 => P-521 key size)
        /// The two 66 byte key components follow as above.
        /// </para>
        /// </remarks>
        public static string ExtractPublicKey(string privateKey)
        {
            using (var key = CngKey.Import(Base64Url.Decode(privateKey), CngKeyBlobFormat.EccPrivateBlob))
            {
                return Base64Url.Encode(key.Export(CngKeyBlobFormat.EccPublicBlob));
            }
        }

        /// <summary>
        /// Signs a challenge using the specified private key.
        /// </summary>
        /// <param name="privateKey">The base64url-encoded private signing key to use.</param>
        /// <param name="challenge">The base64url-encoded challenge to sign.</param>
        /// <returns>The resulting base64url-encoded signature.</returns>
        /// <remarks>
        /// The returned signature appears to be the concatenated octet sequences R and S.
        /// If so, this is exactly what we need in order to convert to JWS.
        /// </remarks>
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
