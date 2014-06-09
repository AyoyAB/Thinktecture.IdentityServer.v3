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
        /// Random number generator.
        /// </summary>
        private static readonly RandomNumberGenerator Rng = new RNGCryptoServiceProvider();

        /// <summary>
        /// Generates a base64url-encoded challenge string to sign.
        /// </summary>
        /// <returns>
        /// The generated challenge.
        /// </returns>
        public static string GenerateChallenge()
        {
            var bytes = new byte[16];

            Rng.GetBytes(bytes);

            return Base64Url.Encode(bytes);
        }

        /// <summary>
        /// Signs a challenge using the specified key and hash algorithm.
        /// </summary>
        /// <param name="key">The signing key to use.</param>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <param name="challenge">The base64url-encoded challenge to sign.</param>
        /// <returns>The resulting base64url-encoded signature.</returns>
        public static string SignChallenge(CngKey key, CngAlgorithm hashAlgorithm, string challenge)
        {
            using (var signer = new ECDsaCng(key))
            {
                signer.HashAlgorithm = hashAlgorithm;
                var signature = signer.SignData(Encoding.ASCII.GetBytes(challenge));

                return Base64Url.Encode(signature);
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
                using (
                    var verifier =
                        new ECDsaCng(CngKey.Import(Base64Url.Decode(publicKey), CngKeyBlobFormat.EccPublicBlob)))
                {
                    return verifier.VerifyData(Encoding.ASCII.GetBytes(challenge), Base64Url.Decode(signature));
                }
            }
            catch
            {
                return false;
            }
        }
    }
}
