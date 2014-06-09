namespace Thinktecture.IdentityServer.Tests.Plumbing
{
    using System.Security.Claims;
    using System.Security.Cryptography;

    using Thinktecture.IdentityModel;
    using Thinktecture.IdentityServer.Core;
    using Thinktecture.IdentityServer.Core.Services.InMemory;

    /// <summary>
    /// Public key test users.
    /// </summary>
    public static class TestPublicKeyUsers
    {
        /// <summary>
        /// Alice's private key.
        /// </summary>
        public static readonly CngKey AliceKey = CngKey.Create(CngAlgorithm.ECDsaP256);

        /// <summary>
        /// Bob's private key.
        /// </summary>
        public static readonly CngKey BobKey = CngKey.Create(CngAlgorithm.ECDsaP256);

        /// <summary>
        /// Alice's user data.
        /// </summary>
        public static readonly InMemoryPublicKeyUser AliceUser = new InMemoryPublicKeyUser
                                                                     {
                                                                         Subject = "818727",
                                                                         Username = "alice",
                                                                         PublicKey =
                                                                             Base64Url.Encode(
                                                                                 AliceKey.Export(
                                                                                     CngKeyBlobFormat
                                                                             .EccPublicBlob)),
                                                                         Claims =
                                                                             new[]
                                                                                 {
                                                                                     new Claim(
                                                                                         Constants
                                                                                         .ClaimTypes
                                                                                         .GivenName,
                                                                                         "Alice"),
                                                                                     new Claim(
                                                                                         Constants
                                                                                         .ClaimTypes
                                                                                         .FamilyName,
                                                                                         "Smith"),
                                                                                     new Claim(
                                                                                         Constants
                                                                                         .ClaimTypes
                                                                                         .Email,
                                                                                         "AliceSmith@email.com")
                                                                                 }
                                                                     };

        /// <summary>
        /// Bob's user data.
        /// </summary>
        public static readonly InMemoryPublicKeyUser BobUser = new InMemoryPublicKeyUser
                                                                   {
                                                                       Subject = "88421113",
                                                                       Username = "bob",
                                                                       PublicKey =
                                                                           Base64Url.Encode(
                                                                               BobKey.Export(
                                                                                   CngKeyBlobFormat
                                                                           .EccPublicBlob)),
                                                                       Claims =
                                                                           new[]
                                                                               {
                                                                                   new Claim(
                                                                                       Constants
                                                                                       .ClaimTypes
                                                                                       .GivenName,
                                                                                       "Bob"),
                                                                                   new Claim(
                                                                                       Constants
                                                                                       .ClaimTypes
                                                                                       .FamilyName,
                                                                                       "Smith"),
                                                                                   new Claim(
                                                                                       Constants
                                                                                       .ClaimTypes
                                                                                       .Email,
                                                                                       "BobSmith@email.com")
                                                                               }
                                                                   };

        /// <summary>
        /// The public key test users.
        /// </summary>
        public static readonly InMemoryPublicKeyUser[] UserList =
            {
                AliceUser,
                BobUser
            };
    }
}
