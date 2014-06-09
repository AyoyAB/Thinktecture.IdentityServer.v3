namespace Thinktecture.IdentityServer.Tests.Plumbing
{
    using System.Security.Claims;

    using Thinktecture.IdentityServer.Core;
    using Thinktecture.IdentityServer.Core.Services;
    using Thinktecture.IdentityServer.Core.Services.InMemory;

    /// <summary>
    /// Public key test users.
    /// </summary>
    public static class TestPublicKeyUsers
    {
        /// <summary>
        /// Alice's private key.
        /// </summary>
        public static readonly string AliceKey = PublicKeyCryptoService.GeneratePrivateKey();

        /// <summary>
        /// Bob's private key.
        /// </summary>
        public static readonly string BobKey = PublicKeyCryptoService.GeneratePrivateKey();

        /// <summary>
        /// Alice's user data.
        /// </summary>
        public static readonly InMemoryPublicKeyUser AliceUser = new InMemoryPublicKeyUser
                                                                     {
                                                                         Subject = "818727",
                                                                         Username = "alice",
                                                                         PublicKey =
                                                                             PublicKeyCryptoService
                                                                             .ExtractPublicKey(
                                                                                 AliceKey),
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
                                                                           PublicKeyCryptoService
                                                                           .ExtractPublicKey(BobKey),
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
        public static readonly InMemoryPublicKeyUser[] UserList = { AliceUser, BobUser };
    }
}
