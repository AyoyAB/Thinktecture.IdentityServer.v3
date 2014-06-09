namespace Thinktecture.IdentityServer.Tests.Authentication_Tests.Public_Key_Authentication
{
    using System.Security.Cryptography;
    using System.Threading.Tasks;

    using Microsoft.VisualStudio.TestTools.UnitTesting;

    using Thinktecture.IdentityServer.Core.Services;
    using Thinktecture.IdentityServer.Core.Services.InMemory;
    using Thinktecture.IdentityServer.Tests.Plumbing;

    /// <summary>
    /// Public key authentication unit tests.
    /// </summary>
    [TestClass]
    public class PublicKeyLocalAuthentication
    {
        /// <summary>
        /// The test category.
        /// </summary>
        private const string Category = "Public Key Local Authentication";

        /// <summary>
        /// The user service instance to test against.
        /// </summary>
        private static readonly IPublicKeyUserService UserService =
            new InMemoryPublicKeyUserService(TestPublicKeyUsers.UserList);

        /// <summary>
        /// Password-based authentication should be disabled.
        /// </summary>
        /// <returns>The <see cref="Task"/> to wait on.</returns>
        [TestMethod]
        [TestCategory(Category)]
        public async Task PasswordUser()
        {
            var result = await UserService.AuthenticateLocalAsync("dummy user", "dummy password");

            Assert.IsNotNull(result);
            Assert.IsTrue(result.IsError);
            Assert.AreEqual("Password auth not supported", result.ErrorMessage);
        }

        /// <summary>
        /// Authenticating with an unknown user name should fail.
        /// </summary>
        /// <returns>The <see cref="Task"/> to wait on.</returns>
        [TestMethod]
        [TestCategory(Category)]
        public async Task UnknownUser()
        {
            var result = await UserService.AuthenticatePublicKeyLocalAsync("invalid user", "dummy signature");

            Assert.IsNull(result);
        }

        /// <summary>
        /// Authenticating with an invalid signed challenge should fail.
        /// </summary>
        /// <returns>The <see cref="Task"/> to wait on.</returns>
        [TestMethod]
        [TestCategory(Category)]
        public async Task InvalidChallenge()
        {
            TestPublicKeyUsers.AliceUser.Challenge = PublicKeyCryptoService.GenerateChallenge();

            var signature = PublicKeyCryptoService.SignChallenge(
                TestPublicKeyUsers.AliceKey,
                CngAlgorithm.Sha256,
                "invalid challenge");

            var result =
                await UserService.AuthenticatePublicKeyLocalAsync(TestPublicKeyUsers.AliceUser.Username, signature);

            Assert.IsNull(result);
        }

        /// <summary>
        /// Authenticating with an unexpected signed challenge should fail.
        /// </summary>
        /// <returns>The <see cref="Task"/> to wait on.</returns>
        [TestMethod]
        [TestCategory(Category)]
        public async Task UnexpectedChallenge()
        {
            TestPublicKeyUsers.AliceUser.Challenge = PublicKeyCryptoService.GenerateChallenge();

            var signature = PublicKeyCryptoService.SignChallenge(
                TestPublicKeyUsers.AliceKey,
                CngAlgorithm.Sha256,
                PublicKeyCryptoService.GenerateChallenge());

            var result =
                await UserService.AuthenticatePublicKeyLocalAsync(TestPublicKeyUsers.AliceUser.Username, signature);

            Assert.IsNull(result);
        }

        /// <summary>
        /// Authenticating with an invalid signature should fail.
        /// </summary>
        /// <returns>The <see cref="Task"/> to wait on.</returns>
        [TestMethod]
        [TestCategory(Category)]
        public async Task InvalidSignature()
        {
            TestPublicKeyUsers.AliceUser.Challenge = PublicKeyCryptoService.GenerateChallenge();

            var result =
                await
                UserService.AuthenticatePublicKeyLocalAsync(TestPublicKeyUsers.AliceUser.Username, "invalid signature");

            Assert.IsNull(result);
        }

        /// <summary>
        /// Authenticating with the wrong signing key should fail.
        /// </summary>
        /// <returns>The <see cref="Task"/> to wait on.</returns>
        [TestMethod]
        [TestCategory(Category)]
        public async Task SignatureWithWrongKey()
        {
            TestPublicKeyUsers.AliceUser.Challenge = PublicKeyCryptoService.GenerateChallenge();

            var signature = PublicKeyCryptoService.SignChallenge(
                TestPublicKeyUsers.BobKey,
                CngAlgorithm.Sha256,
                TestPublicKeyUsers.AliceUser.Challenge);

            var result =
                await UserService.AuthenticatePublicKeyLocalAsync(TestPublicKeyUsers.AliceUser.Username, signature);

            Assert.IsNull(result);
        }

        /// <summary>
        /// Authenticating with a valid signed challenge should succeed.
        /// </summary>
        /// <returns>The <see cref="Task"/> to wait on.</returns>
        [TestMethod]
        [TestCategory(Category)]
        public async Task ValidSignature()
        {
            TestPublicKeyUsers.AliceUser.Challenge = PublicKeyCryptoService.GenerateChallenge();

            var signature = PublicKeyCryptoService.SignChallenge(
                TestPublicKeyUsers.AliceKey,
                CngAlgorithm.Sha256,
                TestPublicKeyUsers.AliceUser.Challenge);

            var result =
                await UserService.AuthenticatePublicKeyLocalAsync(TestPublicKeyUsers.AliceUser.Username, signature);

            Assert.IsNotNull(result);
            Assert.IsFalse(result.IsError);
            Assert.AreEqual(TestPublicKeyUsers.AliceUser.Subject, result.Subject);
            Assert.AreEqual(TestPublicKeyUsers.AliceUser.Username, result.Name);
        }
    }
}
