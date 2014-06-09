namespace Thinktecture.IdentityServer.Core.Services
{
    using System.Threading.Tasks;

    using Thinktecture.IdentityServer.Core.Authentication;
    using Thinktecture.IdentityServer.Core.Models;

    /// <summary>
    /// A specialization of <see cref="IUserService"/> that authenticates users by way of a public key signature.
    /// </summary>
    public interface IPublicKeyUserService : IUserService
    {
        /// <summary>
        /// Authenticates a local user with a public key signature.
        /// </summary>
        /// <param name="username">Name of the user to authenticate</param>
        /// <param name="signature">Public key signature to authenticate with</param>
        /// <returns>The authentication result</returns>
        Task<AuthenticateResult> AuthenticatePublicKeyLocalAsync(string username, string signature);
    }
}
