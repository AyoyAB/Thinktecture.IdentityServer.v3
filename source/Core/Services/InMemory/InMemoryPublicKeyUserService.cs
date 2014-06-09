namespace Thinktecture.IdentityServer.Core.Services.InMemory
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;

    using Thinktecture.IdentityServer.Core.Authentication;
    using Thinktecture.IdentityServer.Core.Models;

    /// <summary>
    /// In-memory implementation of <see cref="IPublicKeyUserService"/>.
    /// </summary>
    public class InMemoryPublicKeyUserService : IPublicKeyUserService
    {
        /// <summary>
        /// The list of users.
        /// </summary>
        private readonly List<InMemoryPublicKeyUser> users = new List<InMemoryPublicKeyUser>();

        /// <summary>
        /// Initializes a new instance of the <see cref="InMemoryPublicKeyUserService"/> class.
        /// </summary>
        /// <param name="users">
        /// The list of users.
        /// </param>
        public InMemoryPublicKeyUserService(IEnumerable<InMemoryPublicKeyUser> users)
        {
            this.users.AddRange(users);
        }

        /// <summary>
        /// Authenticates the user with the given password.
        /// </summary>
        /// <param name="username">
        /// The user name.
        /// </param>
        /// <param name="password">
        /// The password.
        /// </param>
        /// <returns>
        /// This implementation always returns an error.
        /// </returns>
        /// <remarks>
        /// Password-based authentication is not supported for this implementation.
        /// </remarks>
        public Task<AuthenticateResult> AuthenticateLocalAsync(string username, string password)
        {
            // Apologies to Ms. Liskov.
            // TODO: Pass a defined error message back.
            return Task.FromResult(new AuthenticateResult("Password auth not supported"));
        }

        /// <summary>
        /// Authenticates the user with the given signature.
        /// </summary>
        /// <param name="username">
        /// The user name.
        /// </param>
        /// <param name="signature">
        /// The signature.
        /// </param>
        /// <returns>
        /// The authentication result.
        /// </returns>
        public Task<AuthenticateResult> AuthenticatePublicKeyLocalAsync(string username, string signature)
        {
            var query =
                from u in this.users
                where u.Username == username
                select u;

            var user = query.SingleOrDefault();
            if (user == null)
            {
                // No user with that name found.
                // TODO: Figure out an error-handling strategy.
                return Task.FromResult<AuthenticateResult>(null);
            }

            if (!PublicKeyCryptoService.VerifySignature(user.PublicKey, user.Challenge, signature))
            {
                // Invalid signature.
                // TODO: Figure out an error-handling strategy.
                return Task.FromResult<AuthenticateResult>(null);
            }

            return Task.FromResult(new AuthenticateResult(user.Subject, user.Username));
        }

        /// <summary>
        /// Authenticates an external user and optionally adds it to the local database.
        /// </summary>
        /// <param name="subject">
        /// The parameter is not used.
        /// </param>
        /// <param name="externalUser">
        /// The external user object.
        /// </param>
        /// <returns>
        /// The authentication result.
        /// </returns>
        /// <remarks>
        /// This is more or less a straight copy of the code in InMemoryUserService. Needs refactoring.
        /// </remarks>
        public Task<ExternalAuthenticateResult> AuthenticateExternalAsync(string subject, ExternalIdentity externalUser)
        {
            var query =
                from u in this.users
                where
                    u.Provider == externalUser.Provider.Name &&
                    u.ProviderId == externalUser.ProviderId
                select u;

            var user = query.SingleOrDefault();
            if (user == null)
            {
                var name = externalUser.Claims.FirstOrDefault(x => x.Type == Constants.ClaimTypes.Name);
                if (name == null)
                {
                    return Task.FromResult<ExternalAuthenticateResult>(null);
                }

                var claims = externalUser.Claims.Except(new[] { name });

                // NB: This is the only change from the equivalent method in InMemoryUserService.
                user = new InMemoryPublicKeyUser
                {
                    Subject = Guid.NewGuid().ToString("N"),
                    Provider = externalUser.Provider.Name,
                    ProviderId = externalUser.ProviderId,
                    Username = name.Value,
                    Claims = claims.ToArray()
                };

                this.users.Add(user);
            }

            return Task.FromResult(new ExternalAuthenticateResult(user.Provider, user.Subject, user.Username));
        }

        /// <summary>
        /// Gets the requested user profile data.
        /// </summary>
        /// <param name="subject">
        /// The user subject identifier.
        /// </param>
        /// <param name="requestedClaimTypes">
        /// The requested claim types. Pass null to request all claims types.
        /// </param>
        /// <returns>
        /// The requested claims for the specified user.
        /// </returns>
        /// <remarks>
        /// This is a straight copy of the code in InMemoryUserService. Needs refactoring.
        /// </remarks>
        public Task<IEnumerable<Claim>> GetProfileDataAsync(string subject, IEnumerable<string> requestedClaimTypes = null)
        {
            var query =
                from u in this.users
                where u.Subject == subject
                select u;
            var user = query.Single();

            var claims = new List<Claim>
            {
                new Claim(Constants.ClaimTypes.Subject, user.Subject)
            };

            claims.AddRange(user.Claims);
            if (requestedClaimTypes != null)
            {
                claims = claims.Where(x => requestedClaimTypes.Contains(x.Type)).ToList();
            }

            return Task.FromResult<IEnumerable<Claim>>(claims);
        }
    }
}
