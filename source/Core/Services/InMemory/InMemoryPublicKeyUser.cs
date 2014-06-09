namespace Thinktecture.IdentityServer.Core.Services.InMemory
{
    using System.Collections.Generic;
    using System.Security.Claims;

    /// <summary>
    /// In-memory representation of public key users.
    /// </summary>
    public class InMemoryPublicKeyUser
    {
        /// <summary>
        /// Gets or sets the user subject identifier.
        /// </summary>
        public string Subject { get; set; }

        /// <summary>
        /// Gets or sets the user login name.
        /// </summary>
        public string Username { get; set; }

        /// <summary>
        /// Gets or sets the user public key.
        /// </summary>
        public string PublicKey { get; set; }

        /// <summary>
        /// Gets or sets the user pending signing challenge.
        /// </summary>
        public string Challenge { get; set; }

        /// <summary>
        /// Gets or sets the user provider name.
        /// </summary>
        public string Provider { get; set; }

        /// <summary>
        /// Gets or sets the user provider identifier.
        /// </summary>
        public string ProviderId { get; set; }

        /// <summary>
        /// Gets or sets the list of user claims.
        /// </summary>
        public IEnumerable<Claim> Claims { get; set; }
    }
}
