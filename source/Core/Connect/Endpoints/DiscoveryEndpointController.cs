﻿/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license
 */

using System;
using System.Linq;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Cors;
using Thinktecture.IdentityModel;
using Thinktecture.IdentityServer.Core.Extensions;
using Thinktecture.IdentityServer.Core.Models;

namespace Thinktecture.IdentityServer.Core.Connect
{
    [RoutePrefix(".well-known")]
    [EnableCors("*", "*", "GET")]
    public class DiscoveryEndpointController : ApiController
    {
        private CoreSettings _settings;
        private IScopeService _scopes;

        public DiscoveryEndpointController(CoreSettings settings, IScopeService scopes)
        {
            _settings = settings;
            _scopes = scopes;
        }

        [Route("openid-configuration")]
        public async Task<IHttpActionResult> GetConfiguration()
        {
            var baseUrl = Request.GetBaseUrl(_settings.PublicHostName);
            var scopes = await _scopes.GetScopesAsync();

            return Json(new
            {
                issuer = _settings.IssuerUri,
                jwks_uri = baseUrl + ".well-known/jwks",
                authorization_endpoint = baseUrl + "connect/authorize",
                token_endpoint = baseUrl + "connect/token",
                userinfo_endpoint = baseUrl + "connect/userinfo",
                end_session_endpoint = baseUrl + "connect/logout",
                scopes_supported = scopes.Select(s => s.Name),
                response_types_supported = Constants.SupportedResponseTypes,
                response_modes_supported = Constants.SupportedResponseModes,
                grant_types_supported = Constants.SupportedGrantTypes,
                subject_types_support = new string[] { "pairwise", "public" },
                id_token_signing_alg_values_supported = "RS256"
            });
        }

        [Route("jwks")]
        public IHttpActionResult GetKeyData()
        {
            var cert = _settings.SigningCertificate;
            var cert64 = Convert.ToBase64String(cert.RawData);
            var thumbprint = Base64Url.Encode(cert.GetCertHash());

            var key = new
            {
                kty = "RSA",
                use = "sig",
                kid = thumbprint,
                x5t = thumbprint,
                x5c = new string[] { cert64 }
            };

            return Json(new { keys = new[] { key } });
        }
    }
}