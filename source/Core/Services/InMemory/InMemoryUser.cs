﻿/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license
 */
using System.Collections.Generic;
using System.Security.Claims;

namespace Thinktecture.IdentityServer.Core.Models.InMemory
{
    public class InMemoryUser
    {
        public string Subject { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string Provider { get; set; }
        public string ProviderId { get; set; }
        public IEnumerable<Claim> Claims { get; set; }
    }
}