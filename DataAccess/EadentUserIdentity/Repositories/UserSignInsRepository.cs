﻿using Eadent.DataAccess.Repositories;
using Eadent.Identity.DataAccess.EadentUserIdentity.Databases;
using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Repositories
{
    public class UserSignInsRepository : BaseRepository<IEadentUserIdentityDatabase, UserSessionEntity, long>, IUserSignInsRepository
    {
        public UserSignInsRepository(IEadentUserIdentityDatabase database) : base(database)
        {
        }
    }
}
