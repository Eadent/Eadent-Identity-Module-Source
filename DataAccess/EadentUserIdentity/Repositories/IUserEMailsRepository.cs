﻿using Eadent.DataAccess.Repositories;
using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Repositories
{
    public interface IUserEMailsRepository : IBaseRepository<UserEMailEntity, long>
    {
        UserEMailEntity GetFirstOrDefaultIncludeUserAndRoles(string eMailAddress);
    }
}
