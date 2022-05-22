using Eadent.Common.DataAccess.EntityFramework.Repositories;
using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;
using System;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Repositories
{
    internal interface IUserSessionsRepository : IBaseRepository<UserSessionEntity, long>
    {
        UserSessionEntity? GetFirstOrDefaultIncludeUserAndRoles(string userSessionToken);

        UserSessionEntity? GetFirstOrDefaultByUserSessionGuidIncludeUserAndRoles(Guid userSessionGuid);

        UserSessionEntity? GetLastOrDefault(long userId);
    }
}
