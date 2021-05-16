using Eadent.Common.DataAccess.Repositories;
using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Repositories
{
    internal interface IUserSessionsRepository : IBaseRepository<UserSessionEntity, long>
    {
        UserSessionEntity GetFirstOrDefaultIncludeUserAndRoles(string userSessionToken);

        UserSessionEntity GetLastOrDefault(long userId);
    }
}
