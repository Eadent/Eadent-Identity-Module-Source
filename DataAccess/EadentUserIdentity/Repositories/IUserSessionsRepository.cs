using Eadent.Common.DataAccess.EntityFramework.Repositories;
using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Repositories
{
    internal interface IUserSessionsRepository : IBaseRepository<UserSessionEntity, long>
    {
        UserSessionEntity? GetFirstOrDefaultIncludeUserAndRoles(string userSessionToken);

        UserSessionEntity? GetFirstOrDefaultByUserSessionGuidIncludeUserAndRoles(Guid userSessionGuid);

        UserSessionEntity? GetLastOrDefault(long userId);

        Task<UserSessionEntity?> GetFirstOrDefaultIncludeUserAndRolesAsync(string userSessionToken, CancellationToken cancellationToken);

        Task<UserSessionEntity?> GetFirstOrDefaultByUserSessionGuidIncludeUserAndRolesAsync(Guid userSessionGuid, CancellationToken cancellationToken);

        Task<UserSessionEntity?> GetLastOrDefaultAsync(long userId, CancellationToken cancellationToken);
    }
}
