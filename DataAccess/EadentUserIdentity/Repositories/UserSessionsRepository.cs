using Eadent.Common.DataAccess.EntityFramework.Repositories;
using Eadent.Identity.DataAccess.EadentUserIdentity.Databases;
using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;
using Microsoft.EntityFrameworkCore;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Repositories
{
    internal class UserSessionsRepository : BaseRepository<IEadentUserIdentityDatabase, UserSessionEntity, long>, IUserSessionsRepository
    {
        public UserSessionsRepository(IEadentUserIdentityDatabase database) : base(database)
        {
        }

        public UserSessionEntity? GetFirstOrDefaultIncludeUserAndRoles(string userSessionToken)
        {
            var userSessionEntity = Database.Context.Set<UserSessionEntity>()
                .Include(entity => entity.User)
                .ThenInclude(entity => entity.UserRoles)
                .ThenInclude(entity => entity.Role)
                .FirstOrDefault(entity => entity.UserSessionToken == userSessionToken);

            return userSessionEntity;
        }

        public UserSessionEntity? GetFirstOrDefaultByUserSessionGuidIncludeUserAndRoles(Guid userSessionGuid)
        {
            var userSessionEntity = Database.Context.Set<UserSessionEntity>()
                .Include(entity => entity.User)
                .ThenInclude(entity => entity.UserRoles)
                .ThenInclude(entity => entity.Role)
                .FirstOrDefault(entity => entity.UserSessionGuid == userSessionGuid);

            return userSessionEntity;
        }

        public UserSessionEntity? GetLastOrDefault(long userId)
        {
            var userSessionEntity = Database.Context.Set<UserSessionEntity>()
                .OrderByDescending(entity => entity.UserSessionId)
                .FirstOrDefault(entity => entity.UserId == userId);

            return userSessionEntity;
        }

        public async Task<UserSessionEntity?> GetFirstOrDefaultIncludeUserAndRolesAsync(string userSessionToken, CancellationToken cancellationToken)
        {
            var userSessionEntity = await Database.Context.Set<UserSessionEntity>()
                .Include(entity => entity.User)
                .ThenInclude(entity => entity.UserRoles)
                .ThenInclude(entity => entity.Role)
                .FirstOrDefaultAsync(entity => entity.UserSessionToken == userSessionToken, cancellationToken);

            return userSessionEntity;
        }

        public async Task<UserSessionEntity?> GetFirstOrDefaultByUserSessionGuidIncludeUserAndRolesAsync(Guid userSessionGuid, CancellationToken cancellationToken)
        {
            var userSessionEntity = await Database.Context.Set<UserSessionEntity>()
                .Include(entity => entity.User)
                .ThenInclude(entity => entity.UserRoles)
                .ThenInclude(entity => entity.Role)
                .FirstOrDefaultAsync(entity => entity.UserSessionGuid == userSessionGuid, cancellationToken);

            return userSessionEntity;
        }

        public async Task<UserSessionEntity?> GetLastOrDefaultAsync(long userId, CancellationToken cancellationToken)
        {
            var userSessionEntity = await Database.Context.Set<UserSessionEntity>()
                .OrderByDescending(entity => entity.UserSessionId)
                .FirstOrDefaultAsync(entity => entity.UserId == userId, cancellationToken);

            return userSessionEntity;
        }
    }
}
