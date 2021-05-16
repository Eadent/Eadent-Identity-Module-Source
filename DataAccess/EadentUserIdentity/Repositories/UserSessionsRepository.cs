using Eadent.Common.DataAccess.Repositories;
using Eadent.Identity.DataAccess.EadentUserIdentity.Databases;
using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;
using Microsoft.EntityFrameworkCore;
using System.Linq;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Repositories
{
    internal class UserSessionsRepository : BaseRepository<IEadentUserIdentityDatabase, UserSessionEntity, long>, IUserSessionsRepository
    {
        public UserSessionsRepository(IEadentUserIdentityDatabase database) : base(database)
        {
        }

        public UserSessionEntity GetFirstOrDefaultIncludeUserAndRoles(string userSessionToken)
        {
            var userSessionEntity = Database.Context.Set<UserSessionEntity>()
                .Include(entity => entity.User)
                .ThenInclude(entity => entity.UserRoles)
                .ThenInclude(entity => entity.Role)
                .FirstOrDefault(entity => entity.UserSessionToken == userSessionToken);

            return userSessionEntity;
        }

        public UserSessionEntity GetLastOrDefault(long userId)
        {
            var userSessionEntity = Database.Context.Set<UserSessionEntity>()
                .OrderByDescending(entity => entity.UserSessionId)
                .FirstOrDefault(entity => entity.UserId == userId);

            return userSessionEntity;
        }
    }
}
