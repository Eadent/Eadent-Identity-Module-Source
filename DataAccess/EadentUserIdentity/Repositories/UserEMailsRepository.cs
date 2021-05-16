using Eadent.Common.DataAccess.Repositories;
using Eadent.Identity.DataAccess.EadentUserIdentity.Databases;
using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;
using Microsoft.EntityFrameworkCore;
using System.Linq;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Repositories
{
    internal class UserEMailsRepository : BaseRepository<IEadentUserIdentityDatabase, UserEMailEntity, long>, IUserEMailsRepository
    {
        public UserEMailsRepository(IEadentUserIdentityDatabase database) : base(database)
        {
        }

        public UserEMailEntity GetFirstOrDefaultIncludeUserAndRoles(string eMailAddress)
        {
            var userEMailEntity = Database.Context.Set<UserEMailEntity>()
                .Include(entity => entity.User)
                .ThenInclude(entity => entity.UserRoles)
                .ThenInclude(entity => entity.Role)
                .FirstOrDefault(entity => entity.EMailAddress == eMailAddress);

            return userEMailEntity;
        }
    }
}
