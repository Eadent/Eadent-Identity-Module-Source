using Eadent.Common.DataAccess.EntityFramework.Repositories;
using Eadent.Identity.DataAccess.EadentUserIdentity.Databases;
using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;
using Microsoft.EntityFrameworkCore;
using System.Linq;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Repositories
{
    internal class UsersRepository : BaseRepository<IEadentUserIdentityDatabase, UserEntity, long>, IUsersRepository
    {
        public UsersRepository(IEadentUserIdentityDatabase database) : base(database)
        {
        }

        public UserEntity? GetFirstOrDefaultByEMailAddressIncludeRoles(string eMailAddress)
        {
            var userEntity = Database.Context.Set<UserEntity>()
                .Include(entity => entity.UserRoles)
                .ThenInclude(entity => entity.Role)
                .FirstOrDefault(entity => entity.EMailAddress == eMailAddress);

            return userEntity;
        }
    }
}
