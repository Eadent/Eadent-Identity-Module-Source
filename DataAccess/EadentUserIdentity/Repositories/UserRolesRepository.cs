using Eadent.Common.DataAccess.EntityFramework.Repositories;
using Eadent.Identity.DataAccess.EadentUserIdentity.Databases;
using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Repositories
{
    internal class UserRolesRepository : BaseRepository<IEadentUserIdentityDatabase, UserRoleEntity, long>, IUserRolesRepository
    {
        public UserRolesRepository(IEadentUserIdentityDatabase database) : base(database)
        {
        }
    }
}
