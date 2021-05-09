using Eadent.DataAccess.Repositories;
using Eadent.Identity.DataAccess.EadentUserIdentity.Databases;
using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Repositories
{
    public class RolesRepository : BaseRepository<IEadentUserIdentityDatabase, RoleEntity, short>, IRolesRepository
    {
        public RolesRepository(IEadentUserIdentityDatabase database) : base(database)
        {
        }
    }
}
