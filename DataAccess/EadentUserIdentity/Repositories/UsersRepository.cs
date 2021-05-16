using Eadent.Common.DataAccess.Repositories;
using Eadent.Identity.DataAccess.EadentUserIdentity.Databases;
using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Repositories
{
    internal class UsersRepository : BaseRepository<IEadentUserIdentityDatabase, UserEntity, long>, IUsersRepository
    {
        public UsersRepository(IEadentUserIdentityDatabase database) : base(database)
        {
        }
    }
}
