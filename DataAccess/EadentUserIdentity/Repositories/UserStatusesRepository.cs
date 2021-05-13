using Eadent.DataAccess.Repositories;
using Eadent.Identity.DataAccess.EadentUserIdentity.Databases;
using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Repositories
{
    internal class UserStatusesRepository : BaseRepository<IEadentUserIdentityDatabase, UserStatusEntity, short>, IUserStatusesRepository
    {
        public UserStatusesRepository(IEadentUserIdentityDatabase database) : base(database)
        {
        }
    }
}
