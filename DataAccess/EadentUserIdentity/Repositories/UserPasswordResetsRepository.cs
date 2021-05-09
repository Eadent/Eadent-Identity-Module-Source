using Eadent.DataAccess.Repositories;
using Eadent.Identity.DataAccess.EadentUserIdentity.Databases;
using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Repositories
{
    public class UserPasswordResetsRepository : BaseRepository<IEadentUserIdentityDatabase, UserPasswordResetEntity, long>, IUserPasswordResetsRepository
    {
        public UserPasswordResetsRepository(IEadentUserIdentityDatabase database) : base(database)
        {
        }
    }
}
