using Eadent.Common.DataAccess.Repositories;
using Eadent.Identity.DataAccess.EadentUserIdentity.Databases;
using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Repositories
{
    internal class UserPasswordResetsRepository : BaseRepository<IEadentUserIdentityDatabase, UserPasswordResetEntity, long>, IUserPasswordResetsRepository
    {
        public UserPasswordResetsRepository(IEadentUserIdentityDatabase database) : base(database)
        {
        }
    }
}
