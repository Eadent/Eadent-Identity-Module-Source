using Eadent.DataAccess.Repositories;
using Eadent.Identity.DataAccess.EadentUserIdentity.Databases;
using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Repositories
{
    internal class SignInStatusesRepository : BaseRepository<IEadentUserIdentityDatabase, SignInStatusEntity, short>, ISignInStatusesRepository
    {
        public SignInStatusesRepository(IEadentUserIdentityDatabase database) : base(database)
        {
        }
    }
}
