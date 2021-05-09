using Eadent.DataAccess.Repositories;
using Eadent.Identity.DataAccess.EadentUserIdentity.Databases;
using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Repositories
{
    public class UserAuditsRepository : BaseRepository<IEadentUserIdentityDatabase, UserAuditEntity, long>, IUserAuditsRepository
    {
        public UserAuditsRepository(IEadentUserIdentityDatabase database) : base(database)
        {
        }
    }
}
