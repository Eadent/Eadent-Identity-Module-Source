using Eadent.Common.DataAccess.EntityFramework.Repositories;
using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Repositories
{
    internal interface IUserAuditsRepository : IBaseRepository<UserAuditEntity, long>
    {
    }
}
