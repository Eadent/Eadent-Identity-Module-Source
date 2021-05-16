using Eadent.Common.DataAccess.Repositories;
using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Repositories
{
    internal interface IUserRolesRepository : IBaseRepository<UserRoleEntity, long>
    {
    }
}
