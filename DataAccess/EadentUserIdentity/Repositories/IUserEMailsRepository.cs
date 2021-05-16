using Eadent.Common.DataAccess.Repositories;
using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Repositories
{
    internal interface IUserEMailsRepository : IBaseRepository<UserEMailEntity, long>
    {
        UserEMailEntity GetFirstOrDefaultIncludeUserAndRoles(string eMailAddress);
    }
}
