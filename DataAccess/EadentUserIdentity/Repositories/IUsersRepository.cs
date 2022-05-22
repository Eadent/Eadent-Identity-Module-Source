using Eadent.Common.DataAccess.EntityFramework.Repositories;
using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Repositories
{
    internal interface IUsersRepository : IBaseRepository<UserEntity, long>
    {
        UserEntity? GetFirstOrDefaultByEMailAddressIncludeRoles(string eMailAddress);
    }
}
