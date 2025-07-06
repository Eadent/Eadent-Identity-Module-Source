using Eadent.Common.DataAccess.EntityFramework.Repositories;
using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Repositories
{
    internal interface IUsersRepository : IBaseRepository<UserEntity, long>
    {
        UserEntity? GetFirstOrDefaultByEMailAddressIncludeRoles(string eMailAddress);

        UserEntity GetFirstOrDefaultByEMailAddressAndUserGuidIncludeRoles(string eMailAddress, Guid userGuid);

        Task<UserEntity?> GetFirstOrDefaultByEMailAddressIncludeRolesAsync(string eMailAddress, CancellationToken cancellationToken = default);

        Task<UserEntity> GetFirstOrDefaultByEMailAddressAndUserGuidIncludeRolesAsync(string eMailAddress, Guid userGuid, CancellationToken cancellationToken = default);
    }
}
