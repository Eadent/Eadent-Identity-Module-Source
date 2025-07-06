using Eadent.Common.DataAccess.EntityFramework.Repositories;
using Eadent.Identity.DataAccess.EadentUserIdentity.Databases;
using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;
using Microsoft.EntityFrameworkCore;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Repositories
{
    internal class UsersRepository : BaseRepository<IEadentUserIdentityDatabase, UserEntity, long>, IUsersRepository
    {
        public UsersRepository(IEadentUserIdentityDatabase database) : base(database)
        {
        }

        public UserEntity? GetFirstOrDefaultByEMailAddressIncludeRoles(string eMailAddress)
        {
            var userEntity = Database.Context.Set<UserEntity>()
                .Include(entity => entity.UserRoles)
                .ThenInclude(entity => entity.Role)
                .FirstOrDefault(entity => entity.EMailAddress == eMailAddress);

            return userEntity;
        }

        public UserEntity GetFirstOrDefaultByEMailAddressAndUserGuidIncludeRoles(string eMailAddress, Guid userGuid)
        {
            var userEntity = Database.Context.Set<UserEntity>()
                .Include(entity => entity.UserRoles)
                .ThenInclude(entity => entity.Role)
                .FirstOrDefault(entity => entity.EMailAddress == eMailAddress && entity.UserGuid == userGuid);

            return userEntity;
        }

        public async Task<UserEntity?> GetFirstOrDefaultByEMailAddressIncludeRolesAsync(string eMailAddress, CancellationToken cancellationToken)
        {
            var userEntity = await Database.Context.Set<UserEntity>()
                .Include(entity => entity.UserRoles)
                .ThenInclude(entity => entity.Role)
                .FirstOrDefaultAsync(entity => entity.EMailAddress == eMailAddress, cancellationToken);

            return userEntity;
        }

        public async Task<UserEntity> GetFirstOrDefaultByEMailAddressAndUserGuidIncludeRolesAsync(string eMailAddress, Guid userGuid, CancellationToken cancellationToken)
        {
            var userEntity = await Database.Context.Set<UserEntity>()
                .Include(entity => entity.UserRoles)
                .ThenInclude(entity => entity.Role)
                .FirstOrDefaultAsync(entity => entity.EMailAddress == eMailAddress && entity.UserGuid == userGuid, cancellationToken);

            return userEntity;
        }
    }
}
