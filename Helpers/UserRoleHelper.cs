using System.Collections.Generic;
using System.Linq;
using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;

namespace Eadent.Identity.Helpers
{
    public class UserRoleHelper
    {
        public static bool IsPrivileged(ICollection<UserRoleEntity> userRoles)
        {
            bool isPrivileged = false;

            if (userRoles != null)
            {
                var minRoleLevel = userRoles.Min(userRole => userRole.Role.RoleLevel);

                if (minRoleLevel <= RoleEntity.RoleLevelPrivilegedThresholdInclusive)
                {
                    isPrivileged = true;
                }
            }

            return isPrivileged;
        }
    }
}
