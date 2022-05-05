using Eadent.Identity.Configuration;
using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;
using System.Collections.Generic;
using System.Linq;

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

                if (minRoleLevel <= EadentIdentitySettings.Instance.UserIdentity.Security.RoleLevelPrivilegedThresholdInclusive)
                {
                    isPrivileged = true;
                }
            }

            return isPrivileged;
        }
    }
}
