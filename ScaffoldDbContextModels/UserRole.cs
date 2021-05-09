using System;
using System.Collections.Generic;

#nullable disable

namespace Eadent.Identity.ScaffoldDbContextModels
{
    public partial class UserRole
    {
        public long UserRoleId { get; set; }
        public long UserId { get; set; }
        public short RoleId { get; set; }
        public DateTime CreatedDateTimeUtc { get; set; }

        public virtual Role Role { get; set; }
        public virtual User User { get; set; }
    }
}
