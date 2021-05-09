using System;
using System.Collections.Generic;

#nullable disable

namespace Eadent.Identity.ScaffoldDbContextModels
{
    public partial class Role
    {
        public Role()
        {
            UserRoles = new HashSet<UserRole>();
        }

        public short RoleId { get; set; }
        public short RoleLevel { get; set; }
        public string Description { get; set; }
        public DateTime CreatedDateTimeUtc { get; set; }

        public virtual ICollection<UserRole> UserRoles { get; set; }
    }
}
