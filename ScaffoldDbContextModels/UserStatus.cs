using System;
using System.Collections.Generic;

#nullable disable

namespace Eadent.Identity.ScaffoldDbContextModels
{
    public partial class UserStatus
    {
        public UserStatus()
        {
            Users = new HashSet<User>();
        }

        public short UserStatusId { get; set; }
        public string Description { get; set; }
        public DateTime CreatedDateTimeUtc { get; set; }

        public virtual ICollection<User> Users { get; set; }
    }
}
