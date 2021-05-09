using System;
using System.Collections.Generic;

#nullable disable

namespace Eadent.Identity.ScaffoldDbContextModels
{
    public partial class SignInStatus
    {
        public SignInStatus()
        {
            UserSessions = new HashSet<UserSession>();
        }

        public short SignInStatusId { get; set; }
        public string Description { get; set; }
        public DateTime CreatedDateTimeUtc { get; set; }

        public virtual ICollection<UserSession> UserSessions { get; set; }
    }
}
