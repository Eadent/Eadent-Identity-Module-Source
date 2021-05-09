using System;
using System.Collections.Generic;

#nullable disable

namespace Eadent.Identity.ScaffoldDbContextModels
{
    public partial class UserEmail
    {
        public long UserEmailId { get; set; }
        public long UserId { get; set; }
        public string EmailAddress { get; set; }
        public DateTime CreatedDateTimeUtc { get; set; }
        public DateTime? VerifiedDateTimeUtc { get; set; }

        public virtual User User { get; set; }
    }
}
