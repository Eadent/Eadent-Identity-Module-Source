using System;
using System.Collections.Generic;

#nullable disable

namespace Eadent.Identity.ScaffoldDbContextModels
{
    public partial class UserAudit
    {
        public long UserAuditId { get; set; }
        public long UserId { get; set; }
        public string Description { get; set; }
        public string OldValue { get; set; }
        public string NewValue { get; set; }
        public string IpAddress { get; set; }
        public DateTime CreatedDateTimeUtc { get; set; }

        public virtual User User { get; set; }
    }
}
