using System;
using System.Collections.Generic;

#nullable disable

namespace Eadent.Identity.ScaffoldDbContextModels
{
    public partial class RaptureTherapyDatabaseVersion
    {
        public int DatabaseVersionId { get; set; }
        public int Major { get; set; }
        public int Minor { get; set; }
        public int Patch { get; set; }
        public int Build { get; set; }
        public string Description { get; set; }
        public DateTime ReleasedDateTimeUtc { get; set; }
        public DateTime InstalledDateTimeUtc { get; set; }
    }
}
