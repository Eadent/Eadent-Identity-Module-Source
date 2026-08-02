using Eadent.Common.Configuration;
using Eadent.Common.DataAccess.EntityFramework.Databases;
using Eadent.Identity.Configuration;
using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;
using Microsoft.EntityFrameworkCore;
using System;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Databases
{
    internal class EadentUserIdentityDatabase : BaseDatabase, IEadentUserIdentityDatabase
    {
        // Database Tables.
        public virtual DbSet<UserEntity> Users { get; set; }

        public virtual DbSet<UserRoleEntity> UserRoles { get; set; }

        public virtual DbSet<UserStatusEntity> UserStatuses { get; set; }

        public virtual DbSet<UserAuditEntity> UserAudits { get; set; }

        public virtual DbSet<RoleEntity> Roles { get; set; }

        public virtual DbSet<UserSessionEntity> UserSessions { get; set; }

        public virtual DbSet<SignInStatusEntity> SignInStatuses { get; set; }

        public virtual DbSet<UserPasswordResetEntity> UserPasswordResets { get; set; }

        public virtual DbSet<PasswordVersionEntity> PasswordVersions { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            int eadentIdentityDatabaseTypeValue = EadentIdentitySettings.Instance.UserIdentity.DatabaseTypeValue;

            if (eadentIdentityDatabaseTypeValue == DatabaseType.SqlServer)
            {
                modelBuilder.HasDefaultSchema(EadentIdentitySettings.Instance.UserIdentity.SqlServerDatabase.DatabaseSchema);
            }
            else if (eadentIdentityDatabaseTypeValue == DatabaseType.PostgreSql)
            {
                modelBuilder.HasDefaultSchema(EadentIdentitySettings.Instance.UserIdentity.PostgreSqlDatabase.DatabaseSchema);
            }
            else
            {
                throw new InvalidOperationException($"Unsupported Eadent Identity Database Type Value: {eadentIdentityDatabaseTypeValue}");
            }

            base.OnModelCreating(modelBuilder);
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            base.OnConfiguring(optionsBuilder);
        }

        public EadentUserIdentityDatabase(DbContextOptions<EadentUserIdentityDatabase> options) : base(options)
        {
            int eadentIdentityDatabaseTypeValue = EadentIdentitySettings.Instance.UserIdentity.DatabaseTypeValue;

            if (eadentIdentityDatabaseTypeValue == DatabaseType.SqlServer)
            {
                DatabaseName = EadentIdentitySettings.Instance.UserIdentity.SqlServerDatabase.DatabaseName;
                DatabaseSchema = EadentIdentitySettings.Instance.UserIdentity.SqlServerDatabase.DatabaseSchema;
            }
            else if (eadentIdentityDatabaseTypeValue == DatabaseType.PostgreSql)
            {
                DatabaseName = EadentIdentitySettings.Instance.UserIdentity.PostgreSqlDatabase.DatabaseName;
                DatabaseSchema = EadentIdentitySettings.Instance.UserIdentity.PostgreSqlDatabase.DatabaseSchema;
            }
            else
            {
                throw new InvalidOperationException($"Unsupported Eadent Identity Database Type Value: {eadentIdentityDatabaseTypeValue}");
            }
        }
    }
}
