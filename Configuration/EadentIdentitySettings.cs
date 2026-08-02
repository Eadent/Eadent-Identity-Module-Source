using Eadent.Common.Configuration;

namespace Eadent.Identity.Configuration
{
    public class EadentIdentitySettings
    {
        public const string SectionName = "EadentIdentity";

        public static EadentIdentitySettings Instance { get; private set; }

        public EadentIdentitySettings()
        {
            Instance = this;
        }

        public class SecuritySettings
        {
            public class HasherSettings
            {
                public string PasswordSalt { get; set; }

                public string SiteSalt { get; set; }

                public int IterationCount { get; set; }

                public int NumDerivedKeyBytes { get; set; }
            }

            public HasherSettings Hasher { get; set; }

            public int RoleLevelPrivilegedThresholdInclusive { get; set; }
        }

        public class PasswordResetSettings
        {
            public int ResetWindowDurationInMinutes { get; set; }

            public byte RequestCodeLimit { get; set; }

            public byte TryCodeLimit { get; set; }
        }

        public class AccountSettings
        {
            public int SignInErrorLimit { get; set; }

            public int SignInLockOutDurationInSeconds { get; set; }

            public int SessionExpirationDurationInSeconds { get; set; }

            public string SignInUrl { get; set; }

            public PasswordResetSettings PasswordReset { get; set; }
        }

        public class UserIdentitySettings
        {
            public string DatabaseTypeName { get; set; }

            // The following are Derived rather than explicitly Configured.
            private int? _databaseTypeValue;

            public int DatabaseTypeValue
            {
                get
                {
                    if (_databaseTypeValue == null)
                    {
                        _databaseTypeValue = DatabaseType.GetDatabaseType(DatabaseTypeName);
                    }

                    return _databaseTypeValue.GetValueOrDefault();
                }
            }

            public SqlServerDatabaseSettings SqlServerDatabase { get; set; }

            public PostgreSqlDatabaseSettings PostgreSqlDatabase { get; set; }

            public SecuritySettings Security { get; set; }

            public AccountSettings Account { get; set; }
        }

        public UserIdentitySettings UserIdentity { get; set; }
    }
}
