﻿namespace Eadent.Identity.Configuration
{
    public class EadentIdentitySettings
    {
        public const string SectionName = "EadentIdentity";

        public static EadentIdentitySettings Instance { get; private set; }

        public EadentIdentitySettings()
        {
            Instance = this;
        }

        public class DatabaseSettings
        {
            public string DatabaseServer { get; set; }

            public string DatabaseName { get; set; }

            public string DatabaseSchema { get; set; }

            public string ApplicationName { get; set; }

            public string UserName { get; set; }

            public string Password { get; set; }
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
            public DatabaseSettings Database { get; set; }

            public SecuritySettings Security { get; set; }

            public AccountSettings Account { get; set; }
        }

        public UserIdentitySettings UserIdentity { get; set; }
    }
}
