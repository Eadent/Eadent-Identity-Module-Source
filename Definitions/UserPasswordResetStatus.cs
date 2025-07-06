namespace Eadent.Identity.Definitions
{
    public enum UserPasswordResetStatus : short
    {
        Error = 0,
        InvalidEMailAddress = 1,
        NewRequest = 2,
        OutstandingRequest = 3,
        InvalidResetCode = 4,
        LimitsReached = 5,
        ValidResetCode = 6,
        UserDisabled = 7,
        TimedOutExpired = 8,
        InvalidNewPassword = 9,
        UserSoftDeleted = 100
    }
}
