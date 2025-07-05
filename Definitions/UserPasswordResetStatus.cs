namespace Eadent.Identity.Definitions
{
    public enum UserPasswordResetStatus : short
    {
        Error = 0,
        Success = 1,
        InvalidEMailAddress = 2,
        NewRequest = 3,
        OutstandingRequest = 4,
        InvalidResetCode = 5,
        LimitsReached = 6,
        ValidResetCode = 7,

        InvalidNewPassword = 4,
        Aborted = 5,
        TimedOutExpired = 6,
        Closed = 7,
        UserDisabled = 8,
        UserSoftDeleted = 100
    }
}
