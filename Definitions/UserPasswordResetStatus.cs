namespace Eadent.Identity.Definitions
{
    public enum UserPasswordResetStatus : short
    {
        Error = 0,
        Success = 1,
        InvalidEMailAddress = 2,
        NewRequest = 3,
        InvalidResetCode = 4,
        OutstandingRequest = 5,
        ValidResetCode = 6,

        InvalidNewPassword = 4,
        Aborted = 5,
        TimedOutExpired = 6,
        Closed = 7,
        UserDisabled = 8,
        UserSoftDeleted = 100
    }
}
