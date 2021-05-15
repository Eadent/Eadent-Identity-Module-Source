namespace Eadent.Identity.Definitions
{
    public enum UserPasswordResetRequestStatus : short
    {
        Error = 0,
        Success = 1,
        InvalidEMailAddress = 2,
        InvalidResetToken = 3,
        InvalidNewPassword = 4,
        Aborted = 5,
        TimedOutExpired = 6,
        Closed = 7,
        UserDisabled = 8,
        UserSoftDeleted = 100
    }
}
