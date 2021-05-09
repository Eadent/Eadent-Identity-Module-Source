namespace Eadent.Identity.Definitions
{
    public enum UserPasswordResetRequestStatus : short
    {
        Success = 0,
        Error = 1,
        InvalidEMailAddress = 2,
        InvalidResetToken = 3,
        InvalidNewPassword = 4,
        Aborted = 5,
        TimedOutExpired = 6,
        Closed = 7,
        Disabled = 8,
        SoftDeleted = 100
    }
}
