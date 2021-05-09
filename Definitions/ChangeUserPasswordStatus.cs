namespace Eadent.Identity.Definitions
{
    public enum ChangeUserPasswordStatus : short
    {
        Inactive = 0,
        SuccessSignedOut = 1,
        Error = 2,
        InvalidSessionToken = 3,
        InvalidOldPassword = 4,
        InvalidNewPassword = 5,
        SignedOut = 6,
        TimedOutExpired = 7,
        Disabled = 8,
        SoftDeleted = 100
    }
}
