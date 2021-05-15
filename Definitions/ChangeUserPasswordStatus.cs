namespace Eadent.Identity.Definitions
{
    public enum ChangeUserPasswordStatus : short
    {
        Error = 0,
        InvalidSessionToken = 1,
        SessionInactive = 2,
        SessionSignedOut = 3,
        SessionTimedOutExpired = 4,
        SessionDisabled = 5,
        SuccessSignedOut = 10,
        InvalidOldPassword = 11,
        InvalidNewPassword = 12,
        SessionSoftDeleted = 100
    }
}
