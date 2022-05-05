namespace Eadent.Identity.Definitions
{
    public enum ChangeUserEMailStatus : short
    {
        Error = 0,
        InvalidSessionToken = 1,
        SessionInactive = 2,
        SessionSignedOut = 3,
        SessionTimedOutExpired = 4,
        SessionDisabled = 5,
        Success = 10,
        SuccessSignedOut = 11,
        InvalidPassword = 12,
        InvalidOldEMailAddress = 13,
        InvalidNewEMailAddress = 14,
        NewEMailAddressAlreadyInUse = 15,
        SessionSoftDeleted = 100
    }
}
