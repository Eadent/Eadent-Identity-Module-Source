namespace Eadent.Identity.Definitions
{
    public enum ChangeUserEMailStatus : short
    {
        Inactive = 0,
        Success = 1,
        SuccessSignedOut = 2,
        Error = 3,
        InvalidSessionToken = 4,
        InvalidPassword = 5,
        InvalidOldEMailAddress = 6,
        InvalidNewEMailAddress = 7,
        UserDoesNotOwnOldEMailAddress = 8,
        NewEMailAddressAlreadyInUse = 9,
        SignedOut = 10,
        TimedOutExpired = 11,
        Disabled = 12,
        SoftDeleted = 100
    }
}
