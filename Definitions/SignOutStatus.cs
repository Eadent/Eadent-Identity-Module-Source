namespace Eadent.Identity.Definitions
{
    public enum SignOutStatus : short
    {
        Error = 0,
        Success = 1,
        InactiveSession = 2,
        InvalidSessionToken = 3,
        SessionAlreadySignedOut = 4,
        SessionDisabled = 5,
        SessionSoftDeleted = 100
    }
}
