namespace Eadent.Identity.Definitions
{
    public enum SignOutStatus : short
    {
        Success = 0,
        Error = 1,
        InactiveSession = 2,
        InvalidSessionToken = 3,
        AlreadySignedOut = 4,
        Disabled = 5,
        SoftDeleted = 100
    }
}
