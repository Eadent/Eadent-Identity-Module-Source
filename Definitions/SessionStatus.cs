namespace Eadent.Identity.Definitions
{
    public enum SessionStatus : short
    {
        Error = 0,
        Inactive = 1,
        InvalidSessionToken = 2,
        SignedIn = 3,
        SignedOut = 4,
        TimedOutExpired = 5,
        Disabled = 6,
        SoftDeleted = 100
    }
}
