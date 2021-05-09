namespace Eadent.Identity.Definitions
{
    public enum SessionStatus : short
    {
        Inactive = 0,
        Error = 1,
        InvalidSessionToken = 2,
        SignedIn = 3,
        SignedOut = 4,
        TimedOutExpired = 5,
        Disabled = 6,
        SoftDeleted = 100
    }
}
