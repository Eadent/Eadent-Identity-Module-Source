namespace Eadent.Identity.Definitions
{
    public enum UserSessionStatus : short
    {
        Inactive = 0,
        SignedIn = 1,
        SignedOut = 2,
        TimedOutExpired = 3,
        Disabled = 4,
        SoftDeleted = 100
    }
}
