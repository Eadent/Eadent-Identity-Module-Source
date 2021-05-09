namespace Eadent.Identity.Definitions
{
    public enum UserStatus : short
    {
        Enabled = 0,
        Disabled = 1,
        SignInLockedOut = 2,
        SoftDeleted = 100
    }
}
