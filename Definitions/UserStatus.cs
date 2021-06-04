namespace Eadent.Identity.Definitions
{
    public enum UserStatus : short
    {
        Disabled = 0,
        Enabled = 1,
        SignInLockedOut = 2,
        SoftDeleted = 100
    }
}
