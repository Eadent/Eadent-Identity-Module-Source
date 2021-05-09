namespace Eadent.Identity.Definitions
{
    public enum SignInStatus : short
    {
        Success = 0,
        SuccessMustChangePassword = 1,
        Error = 2,
        Disabled = 3,
        LockedOut = 4,
        InvalidEMailAddress = 5,
        InvalidPassword = 6,
        SoftDeleted = 100
    }
}
