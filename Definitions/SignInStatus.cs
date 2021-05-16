namespace Eadent.Identity.Definitions
{
    public enum SignInStatus : short
    {
        Error = 0,
        Success = 1,
        SuccessUserMustChangePassword = 2,
        UserDisabled = 3,
        UserLockedOut = 4,
        InvalidEMailAddress = 5,
        InvalidPassword = 6,
        UserSoftDeleted = 100
    }
}
