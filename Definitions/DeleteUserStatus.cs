namespace Eadent.Identity.Definitions
{
    public enum DeleteUserStatus
    {
        Error = 0,
        InvalidSessionToken = 1,
        NotAuthorisedToSoftDeleteAnotherUser = 2,
        NotAuthorisedToSoftUnDeleteAnotherUser = 3,
        NotAuthorisedToHardDeleteAnotherUser = 4,
        UserNotFound = 5,
        AlreadySoftDeleted = 6,
        MayNotSoftUnDeleteSelf = 7,
        MayNotHardDeleteSelf = 8,
        NotSoftDeleted = 9,
        SoftDeleted = 100,
        SoftUnDeleted = 101,
        HardDeleted = 102
    }
}
