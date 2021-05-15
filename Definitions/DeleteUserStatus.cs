namespace Eadent.Identity.Definitions
{
    public enum DeleteUserStatus
    {
        Error = 0,
        InvalidSessionToken = 1,
        SessionInactive = 2,
        SessionSignedOut = 3,
        SessionTimedOutExpired = 4,
        SessionDisabled = 5,
        SessionSoftDeleted = 6,
        NotAuthorisedToSoftDeleteAnotherUser = 10,
        NotAuthorisedToSoftUnDeleteAnotherUser = 11,
        NotAuthorisedToHardDeleteAnotherUser = 12,
        UserNotFound = 13,
        AlreadySoftDeleted = 14,
        MayNotSoftUnDeleteSelf = 15,
        MayNotHardDeleteSelf = 16,
        NotSoftDeleted = 17,
        SoftDeleted = 100,
        SoftUnDeleted = 101,
        HardDeleted = 102
    }
}
