namespace Eadent.Identity.Definitions
{
    public enum PasswordResetStatus : short
    {
        Open = 0,
        Aborted = 1,
        TimedOutExpired = 2,
        Closed = 3
    }
}
