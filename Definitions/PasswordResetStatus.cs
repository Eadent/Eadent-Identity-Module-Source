namespace Eadent.Identity.Definitions
{
    public enum PasswordResetStatus : short
    {
        Closed = 0,
        Open = 1,
        Aborted = 2,
        TimedOutExpired = 3
    }
}
