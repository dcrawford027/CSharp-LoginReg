using Microsoft.EntityFrameworkCore;

namespace LoginReg.Models
{
    public class LoginRegContext : DbContext
    {
        public LoginRegContext(DbContextOptions options) : base(options) { }
        
        public DbSet<User> Users {get;set;}
    }
}