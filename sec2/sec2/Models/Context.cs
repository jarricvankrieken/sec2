using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Web;

namespace sec2.Models
{
    public class Context : DbContext
    {

        public Context() : base("name=sec2")
        {
            try
            {
                Database.SetInitializer<Context>(new CreateDatabaseIfNotExists<Context>());
            }
            catch { }
        }

        public DbSet<EncryptedData> EncryptedData { get; set; }
    }
}