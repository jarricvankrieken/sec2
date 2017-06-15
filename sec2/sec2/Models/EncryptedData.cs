using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace sec2.Models
{
    public class EncryptedData
    {
        [Key]
        public int id { get; set; }

        public string user { get; set; }

        public byte[] encryptedText { get; set; }

        public byte[] vector { get; set; }

        public byte[] salt { get; set; }
    }
}