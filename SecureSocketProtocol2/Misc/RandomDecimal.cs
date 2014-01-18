using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Misc
{
    public class RandomDecimal
    {
        private Random random;

        public RandomDecimal(int Seed)
        {
            random = new Random(Seed);
        }

        private int NextInt32()
        {
             unchecked
             {
                 int firstBits = this.random.Next(0, 1 << 4) << 28;
                 int lastBits = this.random.Next(0, 1 << 28);
                 return firstBits | lastBits;
             }
        }

        public decimal NextDecimal()
        {
            lock(random)
            {
                byte scale = (byte) this.random.Next(29);
                bool sign = this.random.Next(2) == 1;
                return new decimal(NextInt32(), NextInt32(), NextInt32(), sign, scale);
            }
        }
    }
}