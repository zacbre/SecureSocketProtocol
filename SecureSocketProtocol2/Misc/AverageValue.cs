using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Misc
{
    public class AverageValue
    {
        private List<double> values;
        public int MaxValue { get; private set; }
        public AverageValue(int MaxValue)
        {
            this.MaxValue = MaxValue;
            values = new List<double>();
        }

        public double Average
        {
            get
            {
                lock (values)
                {
                    if (values.Count > 0)
                    {
                        double temp = 0;
                        for (int i = 0; i < values.Count; i++)
                            temp += values[i];
                        return temp / values.Count;
                    }
                }
                return 0;
            }
        }

        /// <summary>
        /// Add a value to calculate the average of it
        /// </summary>
        /// <param name="value">The value to add</param>
        /// <returns>The average value</returns>
        public double AddValue(double value)
        {
            lock (values)
            {
                values.Add(value);
                if (values.Count > MaxValue)
                    values.RemoveAt(0);
                return Average;
            }
        }
    }
}