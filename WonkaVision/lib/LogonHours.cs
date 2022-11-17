using System;
using System.Collections.Generic;
using System.Reflection;

namespace WonkaVision.lib
{
    public class LogonHours
    {
        public Dictionary<int, bool> Monday { get; set; }

        public Dictionary<int, bool> Tuesday { get; set; }

        public Dictionary<int, bool> Wednesday { get; set; }

        public Dictionary<int, bool> Thursday { get; set; }

        public Dictionary<int, bool> Friday { get; set; }

        public Dictionary<int, bool> Saturday { get; set; }

        public Dictionary<int, bool> Sunday { get; set; }

        public bool hasLogoff { get; set; }

        private Dictionary<int, string> Bytes = new Dictionary<int, string>(){
            { 0, "Sunday" },
            { 1, "Sunday" },
            { 2, "Sunday" },
            { 3, "Monday" },
            { 4, "Monday" },
            { 5, "Monday" },
            { 6, "Tuesday" },
            { 7, "Tuesday" },
            { 8, "Tuesday" },
            { 9, "Wednesday" },
            { 10, "Wednesday" },
            { 11, "Wednesday" },
            { 12, "Thursday" },
            { 13, "Thursday" },
            { 14, "Thursday" },
            { 15, "Friday" },
            { 16, "Friday" },
            { 17, "Friday" },
            { 18, "Saturday" },
            { 19, "Saturday" },
            { 20, "Saturday" }
        };

        public LogonHours()
        {
            Monday = SetDefaultLogonHours();
            Tuesday = SetDefaultLogonHours();
            Wednesday = SetDefaultLogonHours();
            Thursday = SetDefaultLogonHours();
            Friday = SetDefaultLogonHours();
            Saturday = SetDefaultLogonHours();
            Sunday = SetDefaultLogonHours();
        }

        public void ConvertLogonHours(byte[] logonHours)
        {
            hasLogoff = false;
            int byteCounter = 0;
            int dayCounter = 0;

            foreach (byte logonHour in logonHours)
            {
                for(int bit = 0; bit < 8; bit++)
                {
                    bool permitted = (logonHour & (1 << bit)) != 0;
                    if (!permitted)
                        hasLogoff = true;
                    int hour = byteCounter * 8 + bit;
                    string day = Bytes[dayCounter];
                    PropertyInfo propInfo = this.GetType().GetProperty(day);
                    Dictionary<int, bool> newVal = (Dictionary<int, bool>)propInfo.GetValue(this);
                    newVal[hour] = permitted;
                    propInfo.SetValue(this, newVal);
                }
                byteCounter += 1;
                if (byteCounter == 3)
                    byteCounter = 0;
                dayCounter += 1;
            }
        }

        public DateTime GetLogoffTime(DateTime startTime)
        {
            if (!hasLogoff)
                return DateTime.MaxValue;

            DateTime logoffTime = startTime;

            int hour = startTime.Hour;
            string day = startTime.DayOfWeek.ToString();
            PropertyInfo propInfo = this.GetType().GetProperty(day);
            Dictionary<int, bool> propValue = (Dictionary<int, bool>)propInfo.GetValue(this);
            if (!propValue[hour])
                return startTime;

            int leftOver = 23 - hour;
            bool foundLogoff = false;

            for (int i = 0; i < 7; i++)
            {
                string tmpDay = startTime.AddDays(i).DayOfWeek.ToString();
                propInfo = this.GetType().GetProperty(tmpDay);
                propValue = (Dictionary<int, bool>)propInfo.GetValue(this);
                int counter = 0;
                if (i == 0)
                {
                    counter = hour;
                }

                do
                {
                    if (!propValue[counter])
                    {
                        foundLogoff = true;
                        break;
                    }
                    counter += 1;
                    logoffTime = logoffTime.AddHours(1);
                } while (counter < 23);

                if (foundLogoff)
                    break;
            }

            if (!foundLogoff && (hour > 0))
            {
                for (int i = 0; i < hour; i++)
                {
                    propInfo = this.GetType().GetProperty(day);
                    propValue = (Dictionary<int, bool>)propInfo.GetValue(this);
                    if (!propValue[i])
                    {
                        foundLogoff = true;
                        break;
                    }
                    logoffTime = logoffTime.AddHours(1);
                }
            }

            if (!foundLogoff)
                return DateTime.MinValue;

            // zero minutes and seconds
            logoffTime = logoffTime.AddMinutes(-(logoffTime.Minute)).AddSeconds(-(logoffTime.Second));

            return logoffTime;
        }

        private static Dictionary<int, bool> SetDefaultLogonHours()
        {
            Dictionary<int, bool> LogonHours = new Dictionary<int, bool>();
            LogonHours.Add(0, true);
            LogonHours.Add(1, true);
            LogonHours.Add(2, true);
            LogonHours.Add(3, true);
            LogonHours.Add(4, true);
            LogonHours.Add(5, true);
            LogonHours.Add(6, true);
            LogonHours.Add(7, true);
            LogonHours.Add(8, true);
            LogonHours.Add(9, true);
            LogonHours.Add(10, true);
            LogonHours.Add(11, true);
            LogonHours.Add(12, true);
            LogonHours.Add(13, true);
            LogonHours.Add(14, true);
            LogonHours.Add(15, true);
            LogonHours.Add(16, true);
            LogonHours.Add(17, true);
            LogonHours.Add(18, true);
            LogonHours.Add(19, true);
            LogonHours.Add(20, true);
            LogonHours.Add(21, true);
            LogonHours.Add(22, true);
            LogonHours.Add(23, true);
            return LogonHours;
        }
    }
}
