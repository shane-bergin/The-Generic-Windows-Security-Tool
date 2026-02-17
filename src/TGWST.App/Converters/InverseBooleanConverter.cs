using System;
using System.Globalization;
using System.Windows.Data;

namespace TGWST.App.Converters
{
    public sealed class InverseBooleanConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return value is bool flag ? !flag : true;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return value is bool flag ? !flag : false;
        }
    }
}
