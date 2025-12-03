using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace WinAutoLogon_WPF
{
  /// <summary>
  /// Interaction logic for MainWindow.xaml
  /// </summary>
  public partial class MainWindow : Window
  {
    
    public MainWindow()
    {
      InitializeComponent();
      
    }

    private void BtnShowPW_Clicked(object sender, RoutedEventArgs e)
    {
      
    }

    private void PWVisibleClicked(object sender, RoutedEventArgs e)
    {
      Button button = (Button)sender;
      bool isPWHiden = (txtPassword.Visibility == Visibility.Visible);

      if (isPWHiden)
      {
        
        TxtVisiblePWInput.Text = txtPassword.Password;
        txtPassword.Visibility = Visibility.Collapsed;
        button.Foreground = new SolidColorBrush(Color.FromRgb(52, 152, 219));
        TxtVisiblePWInput.Visibility = Visibility.Visible;
        button.Content = "👁️";
        button.Padding = new Thickness(0);
        button.FontSize = 12;
        //MessageTextBlock.Text = "";

      }
      else
      {
        txtPassword.Password = TxtVisiblePWInput.Text;
        TxtVisiblePWInput.Visibility = Visibility.Collapsed;
        txtPassword.Visibility = Visibility.Visible;
        button.Content = "‿";
        button.Padding = new Thickness(0,-16,0,0);
        button.FontSize = 20;
      }
    }

    private void DetectKiosk(object sender, RoutedEventArgs e)
    {
      var kioskWin = new FrmKioskDetector();
      kioskWin.ShowDialog();
    }

    private void CloseApp(object sender, RoutedEventArgs e)
    {
      this.Close();
    }
  }
}