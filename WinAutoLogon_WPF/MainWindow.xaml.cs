using Auto_Logon;
using Microsoft.Win32;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace WinAutoLogon_WPF
{
  /// <summary>
  /// Interaction logic for MainWindow.xaml
  /// </summary>
  public partial class MainWindow : Window
  {
    private readonly WindowsApiHelper WinAPI = new WindowsApiHelper();
    public MainWindow()
    {
      InitializeComponent();
      btnDecrypt.Click += (s, e) => CheckAndDecrypt();
      btnSetAutoLogon.Click += (s, e) => SetAutoLogon.SetAutoLogonConfig(txtUserName.Text, txtDomain.Text, txtPassword.Password, CheckAndDecrypt);
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
        button.Padding = new Thickness(0, -16, 0, 0);
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

    private void CheckAndDecrypt()
    {
      try
      {
        var principal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
        if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
        {
          MessageBoxResult result = MessageBox.Show("This action requires admministrator privilages to function properly.\n " +
            "Would you like to restart the application with admin rights?", "Administrator Required", MessageBoxButton.YesNo, MessageBoxImage.Warning);

          if (result == MessageBoxResult.Yes)
          {
            this.Close();
            Application.Current.Shutdown();
            Thread.Sleep(1000);
            try
            {
              ProcessStartInfo processInfo = new ProcessStartInfo
              {
                UseShellExecute = true,
                FileName = Assembly.GetExecutingAssembly().Location,
                Verb = "runas" // trigger UAC
              };

              Process.Start(processInfo);

            }
            catch (Exception ex)
            {
              MessageBox.Show($"Failed to restart with admin privileges: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
          }
          else
          {
            return;
          }

        }

        string regPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        string userName = "Not set";
        string domain = "Not set";
        string debugInfo = "Registry Debug Info:\n";

        // Check 64-bit
        using (RegistryKey key64 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64).OpenSubKey(regPath, false)!)
        {
          if (key64 != null)
          {
            debugInfo += "64-bit view:\n";
            userName = GetRegistryValue(key64, "DefaultUserName", ref debugInfo);
            domain = GetRegistryValue(key64, "DefaultDomainName", ref debugInfo);
          }
          else
          {
            debugInfo += "64-bit view: Key not found\n";
          }
        }

        lblUsername.Content = $"Username: {userName}";
        lblDomain.Content = $"Domain: {domain}";
        string password = string.Empty;
        // Check AutoAdminLogon
        using (RegistryKey key64 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64).OpenSubKey(regPath, false)!)
        {
          object autoAdminLogon = GetRegistryValue(key64!, "AutoAdminLogon", ref debugInfo);


          if (autoAdminLogon == null || autoAdminLogon!.ToString() != "1")
          {
            picInactive.Visibility = Visibility.Visible;
            picActive.Visibility = Visibility.Collapsed;
            btnDeactive.IsEnabled = false;
          }
          else
          {
            picActive.Visibility = Visibility.Visible;
            picInactive.Visibility = Visibility.Collapsed;
            btnDeactive.IsEnabled = true;
          }
          password = GetAutologonPassword();
          lblPassword.Content = $"Password: {(password! != null ? password : "Not found or failed to decrypt")}";
        }

       
      }
      catch (Exception ex)
      {
        MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        lblUsername.Content = "Username: Error";
        lblDomain.Content = "Domain: Error";
        lblPassword.Content = "Password: Error";
      }
    }

    private string GetRegistryValue(RegistryKey key, string valueName, ref string debugInfo)
    {
      object valueObj = key.GetValue(valueName, "Not set");
      string value = "Not set";
      string valueKind = "N/A";

      if (Array.Exists(key.GetValueNames(), name => name.Equals(valueName, StringComparison.OrdinalIgnoreCase)))
      {
        valueKind = key.GetValueKind(valueName).ToString();
        if (valueObj != null && valueObj.ToString() != "Not set")
        {
          value = valueObj.ToString().Trim();
          if (string.IsNullOrEmpty(value)) value = "Empty string detected";
        }
      }
      else
      {
        valueKind = "Not present";
      }

      debugInfo += $"{valueName} ({valueKind}): '{valueObj}'\n";
      return value;
    }

    private string GetAutologonPassword()
    {
      IntPtr policyHandle = IntPtr.Zero;
      string regPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
      string debugInfo = "Registry Debug Info:\n";

      if (!WinAPI.OpenPolicy(null, out policyHandle))
      {
        throw new Exception($"LsaOpenPolicy failed: {Marshal.GetLastWin32Error()}");
      }

      try
      {
        using RegistryKey key64 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64).OpenSubKey(regPath, false)!;
        if (WinAPI.RetrievePrivateData(policyHandle, "DefaultPassword", out string pw))
        {
          return pw;
        }
        else if (!string.IsNullOrEmpty(GetRegistryValue(key64, "DefaultPassword", ref debugInfo)))
        {
          lblPassword.Foreground = Brushes.Red;
          lblWarning.Visibility = Visibility.Visible;
          pw = GetRegistryValue(key64, "DefaultPassword", ref debugInfo);
        }
        else
        {
          pw = "No password found!";
        }

        return pw;
        //return "PW not found! I dont know";
      }
      finally
      {
        WinAPI.CloseHandle(policyHandle);
      }

    }
  }
}