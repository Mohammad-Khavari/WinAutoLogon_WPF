using Microsoft.Win32;
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Windows;


namespace Auto_Logon
{
  internal static class SetAutoLogon
  {
    internal static void SetAutoLogonConfig(string uname, string domainName, string pw, Action callback)
    {
      WindowsApiHelper WinAPI = new WindowsApiHelper();
      try
      {
        if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
        {
          MessageBox.Show("This program must be run with administrative privileges.",
              "Error",MessageBoxButton.OK,MessageBoxImage.Error);
          return;
        }
        string regPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        string username = uname;
        string domain = domainName;
        string password = pw;

        // Check if any of the fields are empty
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(domain) || string.IsNullOrEmpty(password))
        {
          MessageBox.Show("Please fill in all fields.",
              "Error", MessageBoxButton.OK, MessageBoxImage.Error);
          return;
        }

        // Check if the password is too long
        if (password.Length > 127)
        {
          MessageBox.Show("The password is too long (max 127 characters).",
              "Error", MessageBoxButton.OK, MessageBoxImage.Error);
          return;
        }

        // Set the registry values
        using (RegistryKey? key = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                                            .OpenSubKey(regPath, writable: true))
        {
          if (key == null)
          {
            MessageBox.Show("Error: Could not open registry key.",
                "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
          }

          // TODO
          key.SetValue("DefaultUserName", username, RegistryValueKind.String);
          key.SetValue("DefaultDomainName", string.IsNullOrEmpty(domain) ? "." : domain, RegistryValueKind.String);
          key.SetValue("AutoAdminLogon", 1, RegistryValueKind.String);
          //key.SetValue("ForceAutoLogon", 1);
          //key.SetValue("DefaultPassword", password);
        }

        // Encrypt and set the password in LSA 
        IntPtr policyHandle = IntPtr.Zero;

        if (!WinAPI.OpenPolicy(null!, out policyHandle))
        {
          throw new Exception($"LsaOpenPolicy failed: {Marshal.GetLastWin32Error()}");
        }

        try
        {
          // Store the password
          if (!WinAPI.StorePrivateData(policyHandle, "DefaultPassword", password))
          {
            throw new Exception($"LsaStorePrivateData failed: {Marshal.GetLastWin32Error()}");
          }

          MessageBox.Show("Autologon configured successfully!",
                        "Success", MessageBoxButton.OK, MessageBoxImage.Information);
          //CheckAndDecrypt(); // Refresh the display
        }
        finally
        {
          WinAPI.CloseHandle(policyHandle);
          //LsaClose(policyHandle);
          callback?.Invoke();
        }

      }
      catch (Exception ex)
      {
        MessageBox.Show($"Error: {ex.Message}",
            "Error", MessageBoxButton.OK, MessageBoxImage.Error);
      }
    }
  }
}
