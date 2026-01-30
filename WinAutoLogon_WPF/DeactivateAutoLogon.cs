using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Windows;

namespace WinAutoLogon_WPF
{
  internal class DeactivateAutoLogon
  {
    public static void Deactivate(Action callback)
    {
      MessageBoxResult result = MessageBox.Show("Are you sure to deactivate the auto logon for this user account?", "Deactivate Auto Logon", MessageBoxButton.YesNo, MessageBoxImage.Warning);

      if (result == MessageBoxResult.Yes)
      {
        WindowsApiHelper WinAPI = new WindowsApiHelper();

        try
        {
          if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
          {
            MessageBox.Show("This program must be run with administrative privilege.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
          }

          string regPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
          using (RegistryKey key = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64).OpenSubKey(regPath, writable: true)!)
          {
            if (key == null)
            {
              MessageBox.Show("Could not open registry key for writing value.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
              return;
            }

            key.SetValue("AutoAdminLogon", "0", RegistryValueKind.String);
            key.SetValue("DefaultPassword", string.Empty, RegistryValueKind.String);
          }

          IntPtr policyHandle = IntPtr.Zero;

          if (!WinAPI.OpenPolicy(string.Empty, out policyHandle))
          {
            throw new Exception($"LsaOpenPolicy failed: {Marshal.GetLastWin32Error()}");
          }

          try
          {
            if (!WinAPI.StorePrivateData(policyHandle, "DefaultPassword", string.Empty))
            {
              MessageBox.Show($"Failed to clear password from LSA: {Marshal.GetLastWin32Error()}", "Warning", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
          }
          finally
          {
            WinAPI.CloseHandle(policyHandle);
            callback.Invoke();
          }

          MessageBox.Show("Autologon deactivated successfully!", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
          MessageBox.Show($"Error deactivating auto logon: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);

        }
      }
      else
      {
        return;
      }
    }
  }
}
