using System.Windows;
using System.Windows.Controls;
using System.Windows.Markup;
using System.Windows.Media;

namespace Trowser;

/// <summary>
/// Shared dark-themed ComboBox styling used across Trowser dialogs.
/// </summary>
internal static class DarkComboBoxHelper
{
    private static readonly SolidColorBrush BgDark = Bc("#1E1E1E");
    private static readonly SolidColorBrush FgText = Bc("#D4D4D4");
    private static readonly SolidColorBrush BorderClr = Bc("#3F3F46");

    /// <summary>
    /// Returns a ControlTemplate that paints the ComboBox chrome dark and
    /// keeps the dropdown popup dark as well.
    /// </summary>
    public static ControlTemplate CreateDarkTemplate()
    {
        const string xaml = """
            <ControlTemplate TargetType="ComboBox"
                xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
                <Grid>
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="20"/>
                    </Grid.ColumnDefinitions>
                    <ToggleButton Grid.ColumnSpan="2" Focusable="False" ClickMode="Press"
                                  IsChecked="{Binding IsDropDownOpen, RelativeSource={RelativeSource TemplatedParent}, Mode=TwoWay}">
                        <ToggleButton.Template>
                            <ControlTemplate TargetType="ToggleButton">
                                <Border x:Name="Bd" Background="#1E1E1E" BorderBrush="#3F3F46"
                                        BorderThickness="1" CornerRadius="2">
                                    <Grid>
                                        <Grid.ColumnDefinitions>
                                            <ColumnDefinition Width="*"/>
                                            <ColumnDefinition Width="20"/>
                                        </Grid.ColumnDefinitions>
                                        <Path Grid.Column="1" Fill="#D4D4D4" Data="M 0 0 L 4 4 L 8 0 Z"
                                              HorizontalAlignment="Center" VerticalAlignment="Center"/>
                                    </Grid>
                                </Border>
                                <ControlTemplate.Triggers>
                                    <Trigger Property="IsMouseOver" Value="True">
                                        <Setter TargetName="Bd" Property="Background" Value="#3E3E42"/>
                                    </Trigger>
                                </ControlTemplate.Triggers>
                            </ControlTemplate>
                        </ToggleButton.Template>
                    </ToggleButton>
                    <ContentPresenter Margin="6,2,24,2" VerticalAlignment="Center" IsHitTestVisible="False"
                                      Content="{TemplateBinding SelectionBoxItem}"
                                      ContentTemplate="{TemplateBinding SelectionBoxItemTemplate}"/>
                    <Popup x:Name="PART_Popup" Placement="Bottom" AllowsTransparency="True"
                           IsOpen="{TemplateBinding IsDropDownOpen}" SnapsToDevicePixels="True">
                        <Border Background="#1E1E1E" BorderBrush="#3F3F46" BorderThickness="1"
                                MinWidth="{TemplateBinding ActualWidth}">
                            <ItemsPresenter/>
                        </Border>
                    </Popup>
                </Grid>
            </ControlTemplate>
            """;
        return (ControlTemplate)XamlReader.Parse(xaml);
    }

    /// <summary>
    /// Dark template for <see cref="ComboBox.IsEditable"/> combos — includes <c>PART_EditableTextBox</c>
    /// so the selection area matches the non-editable chrome instead of the default white edit surface.
    /// </summary>
    public static ControlTemplate CreateDarkEditableTemplate()
    {
        const string xaml = """
            <ControlTemplate TargetType="ComboBox"
                xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
                <Grid>
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="20"/>
                    </Grid.ColumnDefinitions>
                    <ToggleButton Grid.ColumnSpan="2" Focusable="False" ClickMode="Press"
                                  IsChecked="{Binding IsDropDownOpen, RelativeSource={RelativeSource TemplatedParent}, Mode=TwoWay}">
                        <ToggleButton.Template>
                            <ControlTemplate TargetType="ToggleButton">
                                <Border x:Name="Bd" Background="#1E1E1E" BorderBrush="#3F3F46"
                                        BorderThickness="1" CornerRadius="2">
                                    <Grid>
                                        <Grid.ColumnDefinitions>
                                            <ColumnDefinition Width="*"/>
                                            <ColumnDefinition Width="20"/>
                                        </Grid.ColumnDefinitions>
                                        <Path Grid.Column="1" Fill="#D4D4D4" Data="M 0 0 L 4 4 L 8 0 Z"
                                              HorizontalAlignment="Center" VerticalAlignment="Center"/>
                                    </Grid>
                                </Border>
                                <ControlTemplate.Triggers>
                                    <Trigger Property="IsMouseOver" Value="True">
                                        <Setter TargetName="Bd" Property="Background" Value="#3E3E42"/>
                                    </Trigger>
                                </ControlTemplate.Triggers>
                            </ControlTemplate>
                        </ToggleButton.Template>
                    </ToggleButton>
                    <TextBox x:Name="PART_EditableTextBox"
                             Grid.Column="0"
                             Margin="6,2,24,2"
                             VerticalAlignment="Center"
                             HorizontalAlignment="Stretch"
                             HorizontalContentAlignment="{TemplateBinding HorizontalContentAlignment}"
                             Background="#1E1E1E"
                             Foreground="#D4D4D4"
                             CaretBrush="#D4D4D4"
                             BorderThickness="0"
                             Padding="0"
                             Focusable="True"/>
                    <Popup x:Name="PART_Popup" Placement="Bottom" AllowsTransparency="True"
                           IsOpen="{TemplateBinding IsDropDownOpen}" SnapsToDevicePixels="True">
                        <Border Background="#1E1E1E" BorderBrush="#3F3F46" BorderThickness="1"
                                MinWidth="{TemplateBinding ActualWidth}">
                            <ItemsPresenter/>
                        </Border>
                    </Popup>
                </Grid>
            </ControlTemplate>
            """;
        return (ControlTemplate)XamlReader.Parse(xaml);
    }

    /// <summary>
    /// Applies dark template and popup chrome for an editable ComboBox.
    /// </summary>
    public static void ApplyDarkEditableStyle(ComboBox combo)
    {
        combo.Template = CreateDarkEditableTemplate();
        combo.Resources[SystemColors.HighlightBrushKey] = Bc("#3E3E42");
        combo.Resources[SystemColors.HighlightTextBrushKey] = FgText;
    }

    /// <summary>
    /// Creates a dark-themed ComboBoxItem.
    /// </summary>
    public static ComboBoxItem CreateItem(string text)
    {
        return new ComboBoxItem
        {
            Content = text,
            Background = BgDark,
            Foreground = FgText,
            BorderThickness = new Thickness(0),
            Padding = new Thickness(6, 4, 6, 4)
        };
    }

    /// <summary>
    /// Applies dark highlight colors to a ComboBox's resources and sets the dark template.
    /// </summary>
    public static void ApplyDarkStyle(ComboBox combo)
    {
        combo.Template = CreateDarkTemplate();
        combo.Resources[SystemColors.HighlightBrushKey] = Bc("#3E3E42");
        combo.Resources[SystemColors.HighlightTextBrushKey] = FgText;
    }

    private static SolidColorBrush Bc(string hex)
    {
        var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        brush.Freeze();
        return brush;
    }
}
