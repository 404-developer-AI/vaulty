using MudBlazor;

namespace Vaulty.Web.Theme;

/// <summary>
/// The Vaulty theme (Steaan design tokens): light mode only, primary teal #0F766E, stone neutrals, radius 8px, Inter.
/// Values are identical to the Steaan design tokens.
/// </summary>
public static class VaultyTheme
{
    public static readonly MudTheme Theme = new()
    {
        PaletteLight = new PaletteLight
        {
            Primary = "#0F766E",
            PrimaryDarken = "#115E59",
            PrimaryLighten = "#14B8A6",
            Secondary = "#0D9488",
            Tertiary = "#2563EB",
            Error = "#DC2626",
            Success = "#0F766E",
            Warning = "#D97706",
            Info = "#2563EB",
            Background = "#FAFAF9",
            Surface = "#FFFFFF",
            TextPrimary = "#1C1917",
            TextSecondary = "#78716C",
            TextDisabled = "#A8A29E",
            ActionDefault = "#78716C",
            ActionDisabled = "#D6D3D1",
            LinesDefault = "#E7E5E4",
            LinesInputs = "#D6D3D1",
            TableLines = "#F5F5F4",
            Divider = "#E7E5E4",
            DrawerBackground = "#FFFFFF",
            DrawerText = "#44403C",
            DrawerIcon = "#78716C",
            AppbarBackground = "#FFFFFF",
            AppbarText = "#1C1917"
        },
        Typography = new Typography
        {
            Default = new DefaultTypography
            {
                FontFamily = ["Inter", "-apple-system", "BlinkMacSystemFont", "Segoe UI", "Roboto", "sans-serif"],
                FontSize = "0.875rem"
            },
            H1 = new H1Typography { FontWeight = "600", FontSize = "2.25rem", LetterSpacing = "-0.02em" },
            H2 = new H2Typography { FontWeight = "600", FontSize = "1.875rem", LetterSpacing = "-0.02em" },
            H3 = new H3Typography { FontWeight = "600", FontSize = "1.5rem", LetterSpacing = "-0.01em" },
            H4 = new H4Typography { FontWeight = "600", FontSize = "1.25rem", LetterSpacing = "-0.01em" },
            H5 = new H5Typography { FontWeight = "600", FontSize = "1.125rem" },
            H6 = new H6Typography { FontWeight = "600", FontSize = "1rem" },
            Subtitle1 = new Subtitle1Typography { FontWeight = "500", FontSize = "0.9375rem" },
            Subtitle2 = new Subtitle2Typography { FontWeight = "500", FontSize = "0.8125rem" },
            Body1 = new Body1Typography { FontSize = "0.875rem", LineHeight = "1.6" },
            Body2 = new Body2Typography { FontSize = "0.8125rem", LineHeight = "1.5" },
            Button = new ButtonTypography { FontWeight = "600", FontSize = "0.875rem", LetterSpacing = "0", TextTransform = "none" },
            Caption = new CaptionTypography { FontSize = "0.75rem", FontWeight = "500" },
            Overline = new OverlineTypography { FontSize = "0.6875rem", FontWeight = "600", LetterSpacing = "0.08em" }
        },
        LayoutProperties = new LayoutProperties
        {
            DefaultBorderRadius = "8px",
            DrawerWidthLeft = "260px",
            DrawerMiniWidthLeft = "76px",
            AppbarHeight = "0px"
        }
    };
}
