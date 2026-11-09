using AngleSharp.Dom;
using Ganss.Xss;

namespace Vaulty.Infrastructure.Browse;

/// <summary>
/// Makes the HTML body of a backed-up message safe to show: an allowlist of tags, attributes and CSS (no scripts, event
/// handlers, forms, frames, objects, SVG or MathML), links reduced to their text with the address as a tooltip, and every
/// image that is not embedded in the message removed, so opening a preview never loads anything from outside. The page that
/// shows it adds a sandboxed iframe and a Content Security Policy without scripts as further layers.
/// </summary>
public static class MailHtmlSanitizer
{
    public const string BlockedImageText = "[external image blocked]";

    private static readonly HashSet<string> RemovedTags = new(StringComparer.OrdinalIgnoreCase)
    {
        "form", "input", "button", "select", "textarea", "option", "iframe", "frame", "frameset", "object", "embed", "applet", "svg", "math",
        "base", "link", "meta", "style", "script", "noscript", "template", "audio", "video", "source", "track", "picture", "portal",
    };

    private static HtmlSanitizer Create()
    {
        var sanitizer = new HtmlSanitizer { AllowDataAttributes = false, KeepChildNodes = true };
        foreach (var tag in RemovedTags) sanitizer.AllowedTags.Remove(tag);
        sanitizer.AllowedAttributes.Remove("id");
        sanitizer.AllowedAttributes.Remove("name");
        sanitizer.AllowedAttributes.Remove("srcset");
        sanitizer.AllowedAttributes.Remove("action");
        sanitizer.AllowedAttributes.Remove("formaction");
        sanitizer.AllowedAttributes.Remove("background");
        sanitizer.AllowedAttributes.Remove("ping");
        sanitizer.AllowedAttributes.Add("title");
        // Only embedded images survive as URLs; links are rewritten below.
        sanitizer.AllowedSchemes.Clear();
        sanitizer.AllowedSchemes.Add("data");
        sanitizer.AllowedCssProperties.Remove("background-image");
        sanitizer.AllowedCssProperties.Remove("list-style-image");
        sanitizer.AllowedCssProperties.Remove("content");
        sanitizer.AllowedCssProperties.Remove("cursor");
        sanitizer.AllowedCssProperties.Remove("position");
        sanitizer.AllowedAtRules.Clear();
        sanitizer.RemovingAttribute += (_, e) =>
        {
            // A link keeps its text; its address becomes a tooltip so the reader can still see where it pointed.
            if (e.Tag.NodeName.Equals("A", StringComparison.OrdinalIgnoreCase) && e.Attribute.Name.Equals("href", StringComparison.OrdinalIgnoreCase)
                && IsShownAddress(e.Attribute.Value))
            {
                e.Tag.SetAttribute("title", Shorten(e.Attribute.Value));
            }
        };
        sanitizer.PostProcessNode += (_, e) =>
        {
            if (e.Node is not IElement element) return;
            if (element.NodeName.Equals("A", StringComparison.OrdinalIgnoreCase))
            {
                element.RemoveAttribute("href");
                element.RemoveAttribute("target");
            }
            if (element.NodeName.Equals("IMG", StringComparison.OrdinalIgnoreCase))
            {
                var src = element.GetAttribute("src") ?? "";
                if (!IsEmbeddedImage(src))
                {
                    element.RemoveAttribute("src");
                    element.SetAttribute("alt", BlockedImageText);
                }
            }
        };
        return sanitizer;
    }

    /// <summary>A complete, self-contained HTML document with the sanitized body.</summary>
    public static string Sanitize(string html)
    {
        var body = Create().Sanitize(html ?? "");
        return "<!doctype html><html><head><meta charset=\"utf-8\"><style>body{font-family:system-ui,sans-serif;font-size:14px;line-height:1.45;"
               + "margin:12px;overflow-wrap:anywhere;color:#1b1f24;background:#fff}img{max-width:100%;height:auto}"
               + "table{max-width:100%}</style></head><body>" + body + "</body></html>";
    }

    private static bool IsEmbeddedImage(string src) =>
        src.StartsWith("data:image/", StringComparison.OrdinalIgnoreCase) && !src.StartsWith("data:image/svg", StringComparison.OrdinalIgnoreCase);

    /// <summary>Only web and mail addresses are shown as a tooltip; anything else (scripts, data) is dropped.</summary>
    private static bool IsShownAddress(string url)
    {
        var value = url.Trim();
        return value.StartsWith("https://", StringComparison.OrdinalIgnoreCase) || value.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase);
    }

    private static string Shorten(string url) => url.Length > 300 ? url[..300] + "…" : url;
}
